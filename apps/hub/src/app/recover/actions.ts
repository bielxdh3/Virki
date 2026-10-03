"use server";

import { approveAccountRecovery, consumeApprovedAccountRecovery, getAccountRecoveryRequestId, requestAccountRecovery, verifyAccountRecoveryEmail } from "@bielos/auth/security";
import { requireSecurityElevation } from "@bielos/auth/administration";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface, hasSameOrigin } from "../../lib/surface";
import { RECOVERY_COOKIE_NAME } from "../../lib/recovery";

export async function requestRecoveryAction(formData: FormData) {
  const requestHeaders = await requirePublicAccess(formData, "account-recovery-request");
  try {
    await requestAccountRecovery(read(formData, "email"), "pt-BR", new Date(), requestHeaders.get("cf-connecting-ip")?.trim());
  } catch {
    // Keep account existence and mail-delivery state private.
  }
  redirect("/recover?sent=1");
}

export async function openRecoveryAction(formData: FormData) {
  await requirePublicAccess(formData, "account-recovery-legacy-link");
  const requestKey = read(formData, "requestKey");
  const recovery = await getAccountRecoveryRequestId(requestKey);
  if (!recovery) redirect("/recover?error=1");
  const cookieStore = await cookies();
  cookieStore.set(RECOVERY_COOKIE_NAME, requestKey, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/recover",
    expires: recovery.expiresAt
  });
  redirect(`/recover?requestId=${encodeURIComponent(recovery.id)}`);
}

export async function verifyRecoveryAction(formData: FormData) {
  await requirePublicAccess(formData, "account-recovery-verify");
  const requestId = read(formData, "requestId");
  const requestKey = (await cookies()).get(RECOVERY_COOKIE_NAME)?.value;
  if (!requestKey) redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  try {
    await verifyAccountRecoveryEmail(requestId, requestKey, read(formData, "code"));
  } catch {
    redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  }
  redirect(`/recover?requestId=${encodeURIComponent(requestId)}&verified=1`);
}

export async function completeRecoveryAction(formData: FormData) {
  await requirePublicAccess(formData, "account-recovery-complete");
  const requestId = read(formData, "requestId");
  const requestKey = (await cookies()).get(RECOVERY_COOKIE_NAME)?.value;
  if (!requestKey) redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  try {
    await consumeApprovedAccountRecovery(requestId, requestKey, readRaw(formData, "newPassword"));
  } catch {
    redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  }
  (await cookies()).delete(RECOVERY_COOKIE_NAME);
  redirect("/login?recovered=1");
}

export async function approveRecoveryAction(formData: FormData) {
  const requestHeaders = await headers();
  if (!hasSameOrigin(requestHeaders) || getSurface(requestHeaders) !== "hub" || !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery-approve")) || !validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) redirect("/login");
  const session = await getCurrentSession();
  if (!session || session.user.role !== "ADMIN") redirect("/login");
  try {
    await requireSecurityElevation(session.user.id, session.id, "ACCOUNT_STATE_CHANGE");
    await approveAccountRecovery(session.user, read(formData, "requestId"));
  } catch {
    redirect("/admin/security?error=recovery");
  }
  redirect("/admin/security?status=recovery");
}

async function requirePublicAccess(formData: FormData, source: string): Promise<Headers> {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (!hasSameOrigin(requestHeaders) || surface === "unknown" || (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, source))) || !validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) redirect("/login");
  return requestHeaders;
}

function read(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function readRaw(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}
