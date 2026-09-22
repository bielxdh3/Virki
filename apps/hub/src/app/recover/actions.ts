"use server";

import { consumeApprovedAccountRecovery, approveAccountRecovery, requestAccountRecovery, verifyAccountRecoveryEmail } from "@bielos/auth/security";
import { requireSecurityElevation } from "@bielos/auth/administration";
import { hashPassword } from "@bielos/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface } from "../../lib/surface";

export async function requestRecoveryAction(formData: FormData) {
  await requireAccess(formData, "account-recovery-request");
  try { await requestAccountRecovery(read(formData, "email"), "pt-BR"); } catch { /* generic response */ }
  redirect("/recover?sent=1");
}

export async function verifyRecoveryAction(formData: FormData) {
  await requireAccess(formData, "account-recovery-verify");
  const requestKey = read(formData, "requestKey");
  try { await verifyAccountRecoveryEmail(requestKey, read(formData, "code")); } catch { redirect(`/recover?request=${encodeURIComponent(requestKey)}&error=1`); }
  redirect(`/recover?request=${encodeURIComponent(requestKey)}&verified=1`);
}

export async function completeRecoveryAction(formData: FormData) {
  await requireAccess(formData, "account-recovery-complete");
  const requestKey = read(formData, "requestKey");
  try { await consumeApprovedAccountRecovery(requestKey, await hashPassword(read(formData, "newPassword"))); } catch { redirect(`/recover?request=${encodeURIComponent(requestKey)}&error=1`); }
  redirect("/login?recovered=1");
}

export async function approveRecoveryAction(formData: FormData) {
  await requireAccess(formData, "account-recovery-approve");
  const session = await getCurrentSession();
  if (!session || session.user.role !== "ADMIN") redirect("/login");
  try {
    await requireSecurityElevation(session.user.id, session.id, "ACCOUNT_STATE_CHANGE");
    await approveAccountRecovery(session.user, read(formData, "requestKey"));
  } catch {
    redirect("/admin/security?error=recovery");
  }
  redirect("/admin/security?status=recovery");
}

async function requireAccess(formData: FormData, source: string) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown" || (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, source)))) redirect("/login");
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) redirect("/login");
}

function read(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value.trim() : ""; }
