"use server";

import { approveAccountRecovery, consumeApprovedAccountRecovery, getAccountRecoveryRequestId, requestAccountRecovery, requestAdministrativeAccountRecovery, verifyAccountRecoveryEmail } from "@virki/auth/security";
import { requireSecurityElevation } from "@virki/auth/administration";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@virki/auth/csrf";
import { validateSessionCsrfToken } from "../../lib/session-csrf";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface, hasSameOrigin } from "../../lib/surface";
import { getRecoveryCookieOptions, LEGACY_RECOVERY_COOKIE, RECOVERY_COOKIE_NAME } from "../../lib/recovery";

export async function requestRecoveryAction(formData: FormData) {
  const { requestHeaders } = await requireRecoveryAccess(formData, "recovery-request", "portal");
  try {
    await requestAccountRecovery(read(formData, "email"), "pt-BR", new Date(), requestHeaders.get("cf-connecting-ip")?.trim());
  } catch {
    // Keep account existence and mail-delivery state private.
  }
  redirect("/recover?sent=1");
}

export async function requestAdministrativeRecoveryAction(formData: FormData) {
  const { requestHeaders } = await requireRecoveryAccess(formData, "recovery-admin-request", "hub");
  try {
    await requestAdministrativeAccountRecovery(read(formData, "email"), "pt-BR", new Date(), requestHeaders.get("cf-connecting-ip")?.trim());
  } catch {
    // Keep account existence and mail-delivery state private.
  }
  redirect("/recover?sent=1");
}

export async function openRecoveryAction(formData: FormData) {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-open");
  const requestKey = read(formData, "requestKey");
  const recovery = await getAccountRecoveryRequestId(requestKey, new Date(), expectedRole);
  if (!recovery) redirect("/recover?error=1");
  const cookieStore = await cookies();
  if (RECOVERY_COOKIE_NAME !== LEGACY_RECOVERY_COOKIE.name) cookieStore.delete(LEGACY_RECOVERY_COOKIE);
  cookieStore.set(RECOVERY_COOKIE_NAME, requestKey, getRecoveryCookieOptions(recovery.expiresAt));
  redirect(`/recover?requestId=${encodeURIComponent(recovery.id)}`);
}

export type RecoveryVerificationActionState = { status: "idle" | "error" | "verified" };

export async function verifyRecoveryAction(_state: RecoveryVerificationActionState, formData: FormData): Promise<RecoveryVerificationActionState> {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-verify");
  const requestId = read(formData, "requestId");
  const requestKey = (await cookies()).get(RECOVERY_COOKIE_NAME)?.value;
  if (!requestKey) return { status: "error" };
  try {
    await verifyAccountRecoveryEmail(requestId, requestKey, read(formData, "code"), new Date(), expectedRole);
  } catch {
    return { status: "error" };
  }
  return { status: "verified" };
}

export async function completeRecoveryAction(formData: FormData) {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-complete");
  const requestId = read(formData, "requestId");
  const requestKey = (await cookies()).get(RECOVERY_COOKIE_NAME)?.value;
  if (!requestKey) redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  try {
    await consumeApprovedAccountRecovery(requestId, requestKey, readRaw(formData, "newPassword"), new Date(), expectedRole);
  } catch {
    redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  }
  const cookieStore = await cookies();
  cookieStore.delete({ name: RECOVERY_COOKIE_NAME, path: "/" });
  if (RECOVERY_COOKIE_NAME !== LEGACY_RECOVERY_COOKIE.name) cookieStore.delete(LEGACY_RECOVERY_COOKIE);
  redirect("/login?recovered=1");
}

export async function approveRecoveryAction(formData: FormData) {
  const requestHeaders = await headers();
  if (!hasSameOrigin(requestHeaders) || getSurface(requestHeaders) !== "hub" || !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery-approve")) || !(await validateSessionCsrfToken(read(formData, CSRF_FORM_FIELD_NAME), "admin-security"))) redirect("/login");
  const session = await getCurrentSession();
  if (!session || session.user.role !== "ADMIN") redirect("/login");
  try {
    await requireSecurityElevation(session.user.id, session.id, "ACCOUNT_STATE_CHANGE");
    await approveAccountRecovery(session.user, read(formData, "requestId"));
  } catch {
    redirect("/admin/security?error=recovery#admin-content");
  }
  redirect("/admin/security?status=recovery#admin-content");
}

async function requireRecoveryAccess(formData: FormData, csrfScope: string, requiredSurface?: "hub" | "portal"): Promise<{ requestHeaders: Headers; expectedRole: "ADMIN" | "USER" }> {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  const expectedSurface = surface === "portal" || surface === "hub"
    ? surface
    : surface === "local" && process.env.NODE_ENV !== "production"
      ? "portal"
      : "unknown";
  const recoverySurfaceAllowed = expectedSurface !== "unknown" && (!requiredSurface || expectedSurface === requiredSurface);
  if (!hasSameOrigin(requestHeaders) || !recoverySurfaceAllowed || !validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME), { scope: csrfScope }).valid) redirect("/login");
  if (expectedSurface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery"))) redirect("/login");
  return { requestHeaders, expectedRole: expectedSurface === "hub" ? "ADMIN" : "USER" };
}

function read(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function readRaw(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}
