"use server";

import { withHubAuditRequest } from "../../lib/audit-request";

import { approveAccountRecovery, consumeApprovedAccountRecovery, getAccountRecoveryRequestId, getAccountRecoveryState, isAcceptableRecoveryPassword, requestAccountRecovery, requestAdministrativeAccountRecovery, verifyAccountRecoveryEmail } from "@virki/auth/security";
import { requireSecurityElevation } from "@virki/auth/administration";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@virki/auth/csrf";
import { validateSessionCsrfToken } from "../../lib/session-csrf";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { recordSecurityDenial } from "../../lib/audit-denial";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface, hasSameOrigin } from "../../lib/surface";
import { RECOVERY_COOKIE_NAME } from "../../lib/recovery";
import { clearRecoveryCandidateCookie, clearRecoveryCookie, RECOVERY_CANDIDATE_COOKIE, setRecoveryCandidateCookie, setRecoveryCookie } from "./recovery-cookie";

export async function requestRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const { requestHeaders } = await requireRecoveryAccess(formData, "recovery-request", "portal");
  try {
    await requestAccountRecovery(read(formData, "email"), "pt-BR", new Date(), requestHeaders.get("cf-connecting-ip")?.trim());
  } catch {
    await recordSecurityDenial(requestHeaders, "account-recovery-request", "rejected");
    // Keep account existence and mail-delivery state private.
  }
  redirect("/recover?sent=1");
  });
}

export async function requestAdministrativeRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const { requestHeaders } = await requireRecoveryAccess(formData, "recovery-admin-request", "hub");
  try {
    await requestAdministrativeAccountRecovery(read(formData, "email"), "pt-BR", new Date(), requestHeaders.get("cf-connecting-ip")?.trim());
  } catch {
    await recordSecurityDenial(requestHeaders, "account-recovery-request", "rejected");
    // Keep account existence and mail-delivery state private.
  }
  redirect("/recover?sent=1");
  });
}

export async function openRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-open");
  const requestKey = read(formData, "requestKey");
  const recovery = await getAccountRecoveryRequestId(requestKey, new Date(), expectedRole);
  if (!recovery) redirect("/recover?error=1");
  const cookieStore = await cookies();
  const activeKey = cookieStore.get(RECOVERY_COOKIE_NAME)?.value;
  if (activeKey && activeKey !== requestKey) {
    setRecoveryCandidateCookie(cookieStore, requestKey, recovery.expiresAt);
    redirect(`/recover?switch=1&requestId=${encodeURIComponent(recovery.id)}`);
  }
  setRecoveryCookie(cookieStore, requestKey, recovery.expiresAt);
  redirect(`/recover?requestId=${encodeURIComponent(recovery.id)}`);
  });
}

export type RecoverySwitchActionState = { status: "idle" | "error" | "complete"; requestId?: string };

export async function switchRecoveryAction(_previousState: RecoverySwitchActionState, formData: FormData): Promise<RecoverySwitchActionState> {
  return withHubAuditRequest(async () => {
    const { expectedRole } = await requireRecoveryAccess(formData, "recovery-open");
    const cookieStore = await cookies();
    const requestKey = cookieStore.get(RECOVERY_CANDIDATE_COOKIE)?.value ?? "";
    const requestId = read(formData, "requestId");
    const recovery = await getAccountRecoveryRequestId(requestKey, new Date(), expectedRole);
    if (!recovery || recovery.id !== requestId) {
      await recordSecurityDenial(await headers(), "account-recovery-switch", "rejected");
      return { status: "error" };
    }
    setRecoveryCookie(cookieStore, requestKey, recovery.expiresAt);
    clearRecoveryCandidateCookie(cookieStore);
    return { status: "complete", requestId: recovery.id };
  });
}

export type RecoveryVerificationActionState = { status: "idle" | "error" | "verified" };

export async function verifyRecoveryAction(_state: RecoveryVerificationActionState, formData: FormData): Promise<RecoveryVerificationActionState> {
  return withHubAuditRequest(async () => {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-verify");
  const requestId = read(formData, "requestId");
  const requestKey = (await cookies()).get(RECOVERY_COOKIE_NAME)?.value;
  if (!requestKey) return { status: "error" };
  try {
    await verifyAccountRecoveryEmail(requestId, requestKey, read(formData, "code"), new Date(), expectedRole);
  } catch {
    await recordSecurityDenial(await headers(), "account-recovery-verify", "rejected");
    return { status: "error" };
  }
  return { status: "verified" };
  });
}

export async function completeRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-complete");
  const requestId = read(formData, "requestId");
  const requestKey = (await cookies()).get(RECOVERY_COOKIE_NAME)?.value;
  if (!requestKey) redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  const newPassword = readRaw(formData, "newPassword");
  if (!isAcceptableRecoveryPassword(expectedRole, newPassword)) redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=password`);
  const recovery = await getAccountRecoveryState(requestId, requestKey, new Date(), expectedRole);
  try {
    await consumeApprovedAccountRecovery(requestId, requestKey, newPassword, new Date(), expectedRole);
  } catch {
    await recordSecurityDenial(await headers(), "account-recovery-complete", "rejected");
    redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  }
  const cookieStore = await cookies();
  clearRecoveryCookie(cookieStore);
  clearRecoveryCandidateCookie(cookieStore);
  redirect(recovery?.purpose === "INVITATION" ? "/login?invited=1" : "/login?recovered=1");
  });
}

export async function approveRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const requestHeaders = await headers();
  if (!hasSameOrigin(requestHeaders) || !(await validateSessionCsrfToken(read(formData, CSRF_FORM_FIELD_NAME), "admin-security"))) { await recordSecurityDenial(requestHeaders, "account-recovery-approve", "csrf"); redirect("/login"); }
  if (getSurface(requestHeaders) !== "hub" || !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery-approve"))) { await recordSecurityDenial(requestHeaders, "account-recovery-approve", "role"); redirect("/login"); }
  const session = await getCurrentSession();
  if (!session || session.user.role !== "ADMIN") { await recordSecurityDenial(requestHeaders, "account-recovery-approve", "role", session); redirect("/login"); }
  try {
    await requireSecurityElevation(session.user.id, session.id, "ACCOUNT_STATE_CHANGE");
    await approveAccountRecovery(session.user, read(formData, "requestId"));
  } catch {
    await recordSecurityDenial(requestHeaders, "account-recovery-approve", "rejected", session);
    redirect("/admin/security?error=recovery#admin-content");
  }
  redirect("/admin/security?status=recovery#admin-content");
  });
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
  if (!hasSameOrigin(requestHeaders) || !recoverySurfaceAllowed || !validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME), { scope: csrfScope }).valid) { await recordSecurityDenial(requestHeaders, "account-recovery-access", "csrf"); redirect("/login"); }
  if (expectedSurface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery"))) { await recordSecurityDenial(requestHeaders, "account-recovery-access", "role"); redirect("/login"); }
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
