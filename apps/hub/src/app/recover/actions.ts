"use server";

import { randomBytes } from "node:crypto";
import { withHubAuditRequest } from "../../lib/audit-request";

import { SESSION_COOKIE_NAME, getSessionCookieOptions } from "@virki/auth";
import { approveAccountRecovery, consumeApprovedAccountRecovery, getAccountRecoveryRequestId, getAccountRecoveryState, isAcceptableRecoveryPassword, requestAccountRecovery, requestAdministrativeAccountRecovery, verifyAccountRecoveryEmail } from "@virki/auth/security";
import { requireSecurityElevation } from "@virki/auth/administration";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@virki/auth/csrf";
import { validateSessionCsrfTokenFor } from "../../lib/session-csrf";
import { cookies, headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { recordSecurityDenial, recordSessionCsrfDenial } from "../../lib/audit-denial";
import { getCurrentSession } from "../../lib/auth";
import { expectedPasskeyRP } from "@virki/auth/passkeys";
import {
  canRetainMultiMethodRecoveryBrowser, finishRecoveryPasskeyAssertion, generateRecoveryPublicRequestId, startMultiMethodRecovery, startRecoveryPasskeyAssertion,
  startRecoveryNewMailbox, verifyRecoveryNewMailbox, verifyMultiMethodRecoveryEmail, verifyMultiMethodRecoveryTotp
} from "@virki/auth/recovery-methods";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface, hasSameOrigin, requestHost } from "../../lib/surface";
import { RECOVERY_COOKIE_NAME, requiresRecoveryRequestSwitch } from "../../lib/recovery";
import {
  clearMultiMethodRecoveryCookies, clearRecoveryCandidateCookie, clearRecoveryCookie,
  parseRecoveryIntent, RECOVERY_BROWSER_COOKIE, RECOVERY_CANDIDATE_COOKIE, RECOVERY_INTENT_COOKIE,
  setMultiMethodRecoveryCookies, setRecoveryCandidateCookie, setRecoveryCookie
} from "./recovery-cookie";
import { EMAIL_INPUT_MAX_LENGTH, readBoundedFormString } from "../../lib/action-input-limits";
import { recoveryPolicyFromMethod, type RecoveryRequestMethod } from "./recovery-method-selection";
import type { RecoveryPasskeyStartState, RecoveryProofActionState } from "./recovery-proof-stage";

export async function requestRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const { requestHeaders } = await requireRecoveryAccess(formData, "recovery-request", "portal");
  if (formData.has("method")) return startSelectedRecovery(formData, "USER", requestHeaders);
  const email = readBoundedFormString(formData, "email", EMAIL_INPUT_MAX_LENGTH);
  try {
    if (email === null) throw new Error("Rejected.");
    await requestAccountRecovery(email.trim(), "pt-BR", new Date(), requestHeaders.get("cf-connecting-ip")?.trim());
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
  if (formData.has("method")) return startSelectedRecovery(formData, "ADMIN", requestHeaders);
  const email = readBoundedFormString(formData, "email", EMAIL_INPUT_MAX_LENGTH);
  try {
    if (email === null) throw new Error("Rejected.");
    await requestAdministrativeAccountRecovery(email.trim(), "pt-BR", new Date(), requestHeaders.get("cf-connecting-ip")?.trim());
  } catch {
    await recordSecurityDenial(requestHeaders, "account-recovery-request", "rejected");
    // Keep account existence and mail-delivery state private.
  }
  redirect("/recover?sent=1");
  });
}

async function startSelectedRecovery(formData: FormData, expectedRole: "USER" | "ADMIN", requestHeaders: Headers): Promise<never> {
  const startTime = Date.now();
  const method = read(formData, "method");
  const policy = recoveryPolicyFromMethod(method);
  const email = readBoundedFormString(formData, "email", EMAIL_INPUT_MAX_LENGTH);
  // The author-facing 300-character cap uses Unicode code points. 600 UTF-16
  // units is the tightest transport ceiling for up to 300 astral characters;
  // the server subsequently enforces the actual 300-character policy.
  const comment = readBoundedFormString(formData, "comment", 600);
  const cookieStore = await cookies();
  const existingIntent = parseRecoveryIntent(cookieStore.get(RECOVERY_INTENT_COOKIE)?.value);
  const existingPolicy = recoveryPolicyFromMethod(existingIntent?.method);
  const existing = existingIntent ? {
    requestId: existingIntent.requestId,
    requestKey: cookieStore.get(RECOVERY_COOKIE_NAME)?.value ?? "",
    browserToken: cookieStore.get(RECOVERY_BROWSER_COOKIE)?.value ?? ""
  } : null;
  // Before handling a new anonymous request, protect this browser's existing,
  // independently proven recovery. A malformed or throttled restart must not
  // replace its only copy of the original capability with synthetic cookies.
  // This does not mint/resend anything or bypass the verification rate limits.
  let canRetain = false;
  if (existing && existingPolicy) {
    try {
      canRetain = await canRetainMultiMethodRecoveryBrowser(existing, expectedRole, existingPolicy);
    } catch {
      // Failure to validate a capability never grants access.
    }
  }
  let recovery = {
    // Use the same opaque format as real and synthetic backend requests. A
    // validation/error branch must never reveal account existence by ID shape.
    requestId: generateRecoveryPublicRequestId(),
    requestKey: randomBytes(24).toString("base64url"),
    browserToken: randomBytes(32).toString("base64url")
  };
  if (!canRetain) try {
    // Enforce the role and method policy on the server; browser radios are never authoritative.
    if (!policy || !email ||
      (policy.adminReview ? formData.has("comment") && comment === null : formData.has("comment"))) throw new Error("Rejected.");
    recovery = await startMultiMethodRecovery(email.trim(), expectedRole, policy, "pt-BR", new Date(),
      requestHeaders.get("cf-connecting-ip")?.trim(), policy.adminReview ? comment ?? undefined : undefined, requestHost(requestHeaders));
  } catch {
    await recordSecurityDenial(requestHeaders, "account-recovery-request", "rejected");
    // A synthetic, capability-less browser session renders the same initial step as a real one.
  }
  const remaining = 500 - (Date.now() - startTime);
  if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  if (canRetain && existing) {
    // Retain the original bearer pair and its original cookie expiry unchanged.
    clearRecoveryCandidateCookie(cookieStore);
    redirect(`/recover?requestId=${encodeURIComponent(existing.requestId)}`);
  }
  setMultiMethodRecoveryCookies(cookieStore, recovery.requestKey, recovery.browserToken, recovery.requestId, method as RecoveryRequestMethod);
  clearRecoveryCandidateCookie(cookieStore);
  redirect(`/recover?requestId=${encodeURIComponent(recovery.requestId)}`);
}

export async function openRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-open");
  const requestKey = read(formData, "requestKey");
  const recovery = await getAccountRecoveryRequestId(requestKey, new Date(), expectedRole);
  if (!recovery) redirect("/recover?error=1");
  const cookieStore = await cookies();
  const activeKey = cookieStore.get(RECOVERY_COOKIE_NAME)?.value;
  const activeRecovery = activeKey ? await getAccountRecoveryRequestId(activeKey, new Date(), expectedRole) : null;
  if (requiresRecoveryRequestSwitch(activeRecovery?.id, recovery.id)) {
    setRecoveryCandidateCookie(cookieStore, requestKey, recovery.expiresAt);
    redirect(`/recover?switch=1&requestId=${encodeURIComponent(recovery.id)}`);
  }
  clearRecoveryCandidateCookie(cookieStore);
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

function recoveryBrowserState(cookieStore: Awaited<ReturnType<typeof cookies>>, requestId: string) {
  const requestKey = cookieStore.get(RECOVERY_COOKIE_NAME)?.value ?? "";
  const browserToken = cookieStore.get(RECOVERY_BROWSER_COOKIE)?.value ?? "";
  const intent = parseRecoveryIntent(cookieStore.get(RECOVERY_INTENT_COOKIE)?.value);
  return intent?.requestId === requestId && requestKey && browserToken ? { requestKey, browserToken } : null;
}

export async function verifySelectedRecoveryEmailAction(_state: RecoveryProofActionState, formData: FormData): Promise<RecoveryProofActionState> {
  return withHubAuditRequest(async () => {
    const { expectedRole, requestHeaders } = await requireRecoveryAccess(formData, "recovery-verify");
    const requestId = read(formData, "requestId");
    const browserState = recoveryBrowserState(await cookies(), requestId);
    if (!browserState) return { status: "error" };
    try {
      await verifyMultiMethodRecoveryEmail(requestId, browserState.requestKey, browserState.browserToken, read(formData, "code"), expectedRole);
      return { status: "verified" };
    } catch {
      await recordSecurityDenial(requestHeaders, "account-recovery-verify", "rejected");
      return { status: "error" };
    }
  });
}

export async function verifySelectedRecoveryTotpAction(_state: RecoveryProofActionState, formData: FormData): Promise<RecoveryProofActionState> {
  return withHubAuditRequest(async () => {
    const { expectedRole, requestHeaders } = await requireRecoveryAccess(formData, "recovery-verify");
    const requestId = read(formData, "requestId");
    const browserState = recoveryBrowserState(await cookies(), requestId);
    if (!browserState) return { status: "error" };
    try {
      await verifyMultiMethodRecoveryTotp(requestId, browserState.requestKey, browserState.browserToken, read(formData, "code"), expectedRole);
      return { status: "verified" };
    } catch {
      await recordSecurityDenial(requestHeaders, "account-recovery-verify", "rejected");
      return { status: "error" };
    }
  });
}

export type RecoveryNewMailboxActionState = { status: "idle" | "error" | "sent" | "verified" };

export async function startRecoveryNewMailboxAction(_state: RecoveryNewMailboxActionState, formData: FormData): Promise<RecoveryNewMailboxActionState> {
  return withHubAuditRequest(async () => {
    const { expectedRole, requestHeaders } = await requireRecoveryAccess(formData, "recovery-verify");
    const requestId = read(formData, "requestId");
    const bound = recoveryBrowserState(await cookies(), requestId);
    const newEmail = readBoundedFormString(formData, "newEmail", 254);
    if (!bound || !newEmail) return { status: "error" };
    try {
      await startRecoveryNewMailbox(requestId, bound.requestKey, bound.browserToken, expectedRole, newEmail);
      return { status: "sent" };
    } catch {
      await recordSecurityDenial(requestHeaders, "account-recovery-new-mail-start", "rejected");
      return { status: "error" };
    }
  });
}

export async function verifyRecoveryNewMailboxAction(_state: RecoveryNewMailboxActionState, formData: FormData): Promise<RecoveryNewMailboxActionState> {
  return withHubAuditRequest(async () => {
    const { expectedRole, requestHeaders } = await requireRecoveryAccess(formData, "recovery-verify");
    const requestId = read(formData, "requestId");
    const bound = recoveryBrowserState(await cookies(), requestId);
    if (!bound) return { status: "error" };
    try {
      await verifyRecoveryNewMailbox(requestId, bound.requestKey, bound.browserToken, expectedRole, read(formData, "code"));
      return { status: "verified" };
    } catch {
      await recordSecurityDenial(requestHeaders, "account-recovery-new-mail-verify", "rejected");
      return { status: "error" };
    }
  });
}

export async function startSelectedRecoveryPasskeyAction(formData: FormData): Promise<RecoveryPasskeyStartState> {
  return withHubAuditRequest(async () => {
    const { expectedRole, requestHeaders } = await requireRecoveryAccess(formData, "recovery-verify");
    const requestId = read(formData, "requestId");
    const browserState = recoveryBrowserState(await cookies(), requestId);
    if (!browserState) return { status: "error" };
    const host = requestHost(requestHeaders);
    try {
      const options = await startRecoveryPasskeyAssertion(requestId, browserState.requestKey, browserState.browserToken, expectedRole, host);
      return { status: "ready", options };
    } catch {
      await recordSecurityDenial(requestHeaders, "account-recovery-passkey-start", "rejected");
      // Unknown accounts and expired capabilities receive a non-authorizing challenge, too.
      // This avoids exposing account existence by returning a different action state.
      try {
        const { rpID } = expectedPasskeyRP(process.env, host, expectedRole);
        return { status: "ready", options: { challenge: randomBytes(32).toString("base64url"), rpId: rpID, timeout: 5 * 60_000, userVerification: "required" } };
      } catch {
        return { status: "error" };
      }
    }
  });
}

export async function verifySelectedRecoveryPasskeyAction(formData: FormData): Promise<RecoveryProofActionState> {
  return withHubAuditRequest(async () => {
    const { expectedRole, requestHeaders } = await requireRecoveryAccess(formData, "recovery-verify");
    const requestId = read(formData, "requestId");
    const browserState = recoveryBrowserState(await cookies(), requestId);
    if (!browserState) return { status: "error" };
    const assertion = readBoundedFormString(formData, "assertion", 16384);
    if (!assertion) return { status: "error" };
    try {
      await finishRecoveryPasskeyAssertion(requestId, browserState.requestKey, browserState.browserToken,
        JSON.parse(assertion), expectedRole, requestHost(requestHeaders));
      return { status: "verified" };
    } catch {
      await recordSecurityDenial(requestHeaders, "account-recovery-passkey-verify", "rejected");
      return { status: "error" };
    }
  });
}

export type RecoveryCompletionActionState = { status: "idle" | "password-error" | "completed" };

export async function completeRecoveryAction(_previousState: RecoveryCompletionActionState, formData: FormData): Promise<RecoveryCompletionActionState> {
  return withHubAuditRequest(async () => {
  const { expectedRole } = await requireRecoveryAccess(formData, "recovery-complete");
  const requestId = read(formData, "requestId");
  const cookieStore = await cookies();
  const requestKey = cookieStore.get(RECOVERY_COOKIE_NAME)?.value;
  if (!requestKey) redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  const newPassword = readRaw(formData, "newPassword");
  if (!isAcceptableRecoveryPassword(expectedRole, newPassword)) return { status: "password-error" };
  const recovery = await getAccountRecoveryState(requestId, requestKey, new Date(), expectedRole);
  let newSession: Awaited<ReturnType<typeof consumeApprovedAccountRecovery>>;
  try {
    const browserState = recoveryBrowserState(cookieStore, requestId);
    newSession = await consumeApprovedAccountRecovery(requestId, requestKey, newPassword, undefined, expectedRole, browserState?.browserToken ?? "");
  } catch {
    await recordSecurityDenial(await headers(), "account-recovery-complete", "rejected");
    redirect(`/recover?requestId=${encodeURIComponent(requestId)}&error=1`);
  }
  clearRecoveryCookie(cookieStore);
  clearMultiMethodRecoveryCookies(cookieStore);
  clearRecoveryCandidateCookie(cookieStore);
  if (newSession) {
    cookieStore.set(SESSION_COOKIE_NAME, newSession.token, getSessionCookieOptions(newSession.expiresAt));
    // A Server Action redirect may attempt to render the protected admin route
    // through this action's RSC request, which does not have the next document's
    // Cloudflare Access/render provenance. The client must navigate with a
    // fresh document GET after the new host-only session cookie is committed.
    return { status: "completed" };
  }
  redirect(recovery?.purpose === "INVITATION" ? "/login?invited=1" : "/login?recovered=1");
  });
}

export async function approveRecoveryAction(formData: FormData) {
  return withHubAuditRequest(async () => {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface !== "hub" || !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery-approve"))) { await recordSecurityDenial(requestHeaders, "account-recovery-approve", "role"); forbidden(); }
  if (!hasSameOrigin(requestHeaders)) { await recordSecurityDenial(requestHeaders, "account-recovery-approve", "csrf"); forbidden(); }
  const sessionToken = (await cookies()).get(SESSION_COOKIE_NAME)?.value;
  if (!validateSessionCsrfTokenFor(sessionToken, read(formData, CSRF_FORM_FIELD_NAME), "admin-security")) { await recordSessionCsrfDenial(requestHeaders, "account-recovery-approve", sessionToken); forbidden(); }
  const session = await getCurrentSession();
  if (!session || session.user.role !== "ADMIN") { await recordSecurityDenial(requestHeaders, "account-recovery-approve", "role", session); forbidden(); }
  try {
    await requireSecurityElevation(session.user.id, session.id, "ACCOUNT_STATE_CHANGE");
    await approveAccountRecovery(session.user, session.id, read(formData, "requestId"));
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
  if (!recoverySurfaceAllowed) { await recordSecurityDenial(requestHeaders, "account-recovery-access", "role"); forbidden(); }
  if (expectedSurface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery"))) { await recordSecurityDenial(requestHeaders, "account-recovery-access", "role"); forbidden(); }
  if (!hasSameOrigin(requestHeaders) || !validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME), { scope: csrfScope }).valid) { await recordSecurityDenial(requestHeaders, "account-recovery-access", "csrf"); forbidden(); }
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
