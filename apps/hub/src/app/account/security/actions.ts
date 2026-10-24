"use server";

import { withHubAuditRequest } from "../../../lib/audit-request";

import { revokeOtherAccountSessions, verifyPassword, writeAuditLogInTransaction } from "@virki/auth";
import { CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { validateSessionCsrfToken } from "../../../lib/session-csrf";
import { getAccountSecurityState, startTotpEnrollment, confirmTotpEnrollment, disableTotp, regenerateRecoveryCodes, listTrustedDevices, revokeTrustedDevice, consumeSecurityProofAttempt } from "@virki/auth/security";
import { prisma } from "@virki/database";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { recordSecurityDenial } from "../../../lib/audit-denial";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, hasSameOrigin } from "../../../lib/surface";

export type AccountSecurityState = { status: "idle" | "error" | "started" | "complete"; secret?: string; recoveryCodes?: string[] };

export async function startTotpAction(_state: AccountSecurityState, formData: FormData): Promise<AccountSecurityState> {
  return withHubAuditRequest(async () => {
  const session = await requireAccountMutation(formData, "account-totp-start");
  try {
    await consumeSecurityProofAttempt(session.user.id);
    const user = await prisma.user.findUnique({ where: { id: session.user.id }, select: { email: true, passwordHash: true, isActive: true } });
    const password = readRaw(formData, "password");
    if (!user?.isActive || !user.passwordHash || !await verifyPassword(user.passwordHash, password)) throw new Error("Rejected.");
    const enrollment = await startTotpEnrollment(session.user.id, user.email);
    revalidatePath("/account/security");
    return { status: "started", secret: enrollment.secret };
  } catch { await recordSecurityDenial(await headers(), "account-security-proof", "rejected", session); return { status: "error" }; }
  });
}

export async function confirmTotpAction(_state: AccountSecurityState, formData: FormData): Promise<AccountSecurityState> {
  return withHubAuditRequest(async () => {
  const session = await requireAccountMutation(formData, "account-totp-confirm");
  try {
    const recoveryCodes = await confirmTotpEnrollment(session.user.id, read(formData, "code"));
    revalidatePath("/account/security");
    return { status: "complete", recoveryCodes };
  } catch { await recordSecurityDenial(await headers(), "account-security-proof", "rejected", session); return { status: "error" }; }
  });
}

export async function disableTotpAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const session = await requireAccountMutation(formData, "account-totp-disable");
  try { await disableTotp(session.user.id, read(formData, "code")); }
  catch { await recordSecurityDenial(await headers(), "account-totp-disable", "rejected", session); redirect("/account/security?error=totp"); }
  redirect("/login?security=changed");
  });
}

export async function regenerateRecoveryCodesAction(_state: AccountSecurityState, formData: FormData): Promise<AccountSecurityState> {
  return withHubAuditRequest(async () => {
  const session = await requireAccountMutation(formData, "account-recovery-codes");
  try {
    const recoveryCodes = await regenerateRecoveryCodes(session.user.id, read(formData, "code"));
    revalidatePath("/account/security");
    return { status: "complete", recoveryCodes };
  } catch { await recordSecurityDenial(await headers(), "account-security-proof", "rejected", session); return { status: "error" }; }
  });
}

export async function revokeTrustedDeviceAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const session = await requireAccountMutation(formData, "account-device-revoke");
  try { await revokeTrustedDevice(session.user.id, read(formData, "deviceKey")); }
  catch { await recordSecurityDenial(await headers(), "account-device-revoke", "rejected", session); redirect("/account/security?error=device"); }
  revalidatePath("/account/security");
  redirect("/account/security?status=device");
  });
}

export async function revokeAccountSessionAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const session = await requireAccountMutation(formData, "account-session-revoke");
  const target = read(formData, "sessionId");
  if (!/^[A-Za-z0-9_-]{8,80}$/u.test(target) || target === session.id) redirect("/account/security?error=session");
  try {
    await prisma.$transaction(async (transaction) => {
      // The bulk revoke and password writers lock User before Session. Keep
      // this single-session writer in the same order to avoid a User/Session
      // deadlock with concurrent bulk revocation or account recovery.
      const users = await transaction.$queryRaw<Array<{ id: string }>>`
        SELECT "id" FROM "User"
        WHERE "id" = ${session.user.id} AND "role" = ${session.user.role}::"UserRole"
          AND "isActive" = TRUE AND "accountStatus" = 'ACTIVE'::"AccountStatus"
        FOR UPDATE
      `;
      if (users.length !== 1) throw new Error("Rejected.");
      const liveSession = await transaction.$queryRaw<Array<{ id: string }>>`
        SELECT "id" FROM "Session"
        WHERE "id" = ${session.id} AND "userId" = ${session.user.id}
          AND "revokedAt" IS NULL AND "expiresAt" > ${new Date()}
        FOR UPDATE
      `;
      if (liveSession.length !== 1) throw new Error("Rejected.");
      const result = await transaction.session.updateMany({ where: { id: target, userId: session.user.id, revokedAt: null }, data: { revokedAt: new Date() } });
      if (result.count) await writeAuditLogInTransaction(transaction, { eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, resource: "session", message: "Other account session revoked." });
    });
  } catch {
    await recordSecurityDenial(await headers(), "account-session-revoke", "rejected", session);
    redirect("/account/security?error=session");
  }
  revalidatePath("/account/security");
  redirect("/account/security?status=session");
  });
}

export async function revokeOtherAccountSessionsAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
    const session = await requireAccountMutation(formData, "account-sessions-revoke");
    if (session.user.role !== "USER" || read(formData, "confirmed") !== "yes") {
      await recordSecurityDenial(await headers(), "account-sessions-revoke", "rejected", session);
      redirect("/account/security?error=sessions");
    }
    let revokedCount: number;
    try {
      await consumeSecurityProofAttempt(session.user.id);
      const user = await prisma.user.findUnique({ where: { id: session.user.id }, select: { passwordHash: true, role: true, isActive: true, accountStatus: true } });
      if (!user?.isActive || user.accountStatus !== "ACTIVE" || user.role !== "USER" || !user.passwordHash || !await verifyPassword(user.passwordHash, readRaw(formData, "password"))) throw new Error("Rejected.");
      revokedCount = await revokeOtherAccountSessions(session.user.id, session.id);
    } catch {
      await recordSecurityDenial(await headers(), "account-sessions-revoke", "rejected", session);
      redirect("/account/security?error=sessions");
    }
    revalidatePath("/account/security");
    redirect(`/account/security?status=${revokedCount > 0 ? "sessions" : "no-sessions"}`);
  });
}

export async function getAccountSecurityData() {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown" || (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-security-data")))) return null;
  const session = await getCurrentSession();
  if (!session || (surface === "hub" && session.user.role !== "ADMIN") || (surface === "portal" && session.user.role !== "USER")) return null;
  const now = new Date();
  const [state, devices, otherSessions, otherSessionCount] = await Promise.all([
    getAccountSecurityState(session.user.id),
    listTrustedDevices(session.user.id),
    prisma.session.findMany({ where: { userId: session.user.id, id: { not: session.id }, revokedAt: null, expiresAt: { gt: now } }, select: { id: true, createdAt: true, expiresAt: true }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 49 }),
    prisma.session.count({ where: { userId: session.user.id, id: { not: session.id }, revokedAt: null, expiresAt: { gt: now } } })
  ]);
  const sessions = [{ id: session.id, createdAt: session.createdAt, expiresAt: session.expiresAt }, ...otherSessions];
  return { session, state, devices, sessions, otherSessionCount };
}

async function requireAccountMutation(formData: FormData, source: string) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (!hasSameOrigin(requestHeaders)) { await recordSecurityDenial(requestHeaders, source, "csrf"); redirect("/login"); }
  if (surface === "unknown" || (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, source)))) { await recordSecurityDenial(requestHeaders, source, "role"); redirect("/login"); }
  if (!(await validateSessionCsrfToken(read(formData, CSRF_FORM_FIELD_NAME), "account-security"))) { await recordSecurityDenial(requestHeaders, source, "csrf"); redirect("/login"); }
  const session = await getCurrentSession();
  if (!session) { await recordSecurityDenial(requestHeaders, source, "role"); redirect("/login"); }
  if ((surface === "hub" && session.user.role !== "ADMIN") || (surface === "portal" && session.user.role !== "USER")) { await recordSecurityDenial(requestHeaders, source, "role", session); redirect("/login"); }
  return session;
}

function read(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value.trim() : ""; }
function readRaw(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value : ""; }
