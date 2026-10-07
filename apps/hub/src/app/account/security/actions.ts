"use server";

import { verifyPassword, writeAuditLogInTransaction } from "@virki/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@virki/auth/csrf";
import { getAccountSecurityState, startTotpEnrollment, confirmTotpEnrollment, disableTotp, regenerateRecoveryCodes, listTrustedDevices, revokeTrustedDevice, consumeSecurityProofAttempt } from "@virki/auth/security";
import { prisma } from "@virki/database";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, hasSameOrigin } from "../../../lib/surface";

export type AccountSecurityState = { status: "idle" | "error" | "started" | "complete"; secret?: string; recoveryCodes?: string[] };

export async function startTotpAction(_state: AccountSecurityState, formData: FormData): Promise<AccountSecurityState> {
  const session = await requireAccountMutation(formData, "account-totp-start");
  try {
    await consumeSecurityProofAttempt(session.user.id);
    const user = await prisma.user.findUnique({ where: { id: session.user.id }, select: { email: true, passwordHash: true, isActive: true } });
    const password = readRaw(formData, "password");
    if (!user?.isActive || !user.passwordHash || !await verifyPassword(user.passwordHash, password)) throw new Error("Rejected.");
    const enrollment = await startTotpEnrollment(session.user.id, user.email);
    revalidatePath("/account/security");
    return { status: "started", secret: enrollment.secret };
  } catch { return { status: "error" }; }
}

export async function confirmTotpAction(_state: AccountSecurityState, formData: FormData): Promise<AccountSecurityState> {
  const session = await requireAccountMutation(formData, "account-totp-confirm");
  try {
    const recoveryCodes = await confirmTotpEnrollment(session.user.id, read(formData, "code"));
    revalidatePath("/account/security");
    return { status: "complete", recoveryCodes };
  } catch { return { status: "error" }; }
}

export async function disableTotpAction(formData: FormData): Promise<void> {
  const session = await requireAccountMutation(formData, "account-totp-disable");
  try { await disableTotp(session.user.id, read(formData, "code")); }
  catch { redirect("/account/security?error=totp"); }
  redirect("/login?security=changed");
}

export async function regenerateRecoveryCodesAction(_state: AccountSecurityState, formData: FormData): Promise<AccountSecurityState> {
  const session = await requireAccountMutation(formData, "account-recovery-codes");
  try {
    const recoveryCodes = await regenerateRecoveryCodes(session.user.id, read(formData, "code"));
    revalidatePath("/account/security");
    return { status: "complete", recoveryCodes };
  } catch { return { status: "error" }; }
}

export async function revokeTrustedDeviceAction(formData: FormData): Promise<void> {
  const session = await requireAccountMutation(formData, "account-device-revoke");
  try { await revokeTrustedDevice(session.user.id, read(formData, "deviceKey")); }
  catch { redirect("/account/security?error=device"); }
  revalidatePath("/account/security");
  redirect("/account/security?status=device");
}

export async function revokeAccountSessionAction(formData: FormData): Promise<void> {
  const session = await requireAccountMutation(formData, "account-session-revoke");
  const target = read(formData, "sessionId");
  if (!/^[A-Za-z0-9_-]{8,80}$/u.test(target) || target === session.id) redirect("/account/security?error=session");
  try {
    await prisma.$transaction(async (transaction) => {
      const result = await transaction.session.updateMany({ where: { id: target, userId: session.user.id, revokedAt: null }, data: { revokedAt: new Date() } });
      if (result.count) await writeAuditLogInTransaction(transaction, { eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, resource: "session", message: "Other account session revoked." });
    });
  } catch {
    redirect("/account/security?error=session");
  }
  revalidatePath("/account/security");
  redirect("/account/security?status=session");
}

export async function getAccountSecurityData() {
  const session = await getCurrentSession();
  if (!session) return null;
  const now = new Date();
  const [state, devices, sessions] = await Promise.all([
    getAccountSecurityState(session.user.id),
    listTrustedDevices(session.user.id),
    prisma.session.findMany({ where: { userId: session.user.id, revokedAt: null, expiresAt: { gt: now } }, select: { id: true, createdAt: true, expiresAt: true }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 50 })
  ]);
  return { session, state, devices, sessions };
}

async function requireAccountMutation(formData: FormData, source: string) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (!hasSameOrigin(requestHeaders) || surface === "unknown" || (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, source)))) redirect("/login");
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME), { scope: "account-security" }).valid) redirect("/login");
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  if ((surface === "hub" && session.user.role !== "ADMIN") || (surface === "portal" && session.user.role !== "USER")) redirect("/login");
  return session;
}

function read(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value.trim() : ""; }
function readRaw(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value : ""; }
