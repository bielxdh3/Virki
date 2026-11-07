"use server";

import { withHubAuditRequest } from "../../../lib/audit-request";

import {
  AdministrativePasswordReuseError,
  completeAdministrativeCredentialSetup,
  completeAdministrativeEmailRecovery,
  changeAdministrativePassword,
  regenerateAdministrativeRecoveryCodes,
  recoverAdministrativeCredential,
  startAdministrativeCredentialSetup,
  startAdministrativeEmailRecovery,
  startSecurityElevation,
  verifySecurityElevation,
  assertAdminSessionCurrentInTransaction,
  lockAdminSessionInTransaction,
  type ElevationDuration,
  type ElevationScope
} from "@virki/auth/administration";
import { hashAuditIdentifier, hashAuditSessionReference, writeAuditLogInTransaction } from "@virki/auth";
import { prisma } from "@virki/database";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { recordSecurityDenial } from "../../../lib/audit-denial";
import { requireAdminMutation, readFormString } from "../../../lib/admin-mutation";
import { PASSWORD_INPUT_MAX_LENGTH, readBoundedFormString } from "../../../lib/action-input-limits";

export type SecurityFormState = { status: "idle" | "error" | "password-reuse" | "password-mismatch" | "started" | "complete"; requestKey?: string; scope?: string; recoveryCodes?: string[] };

export async function startCredentialSetupAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
  const normalPassword = readBoundedFormString(formData, "normalPassword", PASSWORD_INPUT_MAX_LENGTH);
  const session = await requireAdminMutation(formData, "admin-credential-setup");
  if (normalPassword === null) {
    await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session);
    return { status: "error" };
  }
  try {
    const requestKey = await startAdministrativeCredentialSetup({ actor: session.user, sessionId: session.id, normalPassword, locale: "pt-BR" });
    return { status: "started", requestKey };
  } catch (error) { await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session); return { status: passwordStatus(error) }; }
  });
}

export async function completeCredentialSetupAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
  const newPassword = readBoundedFormString(formData, "newPassword", PASSWORD_INPUT_MAX_LENGTH);
  const confirmPassword = readBoundedFormString(formData, "confirmPassword", PASSWORD_INPUT_MAX_LENGTH);
  const session = await requireAdminMutation(formData, "admin-credential-setup-complete");
  if (newPassword === null || confirmPassword === null) {
    await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session);
    return { status: "error" };
  }
  if (newPassword !== confirmPassword) {
    await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session);
    return { status: "password-mismatch" };
  }
  try {
    const recoveryCodes = await completeAdministrativeCredentialSetup({ actor: session.user, sessionId: session.id, requestKey: readFormString(formData, "requestKey"), code: readFormString(formData, "code"), newPassword });
    revalidatePath("/admin/security");
    return { status: "complete", recoveryCodes };
  } catch (error) { await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session); return { status: passwordStatus(error) }; }
  });
}

export async function startElevationAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
  const normalPassword = readBoundedFormString(formData, "normalPassword", PASSWORD_INPUT_MAX_LENGTH);
  const administrativePassword = readBoundedFormString(formData, "administrativePassword", PASSWORD_INPUT_MAX_LENGTH);
  const session = await requireAdminMutation(formData, "admin-elevation-start");
  if (normalPassword === null || administrativePassword === null) {
    await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session);
    return { status: "error" };
  }
  const scope = readFormString(formData, "scope") as ElevationScope;
  try {
    const durationValue = readFormString(formData, "duration");
    const duration: ElevationDuration = durationValue === "manual"
      ? { kind: "MANUAL", confirmed: readFormString(formData, "manualConfirmed") === "true" }
      : { kind: "TIMED", minutes: Number(durationValue) as 15 | 60 | 240 | 1440 };
    const request = await startSecurityElevation({ actor: session.user, sessionId: session.id, normalPassword, administrativePassword, scope, duration, locale: "pt-BR" });
    return { status: "started", requestKey: request.requestKey, scope };
  } catch (error) { await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session); return { status: passwordStatus(error), scope }; }
  });
}

export async function verifyElevationAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
  const session = await requireAdminMutation(formData, "admin-elevation-verify");
  try {
    await verifySecurityElevation({ actor: session.user, sessionId: session.id, requestKey: readFormString(formData, "requestKey"), code: readFormString(formData, "code") });
    revalidatePath("/admin/security");
    return { status: "complete" };
  } catch {
    await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session);
    return { status: "error" };
  }
  });
}

export async function revokeElevationAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const session = await requireAdminMutation(formData, "admin-elevation-revoke");
  const requestKey = readFormString(formData, "requestKey");
  const revoked = await prisma.$transaction(async (transaction) => {
    // Acquire the same User -> Session locks as other ADMIN security mutations.
    // A stale actor must never commit revocation/audit after an unrelated wait.
    await lockAdminSessionInTransaction(transaction, session.user.id, session.id, new Date());
    const elevation = await transaction.securityElevation.findFirst({ where: { requestKey, userId: session.user.id, sessionId: session.id, status: "ACTIVE" }, select: { id: true } });
    if (!elevation) return false;
    const result = await transaction.securityElevation.updateMany({ where: { id: elevation.id, status: "ACTIVE" }, data: { status: "REVOKED", revokedAt: new Date() } });
    if (result.count !== 1) return false;
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_ELEVATION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(session.id), resource: "identity.elevation", message: "Administrative elevation revoked.", metadata: { requestRef: hashAuditIdentifier(requestKey) } });
    // The elevation UPDATE/audit INSERT can wait until this session expires.
    // Recheck the current time after both writes, before the transaction commits.
    await assertAdminSessionCurrentInTransaction(transaction, session.user.id, session.id, new Date());
    return true;
  });
  if (!revoked) redirect("/admin/security?error=elevation#admin-content");
  revalidatePath("/admin/security");
  redirect("/admin/security?status=revoked#admin-content");
  });
}

export async function revokeOtherSessionsAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const session = await requireAdminMutation(formData, "admin-sessions-revoke");
  await prisma.$transaction(async (transaction) => {
    // Match ADMIN credential mutation lock ordering (User -> current Session),
    // so a concurrent deactivation/revocation cannot invalidate the actor
    // while a target Session UPDATE is waiting on a different transaction.
    await lockAdminSessionInTransaction(transaction, session.user.id, session.id, new Date());
    const result = await transaction.session.updateMany({ where: { userId: session.user.id, id: { not: session.id }, revokedAt: null }, data: { revokedAt: new Date() } });
    if (result.count) await writeAuditLogInTransaction(transaction, { eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(session.id), resource: "session", message: "Other active admin sessions revoked.", metadata: { revokedCount: result.count } });
    // Row locks cannot freeze time. A Session can expire during the target
    // UPDATE or audit write; always verify fresh validity after those waits.
    // DateTime is UTC timestamp without time zone, matching ADMIN auth checks.
    const checkedAt = new Date();
    const authorized = await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT s."id" FROM "User" u JOIN "Session" s ON s."userId" = u."id"
      WHERE u."id" = ${session.user.id} AND u."role" = 'ADMIN'::"UserRole"
        AND u."isActive" = TRUE AND u."accountStatus" = 'ACTIVE'::"AccountStatus"
        AND s."id" = ${session.id} AND s."revokedAt" IS NULL
        AND s."expiresAt" > (${checkedAt} AT TIME ZONE 'UTC')
    `;
    if (authorized.length !== 1) throw new Error("Administrative session revocation rejected.");
  });
  revalidatePath("/admin/security");
  redirect("/admin/security?status=sessions#admin-content");
  });
}

export async function changeAdminPasswordAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
  const newPassword = readBoundedFormString(formData, "newPassword", PASSWORD_INPUT_MAX_LENGTH);
  const session = await requireAdminMutation(formData, "admin-credential-change");
  if (newPassword === null) {
    await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session);
    return { status: "error" };
  }
  try {
    await changeAdministrativePassword(session.user, session.id, newPassword);
    revalidatePath("/admin/security");
    return { status: "complete" };
  } catch (error) { await recordSecurityDenial(await headers(), "admin-security-proof", "rejected", session); return { status: passwordStatus(error) }; }
  });
}

export async function regenerateAdminRecoveryCodesAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
  const session = await requireAdminMutation(formData, "admin-recovery-codes");
  try {
    const recoveryCodes = await regenerateAdministrativeRecoveryCodes(session.user, session.id);
    return { status: "complete", recoveryCodes };
  } catch { await recordSecurityDenial(await headers(), "admin-recovery-codes", "rejected", session); return { status: "error" }; }
  });
}

export async function recoverAdminCredentialAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
  const normalPassword = readBoundedFormString(formData, "normalPassword", PASSWORD_INPUT_MAX_LENGTH);
  const newPassword = readBoundedFormString(formData, "newPassword", PASSWORD_INPUT_MAX_LENGTH);
  const session = await requireAdminMutation(formData, "admin-credential-recovery");
  if (normalPassword === null || newPassword === null) {
    await recordSecurityDenial(await headers(), "admin-credential-recovery", "rejected", session);
    return { status: "error" };
  }
  try {
    const recoveryCodes = await recoverAdministrativeCredential({
      actor: session.user,
      sessionId: session.id,
      normalPassword,
      recoveryCode: readFormString(formData, "recoveryCode"),
      newPassword
    });
    revalidatePath("/admin/security");
    return { status: "complete", recoveryCodes };
  } catch (error) {
    await recordSecurityDenial(await headers(), "admin-credential-recovery", "rejected", session);
    return { status: passwordStatus(error) };
  }
  });
}

export async function startAdminEmailRecoveryAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
    const normalPassword = readBoundedFormString(formData, "normalPassword", PASSWORD_INPUT_MAX_LENGTH);
    const session = await requireAdminMutation(formData, "admin-email-recovery-start");
    if (normalPassword === null) {
      await recordSecurityDenial(await headers(), "admin-credential-email-recovery", "rejected", session);
      return { status: "error" };
    }
    try {
      const requestKey = await startAdministrativeEmailRecovery({ actor: session.user, sessionId: session.id, normalPassword, locale: "pt-BR" });
      return { status: "started", requestKey };
    } catch {
      await recordSecurityDenial(await headers(), "admin-credential-email-recovery", "rejected", session);
      return { status: "error" };
    }
  });
}

export async function completeAdminEmailRecoveryAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  return withHubAuditRequest(async () => {
    const normalPassword = readBoundedFormString(formData, "normalPassword", PASSWORD_INPUT_MAX_LENGTH);
    const newPassword = readBoundedFormString(formData, "newPassword", PASSWORD_INPUT_MAX_LENGTH);
    const confirmPassword = readBoundedFormString(formData, "confirmPassword", PASSWORD_INPUT_MAX_LENGTH);
    const session = await requireAdminMutation(formData, "admin-email-recovery-complete");
    if (normalPassword === null || newPassword === null || confirmPassword === null) {
      await recordSecurityDenial(await headers(), "admin-credential-email-recovery", "rejected", session);
      return { status: "error" };
    }
    if (newPassword !== confirmPassword) {
      await recordSecurityDenial(await headers(), "admin-credential-email-recovery", "rejected", session);
      return { status: "password-mismatch" };
    }
    try {
      const recoveryCodes = await completeAdministrativeEmailRecovery({
        actor: session.user,
        sessionId: session.id,
        requestKey: readFormString(formData, "requestKey"),
        code: readFormString(formData, "code"),
        normalPassword,
        newPassword
      });
      revalidatePath("/admin/security");
      return { status: "complete", recoveryCodes };
    } catch (error) {
      await recordSecurityDenial(await headers(), "admin-credential-email-recovery", "rejected", session);
      return { status: passwordStatus(error) };
    }
  });
}

function passwordStatus(error: unknown): SecurityFormState["status"] {
  return error instanceof AdministrativePasswordReuseError ? "password-reuse" : "error";
}
