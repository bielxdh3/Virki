"use server";

import {
  completeAdministrativeCredentialSetup,
  changeAdministrativePassword,
  regenerateAdministrativeRecoveryCodes,
  recoverAdministrativeCredential,
  startAdministrativeCredentialSetup,
  startSecurityElevation,
  verifySecurityElevation,
  type ElevationDuration,
  type ElevationScope
} from "@bielos/auth/administration";
import { hashAuditIdentifier, writeAuditLogInTransaction } from "@bielos/auth";
import { prisma } from "@bielos/database";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { requireAdminMutation, readFormRawString, readFormString } from "../../../lib/admin-mutation";

export type SecurityFormState = { status: "idle" | "error" | "started" | "complete"; requestKey?: string; scope?: string; recoveryCodes?: string[] };

export async function startCredentialSetupAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  const session = await requireAdminMutation(formData, "admin-credential-setup");
  try {
    const requestKey = await startAdministrativeCredentialSetup({ actor: session.user, sessionId: session.id, normalPassword: readFormRawString(formData, "normalPassword"), locale: "pt-BR" });
    return { status: "started", requestKey };
  } catch { return { status: "error" }; }
}

export async function completeCredentialSetupAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  const session = await requireAdminMutation(formData, "admin-credential-setup-complete");
  try {
    const recoveryCodes = await completeAdministrativeCredentialSetup({ actor: session.user, sessionId: session.id, requestKey: readFormString(formData, "requestKey"), code: readFormString(formData, "code"), newPassword: readFormRawString(formData, "newPassword") });
    revalidatePath("/admin/security");
    return { status: "complete", recoveryCodes };
  } catch { return { status: "error" }; }
}

export async function startElevationAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  const session = await requireAdminMutation(formData, "admin-elevation-start");
  const scope = readFormString(formData, "scope") as ElevationScope;
  try {
    const durationValue = readFormString(formData, "duration");
    const duration: ElevationDuration = durationValue === "manual"
      ? { kind: "MANUAL", confirmed: readFormString(formData, "manualConfirmed") === "true" }
      : { kind: "TIMED", minutes: Number(durationValue) as 15 | 60 | 240 | 1440 };
    const request = await startSecurityElevation({ actor: session.user, sessionId: session.id, normalPassword: readFormRawString(formData, "normalPassword"), administrativePassword: readFormRawString(formData, "administrativePassword"), scope, duration, locale: "pt-BR" });
    return { status: "started", requestKey: request.requestKey, scope };
  } catch { return { status: "error", scope }; }
}

export async function verifyElevationAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  const session = await requireAdminMutation(formData, "admin-elevation-verify");
  try {
    await verifySecurityElevation({ actor: session.user, sessionId: session.id, requestKey: readFormString(formData, "requestKey"), code: readFormString(formData, "code") });
    revalidatePath("/admin/security");
    return { status: "complete" };
  } catch {
    return { status: "error" };
  }
}

export async function revokeElevationAction(formData: FormData): Promise<void> {
  const session = await requireAdminMutation(formData, "admin-elevation-revoke");
  const requestKey = readFormString(formData, "requestKey");
  const revoked = await prisma.$transaction(async (transaction) => {
    const elevation = await transaction.securityElevation.findFirst({ where: { requestKey, userId: session.user.id, sessionId: session.id, status: "ACTIVE" }, select: { id: true } });
    if (!elevation) return false;
    const result = await transaction.securityElevation.updateMany({ where: { id: elevation.id, status: "ACTIVE" }, data: { status: "REVOKED", revokedAt: new Date() } });
    if (result.count !== 1) return false;
    await writeAuditLogInTransaction(transaction, { eventType: "ADMIN_ELEVATION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, resource: "identity.elevation", message: "Administrative elevation revoked.", metadata: { requestRef: hashAuditIdentifier(requestKey) } });
    return true;
  });
  if (!revoked) redirect("/admin/security?error=elevation#admin-content");
  revalidatePath("/admin/security");
  redirect("/admin/security?status=revoked#admin-content");
}

export async function revokeOtherSessionsAction(formData: FormData): Promise<void> {
  const session = await requireAdminMutation(formData, "admin-sessions-revoke");
  await prisma.$transaction(async (transaction) => {
    const result = await transaction.session.updateMany({ where: { userId: session.user.id, id: { not: session.id }, revokedAt: null }, data: { revokedAt: new Date() } });
    if (result.count) await writeAuditLogInTransaction(transaction, { eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, resource: "session", message: "Other active admin sessions revoked.", metadata: { revokedCount: result.count } });
  });
  revalidatePath("/admin/security");
  redirect("/admin/security?status=sessions#admin-content");
}

export async function changeAdminPasswordAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  const session = await requireAdminMutation(formData, "admin-credential-change");
  try {
    await changeAdministrativePassword(session.user, session.id, readFormRawString(formData, "newPassword"));
    revalidatePath("/admin/security");
    return { status: "complete" };
  } catch { return { status: "error" }; }
}

export async function regenerateAdminRecoveryCodesAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  const session = await requireAdminMutation(formData, "admin-recovery-codes");
  try {
    const recoveryCodes = await regenerateAdministrativeRecoveryCodes(session.user, session.id);
    return { status: "complete", recoveryCodes };
  } catch { return { status: "error" }; }
}

export async function recoverAdminCredentialAction(_state: SecurityFormState, formData: FormData): Promise<SecurityFormState> {
  const session = await requireAdminMutation(formData, "admin-credential-recovery");
  try {
    const recoveryCodes = await recoverAdministrativeCredential({
      actor: session.user,
      normalPassword: readFormRawString(formData, "normalPassword"),
      recoveryCode: readFormString(formData, "recoveryCode"),
      newPassword: readFormRawString(formData, "newPassword")
    });
    revalidatePath("/admin/security");
    return { status: "complete", recoveryCodes };
  } catch {
    return { status: "error" };
  }
}
