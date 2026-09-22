"use server";

import {
  completeAdministrativeCredentialSetup,
  changeAdministrativePassword,
  regenerateAdministrativeRecoveryCodes,
  startAdministrativeCredentialSetup,
  startSecurityElevation,
  verifySecurityElevation,
  type ElevationDuration,
  type ElevationScope
} from "@bielos/auth/administration";
import { writeAuditLog } from "@bielos/auth";
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

export async function verifyElevationAction(formData: FormData): Promise<void> {
  const session = await requireAdminMutation(formData, "admin-elevation-verify");
  try {
    await verifySecurityElevation({ actor: session.user, sessionId: session.id, requestKey: readFormString(formData, "requestKey"), code: readFormString(formData, "code") });
    revalidatePath("/admin/security");
  } catch { redirect("/admin/security?error=elevation"); }
  redirect("/admin/security?status=elevation");
}

export async function revokeElevationAction(formData: FormData): Promise<void> {
  const session = await requireAdminMutation(formData, "admin-elevation-revoke");
  const requestKey = readFormString(formData, "requestKey");
  const elevation = await prisma.securityElevation.findFirst({ where: { requestKey, userId: session.user.id, sessionId: session.id, status: "ACTIVE" }, select: { id: true } });
  if (!elevation) redirect("/admin/security?error=elevation");
  await prisma.securityElevation.update({ where: { id: elevation.id }, data: { status: "REVOKED", revokedAt: new Date() } });
  await writeAuditLog({ eventType: "ADMIN_ELEVATION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, resource: "identity.elevation", message: "Administrative elevation revoked." });
  revalidatePath("/admin/security");
  redirect("/admin/security?status=revoked");
}

export async function revokeOtherSessionsAction(formData: FormData): Promise<void> {
  const session = await requireAdminMutation(formData, "admin-sessions-revoke");
  const result = await prisma.session.updateMany({ where: { userId: session.user.id, id: { not: session.id }, revokedAt: null }, data: { revokedAt: new Date() } });
  await writeAuditLog({ eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS", actorUserId: session.user.id, resource: "session", message: "Other active admin sessions revoked.", metadata: { revokedCount: result.count } });
  revalidatePath("/admin/security");
  redirect("/admin/security?status=sessions");
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
