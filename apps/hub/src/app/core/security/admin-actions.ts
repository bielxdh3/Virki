"use server";

import { completeAdministrativeCredentialSetup, recoverAdministrativeCredential, revokeSecurityElevation, startAdministrativeCredentialSetup, startSecurityElevation, verifySecurityElevation, type ElevationScope } from "@bielos/auth/administration";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";

export type AdminActionState = { status: "idle" | "ok" | "error"; requestKey?: string; recoveryCodes?: string[] };

export async function startAdminSetupAction(_state: AdminActionState, formData: FormData): Promise<AdminActionState> {
  const session = await requireOwnerMutation(formData, "admin-setup-start");
  try { return { status: "ok", requestKey: await startAdministrativeCredentialSetup({ actor: session.user, sessionId: session.id, normalPassword: read(formData, "normalPassword"), locale: "pt-BR" }) }; } catch { return { status: "error" }; }
}

export async function completeAdminSetupAction(_state: AdminActionState, formData: FormData): Promise<AdminActionState> {
  const session = await requireOwnerMutation(formData, "admin-setup-complete");
  try { return { status: "ok", recoveryCodes: await completeAdministrativeCredentialSetup({ actor: session.user, sessionId: session.id, requestKey: read(formData, "requestKey"), code: read(formData, "code"), newPassword: read(formData, "newPassword") }) }; } catch { return { status: "error" }; }
}

export async function recoverAdminCredentialAction(_state: AdminActionState, formData: FormData): Promise<AdminActionState> {
  const session = await requireOwnerMutation(formData, "admin-recovery");
  try {
    return {
      status: "ok",
      recoveryCodes: await recoverAdministrativeCredential({
        actor: session.user,
        normalPassword: read(formData, "normalPassword"),
        recoveryCode: read(formData, "recoveryCode"),
        newPassword: read(formData, "newPassword")
      })
    };
  } catch {
    return { status: "error" };
  }
}

export async function startElevationAction(_state: AdminActionState, formData: FormData): Promise<AdminActionState> {
  const session = await requireOwnerMutation(formData, "elevation-start");
  try {
    const result = await startSecurityElevation({ actor: session.user, sessionId: session.id, normalPassword: read(formData, "normalPassword"), administrativePassword: read(formData, "administrativePassword"), scope: read(formData, "scope") as ElevationScope, duration: read(formData, "duration") === "MANUAL" ? { kind: "MANUAL", confirmed: read(formData, "manualConfirm") === "yes" } : { kind: "TIMED", minutes: Number(read(formData, "minutes")) as 15 | 60 | 240 | 1440 }, locale: "pt-BR" });
    return { status: "ok", requestKey: result.requestKey };
  } catch { return { status: "error" }; }
}

export async function verifyElevationAction(_state: AdminActionState, formData: FormData): Promise<AdminActionState> {
  const session = await requireOwnerMutation(formData, "elevation-verify");
  try { await verifySecurityElevation({ actor: session.user, sessionId: session.id, requestKey: read(formData, "requestKey"), code: read(formData, "code") }); return { status: "ok" }; } catch { return { status: "error" }; }
}

export async function revokeElevationAction(formData: FormData): Promise<void> {
  const session = await requireOwnerMutation(formData, "elevation-revoke");
  try { await revokeSecurityElevation(session.user, session.id, read(formData, "requestKey") || undefined); } catch { forbidden(); }
}

async function requireOwnerMutation(formData: FormData, source: string) {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), source))) forbidden();
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) forbidden();
  const session = await getCurrentSession();
  if (!session || session.user.role !== "OWNER") forbidden();
  return session;
}
function read(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value.trim() : ""; }
