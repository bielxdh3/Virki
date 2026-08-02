"use server";

import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { confirmTotpEnrollment, disableTotp, getAccountSecurityState, listTrustedDevices, regenerateRecoveryCodes, revokeTrustedDevice, startTotpEnrollment } from "@bielos/auth/security";
import { headers } from "next/headers";
import { forbidden } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";

export type SecurityActionState = { status: "idle" | "ok" | "error"; secret?: string; uri?: string; recoveryCodes?: string[] };

export async function startTotpEnrollmentAction(_state: SecurityActionState, formData: FormData): Promise<SecurityActionState> {
  const session = await requireAccountMutation(formData, "security-totp-start");
  try { const setup = await startTotpEnrollment(session.user.id, session.user.email); return { status: "ok", secret: setup.secret, uri: setup.uri }; } catch { return { status: "error" }; }
}

export async function confirmTotpEnrollmentAction(_state: SecurityActionState, formData: FormData): Promise<SecurityActionState> {
  const session = await requireAccountMutation(formData, "security-totp-confirm");
  try { return { status: "ok", recoveryCodes: await confirmTotpEnrollment(session.user.id, read(formData, "code")) }; } catch { return { status: "error" }; }
}

export async function regenerateRecoveryCodesAction(_state: SecurityActionState, formData: FormData): Promise<SecurityActionState> {
  const session = await requireAccountMutation(formData, "security-recovery-regenerate");
  try { return { status: "ok", recoveryCodes: await regenerateRecoveryCodes(session.user.id) }; } catch { return { status: "error" }; }
}

export async function disableTotpAction(formData: FormData): Promise<void> {
  const session = await requireAccountMutation(formData, "security-totp-disable");
  try { await disableTotp(session.user.id); } catch { forbidden(); }
}

export async function revokeTrustedDeviceAction(formData: FormData): Promise<void> {
  const session = await requireAccountMutation(formData, "security-device-revoke");
  try { await revokeTrustedDevice(session.user.id, read(formData, "deviceKey")); } catch { forbidden(); }
}

export async function loadTrustedDevices() {
  const session = await getCurrentSession();
  return session ? listTrustedDevices(session.user.id) : [];
}

export async function loadAccountSecurityState(userId: string) {
  return getAccountSecurityState(userId);
}

async function requireAccountMutation(formData: FormData, source: string) {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), source))) forbidden();
  if (!validateCsrfToken(read(formData, CSRF_FORM_FIELD_NAME)).valid) forbidden();
  const session = await getCurrentSession();
  if (!session) forbidden();
  return session;
}

function read(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value.trim() : ""; }
