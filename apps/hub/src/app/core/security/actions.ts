"use server";

import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";

import { getCurrentSession } from "../../../lib/auth";
import {
  isCloudflareAccessAllowed,
  validateHubCloudflareAccess
} from "../../../lib/cloudflare-access";
import {
  canRevokeOtherSession,
  isRevokeAllOtherSessionsConfirmed
} from "./session-policy";
import {
  revokeAllOtherCoreSessionRecords,
  revokeCoreSessionRecord
} from "./session-service";

const CORE_SECURITY_PATH = "/core/security";

function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

async function requireCoreSessionMutation(formData: FormData, source: string) {
  const accessResult = await validateHubCloudflareAccess(await headers(), source);

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const csrfResult = validateCsrfToken(readFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  return session;
}

function revalidateCoreSecurity() {
  revalidatePath(CORE_SECURITY_PATH);
  revalidatePath("/");
}

export async function revokeCoreSession(formData: FormData) {
  const session = await requireCoreSessionMutation(formData, "core-session-revoke");
  const targetSessionId = readFormString(formData, "sessionId");

  if (!canRevokeOtherSession(session.id, targetSessionId)) {
    redirect(`${CORE_SECURITY_PATH}?error=session`);
  }

  try {
    await revokeCoreSessionRecord(session.user, session.id, targetSessionId);
  } catch {
    redirect(`${CORE_SECURITY_PATH}?error=session`);
  }

  revalidateCoreSecurity();
  redirect(`${CORE_SECURITY_PATH}?status=session-revoked`);
}

export async function revokeAllOtherCoreSessions(formData: FormData) {
  const session = await requireCoreSessionMutation(formData, "core-session-revoke-all-other");
  const confirmed = isRevokeAllOtherSessionsConfirmed(
    readFormString(formData, "confirmAll")
  );

  if (!confirmed) {
    redirect(`${CORE_SECURITY_PATH}?error=session`);
  }

  try {
    await revokeAllOtherCoreSessionRecords(
      session.user,
      session.id,
      confirmed
    );
  } catch {
    redirect(`${CORE_SECURITY_PATH}?error=session`);
  }

  revalidateCoreSecurity();
  redirect(`${CORE_SECURITY_PATH}?status=sessions-revoked`);
}
