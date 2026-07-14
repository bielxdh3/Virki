"use server";

import { hashAuditIdentifier, writeAuditLog } from "@bielos/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
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

  const now = new Date();
  let result: { count: number };

  try {
    result = await prisma.session.updateMany({
      where: {
        id: targetSessionId,
        userId: session.user.id,
        revokedAt: null,
        expiresAt: { gt: now }
      },
      data: { revokedAt: now }
    });
  } catch {
    redirect(`${CORE_SECURITY_PATH}?error=session`);
  }

  if (result.count !== 1) {
    redirect(`${CORE_SECURITY_PATH}?error=session`);
  }

  await writeAuditLog({
    eventType: "AUTH_SESSION_REVOKED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "session",
    message: "Personal session revoked.",
    metadata: {
      scope: "single-other",
      sessionRef: hashAuditIdentifier(targetSessionId)
    }
  });

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

  const now = new Date();
  let result: { count: number };

  try {
    result = await prisma.session.updateMany({
      where: {
        userId: session.user.id,
        id: { not: session.id },
        revokedAt: null,
        expiresAt: { gt: now }
      },
      data: { revokedAt: now }
    });
  } catch {
    redirect(`${CORE_SECURITY_PATH}?error=session`);
  }

  await writeAuditLog({
    eventType: "AUTH_SESSION_REVOKED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "session",
    message: "Other personal sessions revoked.",
    metadata: {
      scope: "all-other",
      revokedCount: result.count
    }
  });

  revalidateCoreSecurity();
  redirect(`${CORE_SECURITY_PATH}?status=sessions-revoked`);
}
