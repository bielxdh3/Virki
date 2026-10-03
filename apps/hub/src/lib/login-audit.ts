import type { AuditMetadata } from "@bielos/auth";

export type LoginSurface = "hub" | "portal" | "local";
export type LoginVerificationFactor = "email" | "totp" | "recovery";

export class RequiredLoginAuditError extends Error {
  constructor() {
    super("Required login audit persistence failed.");
    this.name = "RequiredLoginAuditError";
  }
}

export async function createLoginResponseAfterRequiredAudit<T>(
  writeAudit: () => Promise<void>,
  createResponse: () => T,
  createAuditFailureResponse?: () => T
): Promise<T> {
  try {
    await writeAudit();
  } catch {
    if (createAuditFailureResponse) return createAuditFailureResponse();
    throw new RequiredLoginAuditError();
  }

  return createResponse();
}

export function createVerifiedLoginAudit(
  actorUserId: string,
  surface: LoginSurface,
  factor: LoginVerificationFactor,
  requestMetadata: AuditMetadata
) {
  return {
    eventType: "AUTH_LOGIN_SUCCESS" as const,
    result: "SUCCESS" as const,
    actorUserId,
    resource: surface,
    message: "Security verification completed; login succeeded.",
    metadata: { ...requestMetadata, verificationFactor: factor }
  };
}
