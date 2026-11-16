import { validateCloudflareAccessJwt, type CloudflareAccessJwtResult } from "@virki/auth/cloudflare-access";
import { isNativeHubPerimeterEnabled } from "./hub-perimeter";
import {
  createAuditRequestMetadata,
  writeAuditLog,
  type AuditEventType,
  type AuditMetadata,
  type AuditResult
} from "@virki/auth";

export async function validateHubCloudflareAccess(
  headers: Pick<Headers, "get">,
  source: string
): Promise<CloudflareAccessJwtResult> {
  // Native ADMIN login/recovery is deliberately independent of the original
  // mailbox and the external Access session. Never skip the existing Virki
  // session/role/elevation and anti-CSRF checks performed by every caller.
  if (isNativeHubPerimeterEnabled()) {
    return { allowed: true, required: false, status: "disabled" };
  }
  const result = await validateCloudflareAccessJwt(headers);

  if (!result.required || result.allowed) {
    return result;
  }

  await writeAuditLog({
    eventType: getAccessAuditEventType(result.status),
    result: getAccessAuditResult(result.allowed),
    resource: "hub",
    message: getAccessAuditMessage(result.status),
    metadata: getAccessAuditMetadata(headers, source, result)
  });

  return result;
}

export function isCloudflareAccessAllowed(result: CloudflareAccessJwtResult): boolean {
  return result.allowed;
}

function getAccessAuditEventType(status: CloudflareAccessJwtResult["status"]): AuditEventType {
  if (status === "valid") {
    return "ACCESS_JWT_VALID";
  }

  if (status === "missing") {
    return "ACCESS_JWT_MISSING";
  }

  return "ACCESS_JWT_INVALID";
}

function getAccessAuditResult(allowed: boolean): AuditResult {
  return allowed ? "SUCCESS" : "FAILURE";
}

function getAccessAuditMessage(status: CloudflareAccessJwtResult["status"]): string {
  if (status === "valid") {
    return "Cloudflare Access JWT validated.";
  }

  if (status === "missing") {
    return "Cloudflare Access JWT missing.";
  }

  return "Cloudflare Access JWT rejected.";
}

function getAccessAuditMetadata(
  headers: Pick<Headers, "get">,
  source: string,
  result: CloudflareAccessJwtResult
): AuditMetadata {
  return {
    ...createAuditRequestMetadata(headers, source),
    accessJwtRequired: result.required,
    accessJwtStatus: result.status,
    accessJwtReason: result.reason ?? null
  };
}
