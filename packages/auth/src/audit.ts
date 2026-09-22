import { createHash } from "node:crypto";
import { prisma } from "@bielos/database";

export type AuditEventType =
  | "AUTH_LOGIN_SUCCESS"
  | "AUTH_LOGIN_FAILURE"
  | "AUTH_LOGOUT"
  | "AUTH_SESSION_REVOKED"
  | "AUTH_SESSION_CLEANUP"
  | "AUTH_AUDIT_LOG_CLEANUP"
  | "AUDIT_LOG_EXPORTED"
  | "ACCOUNT_CREATED"
  | "ACCOUNT_STATE_CHANGED"
  | "PROJECT_ACCESS_GRANTED"
  | "PROJECT_ACCESS_REVOKED"
  | "PROJECT_CONNECTION_CREATED"
  | "PROJECT_CONNECTION_UPDATED"
  | "PROJECT_CONNECTION_REVOKED"
  | "SSO_AUTHORIZATION_ISSUED"
  | "SSO_AUTHORIZATION_DENIED"
  | "SSO_TOKEN_ISSUED"
  | "SSO_TOKEN_REJECTED"
  | "SECOND_FACTOR_ENROLLMENT_STARTED"
  | "SECOND_FACTOR_ENROLLED"
  | "SECOND_FACTOR_DISABLED"
  | "RECOVERY_CODES_REGENERATED"
  | "DEVICE_VERIFIED"
  | "TRUSTED_DEVICE_REVOKED"
  | "ACCOUNT_RECOVERY_REQUESTED"
  | "ACCOUNT_RECOVERY_EMAIL_VERIFIED"
  | "ACCOUNT_RECOVERY_APPROVED"
  | "ACCOUNT_RECOVERY_CONSUMED"
  | "ADMIN_CREDENTIAL_SETUP"
  | "ADMIN_CREDENTIAL_CHANGED"
  | "ADMIN_CREDENTIAL_RECOVERED"
  | "ADMIN_ELEVATION_STARTED"
  | "ADMIN_ELEVATION_ACTIVATED"
  | "ADMIN_ELEVATION_REVOKED"
  | "ACCESS_JWT_MISSING"
  | "ACCESS_JWT_INVALID"
  | "ACCESS_JWT_VALID";

export type AuditResult = "SUCCESS" | "FAILURE" | "INFO";

export type AuditMetadata = Record<string, string | number | boolean | null>;

export type AuditLogInput = {
  eventType: AuditEventType;
  result: AuditResult;
  actorUserId?: string;
  actorEmailHash?: string;
  resource?: string;
  message?: string;
  metadata?: AuditMetadata;
};

const MAX_MESSAGE_LENGTH = 160;
const MAX_METADATA_KEYS = 12;
const MAX_METADATA_STRING_LENGTH = 80;
const DEFAULT_AUDIT_LOG_RETENTION_DAYS = 180;
const MIN_AUDIT_LOG_RETENTION_DAYS = 1;
const MAX_AUDIT_LOG_RETENTION_DAYS = 3650;

export async function writeAuditLog(input: AuditLogInput): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        eventType: input.eventType,
        result: input.result,
        actorUserId: input.actorUserId,
        actorEmailHash: input.actorEmailHash,
        resource: input.resource,
        message: truncate(input.message, MAX_MESSAGE_LENGTH),
        metadata: sanitizeMetadata(input.metadata)
      }
    });
  } catch {
    console.warn("Audit log write failed.");
  }
}

export function hashAuditEmail(email: string): string {
  return createHash("sha256").update(email.trim().toLowerCase(), "utf8").digest("hex");
}

export function hashAuditIdentifier(identifier: string): string {
  return createHash("sha256").update(identifier, "utf8").digest("hex");
}

export function hashAuditUserAgent(userAgent: string | null): string | undefined {
  if (!userAgent) {
    return undefined;
  }

  return createHash("sha256").update(userAgent.slice(0, 500), "utf8").digest("hex");
}

export function createAuditRequestMetadata(
  headers: Pick<Headers, "get">,
  source: string
): AuditMetadata {
  const userAgentHash = hashAuditUserAgent(headers.get("user-agent"));

  return {
    source,
    cloudflareAccessPresent: Boolean(headers.get("cf-access-jwt-assertion")),
    userAgentHash: userAgentHash ?? null
  };
}

export async function cleanupExpiredAuditLogs(
  now = new Date(),
  env: NodeJS.ProcessEnv = process.env
): Promise<{ deletedCount: number; retentionDays: number; cutoff: Date }> {
  const retentionDays = getAuditLogRetentionDays(env);
  const cutoff = new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000);
  const result = await prisma.auditLog.deleteMany({
    where: {
      createdAt: { lt: cutoff }
    }
  });

  return {
    deletedCount: result.count,
    retentionDays,
    cutoff
  };
}

export function getAuditLogRetentionDays(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.AUDIT_LOG_RETENTION_DAYS ?? DEFAULT_AUDIT_LOG_RETENTION_DAYS);

  if (!Number.isFinite(raw)) {
    return DEFAULT_AUDIT_LOG_RETENTION_DAYS;
  }

  return Math.min(
    Math.max(Math.floor(raw), MIN_AUDIT_LOG_RETENTION_DAYS),
    MAX_AUDIT_LOG_RETENTION_DAYS
  );
}

function sanitizeMetadata(metadata?: AuditMetadata): AuditMetadata | undefined {
  if (!metadata) {
    return undefined;
  }

  return Object.fromEntries(
    Object.entries(metadata)
      .slice(0, MAX_METADATA_KEYS)
      .map(([key, value]) => [key, sanitizeMetadataValue(value)])
  );
}

function sanitizeMetadataValue(value: string | number | boolean | null): string | number | boolean | null {
  if (typeof value !== "string") {
    return value;
  }

  return truncate(value, MAX_METADATA_STRING_LENGTH) ?? "";
}

function truncate(value: string | undefined, maxLength: number): string | undefined {
  if (!value) {
    return value;
  }

  return value.length > maxLength ? value.slice(0, maxLength) : value;
}
