import { createHash } from "node:crypto";
import { prisma } from "@bielos/database";

export type AuditEventType =
  | "AUTH_LOGIN_SUCCESS"
  | "AUTH_LOGIN_FAILURE"
  | "AUTH_LOGOUT"
  | "AUTH_SESSION_REVOKED"
  | "AUTH_SESSION_CLEANUP"
  | "AUTH_AUDIT_LOG_CLEANUP"
  | "ACCESS_JWT_MISSING"
  | "ACCESS_JWT_INVALID"
  | "ACCESS_JWT_VALID"
  | "OWNER_SEED_CREATED"
  | "OWNER_SEED_UPDATED"
  | "GYMFORGE_PARTICIPANT_CREATED"
  | "GYMFORGE_PARTICIPANT_STATUS_CHANGED"
  | "GYMFORGE_EXERCISE_CREATED"
  | "GYMFORGE_EXERCISE_STATUS_CHANGED"
  | "GYMFORGE_ATTENDANCE_CHECKIN_CREATED"
  | "GYMFORGE_WORKOUT_CREATED"
  | "GYMFORGE_COMPETITION_CREATED";

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
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown audit logging error";
    console.warn(`Audit log write failed: ${message}`);
  }
}

export function hashAuditEmail(email: string): string {
  return createHash("sha256").update(email.trim().toLowerCase(), "utf8").digest("hex");
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
