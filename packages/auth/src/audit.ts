import { createHash, createHmac, randomUUID } from "node:crypto";
import { Prisma, prisma } from "@virki/database";
import type { Prisma as PrismaTypes } from "@virki/database";

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
  | "SECOND_FACTOR_RECOVERED"
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

export interface AuditMetadata {
  [key: string]: AuditMetadataValue;
}
export type AuditMetadataValue = string | number | boolean | null | AuditMetadata | AuditMetadataValue[];

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
const MAX_METADATA_INSPECTION_LENGTH = MAX_METADATA_STRING_LENGTH * 10;
const MAX_METADATA_DEPTH = 4;
const MAX_METADATA_NODES = 64;
const MAX_METADATA_ARRAY_ITEMS = 12;
const REDACTED_METADATA_VALUE = "[REDACTED]";
const SENSITIVE_METADATA_KEY = /(?:token|code|password|passwd|passphrase|secret|privatekey|credential|authorization|authheader|cookie|session|assertion|verifier|nonce|otp|totp|apikey|clientkey|url|uri)/u;
const URL_VALUE = /(?:\b(?:https?|ftp):\/\/|(?:^|\s)www\.)/iu;
const ENCODED_URL_VALUE = /\b(?:https?|ftp)(?:%3a|:)(?:%2f|\/){2}/iu;
const PROTOCOL_RELATIVE_URL = /(?:^|[\s"'(])\/\/[^\s/]+/u;
const CREDENTIAL_ASSIGNMENT = /(?:^|[^A-Za-z0-9])(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|authorization|auth[_-]?code|code|password|passwd|passphrase|client[_-]?secret|secret|private[_-]?key|api[_-]?key|credential|cookie|session(?:[_-]?(?:id|key|token))?|state|nonce|verifier|recovery[_-]?code|otp|totp)\s*[:=]\s*[^\s,;&]+/iu;
const PRIVATE_KEY_MATERIAL = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/iu;
const JWT_VALUE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u;
const AUTHORIZATION_VALUE = /\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_=-]{8,}/iu;
const OPAQUE_CREDENTIAL_VALUE = /^[A-Za-z0-9+/_=-]{32,}$/u;
const DEFAULT_AUDIT_LOG_RETENTION_DAYS = 180;
const MIN_AUDIT_LOG_RETENTION_DAYS = 1;
const MAX_AUDIT_LOG_RETENTION_DAYS = 3650;

export async function writeAuditLog(input: AuditLogInput): Promise<void> {
  try {
    await writeAuditLogRequired(input);
  } catch {
    console.warn("Audit log write failed.");
  }
}

export async function writeAuditLogRequired(input: AuditLogInput): Promise<void> {
  await prisma.auditLog.create({ data: createAuditLogData(input) });
}

export async function writeAuditLogForMaintenanceRequired(
  input: AuditLogInput,
  execute: (query: ReturnType<typeof Prisma.sql>) => Promise<number> = (query) => prisma.$executeRaw(query)
): Promise<void> {
  const data = createAuditLogData(input);
  await execute(Prisma.sql`
    INSERT INTO "AuditLog" ("id", "eventType", "actorUserId", "actorEmailHash", "result", "resource", "message", "metadata", "createdAt")
    VALUES (${randomUUID()}, ${data.eventType}, ${data.actorUserId ?? null}, ${data.actorEmailHash ?? null}, ${data.result}, ${data.resource ?? null}, ${data.message ?? null}, ${JSON.stringify(data.metadata ?? null)}::jsonb, CURRENT_TIMESTAMP)
  `);
}

export async function writeAuditLogInTransaction(
  transaction: PrismaTypes.TransactionClient,
  input: AuditLogInput
): Promise<void> {
  await transaction.auditLog.create({ data: createAuditLogData(input) });
}

function createAuditLogData(input: AuditLogInput) {
  return {
    eventType: input.eventType,
    result: input.result,
    actorUserId: input.actorUserId,
    actorEmailHash: input.actorEmailHash,
    resource: input.resource,
    message: truncate(input.message, MAX_MESSAGE_LENGTH),
    metadata: sanitizeAuditMetadata(input.metadata)
  };
}

export function hashAuditEmail(email: string, env: NodeJS.ProcessEnv = process.env): string {
  const key = getAuditHashKey(env);
  if (!key) throw new Error("Audit pseudonymization key is unavailable.");
  const keyId = createHash("sha256").update("virki-audit-key-id\0").update(key).digest("hex").slice(0, 16);
  const digest = createHmac("sha256", key).update("virki-audit-email-v1\0").update(email.trim().toLowerCase(), "utf8").digest("hex");
  return `hmac-v1:${keyId}:${digest}`;
}

export function formatAuditEmailReference(value: string): string {
  const versioned = /^hmac-v1:[a-f0-9]{16}:([a-f0-9]{64})$/u.exec(value);
  const legacy = /^[a-f0-9]{64}$/u.test(value) ? value : undefined;
  return (versioned?.[1] ?? legacy ?? "unknown").slice(0, 10);
}

function getAuditHashKey(env: NodeJS.ProcessEnv): Buffer | null {
  const value = env.VIRKI_AUDIT_HASH_SECRET;
  if (value === undefined && env.NODE_ENV !== "production") {
    return createHash("sha256").update("virki synthetic non-production audit key", "utf8").digest();
  }
  if (!value || !/^[a-f0-9]{64}$/iu.test(value)) return null;
  return Buffer.from(value, "hex");
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

export function sanitizeAuditMetadata(metadata?: AuditMetadata): AuditMetadata | undefined {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return undefined;
  }

  return sanitizeMetadataObject(metadata, 0, {
    remainingNodes: MAX_METADATA_NODES,
    ancestors: new WeakSet<object>()
  });
}

type MetadataSanitizationState = {
  remainingNodes: number;
  ancestors: WeakSet<object>;
};

function sanitizeMetadataObject(
  value: Record<string, unknown>,
  depth: number,
  state: MetadataSanitizationState
): AuditMetadata | undefined {
  if (depth > MAX_METADATA_DEPTH || state.ancestors.has(value)) {
    return undefined;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return undefined;
  }

  state.ancestors.add(value);
  const sanitized: AuditMetadata = {};

  let keysVisited = 0;
  for (const rawKey in value) {
    if (!Object.prototype.hasOwnProperty.call(value, rawKey)) {
      continue;
    }

    if (keysVisited >= MAX_METADATA_KEYS) {
      break;
    }
    keysVisited += 1;

    if (state.remainingNodes <= 0) {
      break;
    }

    state.remainingNodes -= 1;
    const key = sanitizeMetadataKey(rawKey);
    if (!key) {
      continue;
    }

    if (isSensitiveMetadataKey(key)) {
      sanitized[key] = REDACTED_METADATA_VALUE;
      continue;
    }

    const entry = value[rawKey];
    const safeValue = sanitizeMetadataValue(entry, depth + 1, key, state);
    if (safeValue !== undefined) {
      sanitized[key] = safeValue;
    }
  }

  state.ancestors.delete(value);
  return sanitized;
}

function sanitizeMetadataValue(
  value: unknown,
  depth: number,
  key: string,
  state: MetadataSanitizationState
): AuditMetadataValue | undefined {
  if (typeof value === "string") {
    return sanitizeMetadataString(value, key);
  }

  if (typeof value === "boolean" || value === null) {
    return value;
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }

  if (typeof value !== "object" || depth > MAX_METADATA_DEPTH || state.ancestors.has(value)) {
    return undefined;
  }

  if (Array.isArray(value)) {
    state.ancestors.add(value);
    const sanitized: AuditMetadataValue[] = [];
    for (const entry of value.slice(0, MAX_METADATA_ARRAY_ITEMS)) {
      if (state.remainingNodes <= 0) {
        break;
      }

      state.remainingNodes -= 1;
      const safeEntry = sanitizeMetadataValue(entry, depth + 1, key, state);
      if (safeEntry !== undefined) {
        sanitized.push(safeEntry);
      }
    }
    state.ancestors.delete(value);
    return sanitized;
  }

  return sanitizeMetadataObject(value as Record<string, unknown>, depth, state);
}

function sanitizeMetadataKey(key: string): string | undefined {
  if (key.length > MAX_METADATA_STRING_LENGTH || hasAuditControlCharacters(key)) {
    return undefined;
  }

  if (!/^[A-Za-z][A-Za-z0-9_.-]*$/u.test(key) || key === "constructor" || key === "prototype" || key === "__proto__") {
    return undefined;
  }

  return key;
}

function isSensitiveMetadataKey(key: string): boolean {
  const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
  return SENSITIVE_METADATA_KEY.test(normalizedKey);
}

function sanitizeMetadataString(value: string, key: string): string {
  const inspectionValue = replaceAuditControlCharacters(value.slice(0, MAX_METADATA_INSPECTION_LENGTH), "");

  if (hasSensitiveMetadataValue(inspectionValue, key)) {
    return REDACTED_METADATA_VALUE;
  }

  return replaceAuditControlCharacters(value.slice(0, MAX_METADATA_STRING_LENGTH), " ");
}

function hasAuditControlCharacters(value: string): boolean {
  return Array.from(value).some(isAuditControlCharacter);
}

function replaceAuditControlCharacters(value: string, replacement: string): string {
  let sanitized = "";
  for (const character of value) {
    sanitized += isAuditControlCharacter(character) ? replacement : character;
  }
  return sanitized;
}

function isAuditControlCharacter(character: string): boolean {
  const code = character.codePointAt(0) ?? 0;
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f) ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2060 && code <= 0x206f) || code === 0xfeff;
}

function hasSensitiveMetadataValue(value: string, key: string): boolean {
  const candidate = value.trim();
  if (
    URL_VALUE.test(candidate) ||
    ENCODED_URL_VALUE.test(candidate) ||
    PROTOCOL_RELATIVE_URL.test(candidate) ||
    CREDENTIAL_ASSIGNMENT.test(candidate) ||
    PRIVATE_KEY_MATERIAL.test(candidate) ||
    JWT_VALUE.test(candidate) ||
    AUTHORIZATION_VALUE.test(candidate)
  ) {
    return true;
  }

  if (!OPAQUE_CREDENTIAL_VALUE.test(candidate)) {
    return false;
  }

  return !isAuditDigestReference(key, candidate);
}

function isAuditDigestReference(key: string, value: string): boolean {
  return /(?:refs?|hash)$/iu.test(key) && /^[a-f0-9]{64}$/iu.test(value);
}

function truncate(value: string | undefined, maxLength: number): string | undefined {
  if (!value) {
    return value;
  }

  return value.length > maxLength ? value.slice(0, maxLength) : value;
}
