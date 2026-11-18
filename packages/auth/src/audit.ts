import { createHash, createHmac } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { Prisma, prisma } from "@virki/database";
import type { Prisma as PrismaTypes } from "@virki/database";

export type AuditEventType =
  | "AUTHORIZATION_DENIED"
  | "CSRF_DENIED"
  | "RATE_LIMIT_REACHED"
  | "SECURITY_PROOF_REJECTED"
  | "SSO_INTERACTION_STARTED"
  | "SSO_INTERACTION_COMPLETED"
  | "SSO_INTERACTION_DENIED"
  | "AUTH_LOGIN_SUCCESS"
  | "AUTH_LOGIN_FAILURE"
  | "PASSKEY_REGISTERED"
  | "PASSKEY_AUTHENTICATED"
  | "PASSKEY_RENAMED"
  | "PASSKEY_REVOKED"
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
  | "SSO_USERINFO_REJECTED"
  | "SSO_REVOCATION_REJECTED"
  | "SSO_LOGOUT_COMPLETED"
  | "SSO_LOGOUT_REJECTED"
  | "SSO_PROVIDER_ERROR"
  | "SECOND_FACTOR_ENROLLMENT_STARTED"
  | "SECOND_FACTOR_ENROLLED"
  | "SECOND_FACTOR_DISABLED"
  | "SECOND_FACTOR_RECOVERED"
  | "RECOVERY_CODES_REGENERATED"
  | "RECOVERY_CODE_CONSUMED"
  | "DEVICE_VERIFIED"
  | "TRUSTED_DEVICE_REVOKED"
  | "ACCOUNT_RECOVERY_REQUESTED"
  | "ACCOUNT_RECOVERY_EMAIL_VERIFIED"
  | "ACCOUNT_RECOVERY_TOTP_VERIFIED"
  | "ACCOUNT_RECOVERY_PASSKEY_VERIFIED"
  | "ACCOUNT_RECOVERY_APPROVED"
  | "ACCOUNT_RECOVERY_CONSUMED"
  | "ACCOUNT_RECOVERY_EMAIL_REBIND_STARTED"
  | "ACCOUNT_RECOVERY_EMAIL_REBOUND"
  | "ADMIN_CREDENTIAL_SETUP"
  | "ADMIN_CREDENTIAL_CHANGED"
  | "ADMIN_CREDENTIAL_RECOVERED"
  | "ADMIN_CREDENTIAL_EMAIL_RECOVERY_STARTED"
  | "ADMIN_CREDENTIAL_EMAIL_RECOVERED"
  | "ADMIN_CREDENTIAL_TOTP_RECOVERED"
  | "ADMIN_ELEVATION_STARTED"
  | "ADMIN_ELEVATION_ACTIVATED"
  | "ADMIN_ELEVATION_REVOKED"
  | "ACCESS_JWT_MISSING"
  | "ACCESS_JWT_INVALID"
  | "ACCESS_JWT_VALID";

export type AuditResult = "SUCCESS" | "FAILURE" | "INFO" | "DENIED";

export type AuditContext = {
  requestId: string;
  service: "hub" | "issuer";
  route?: string;
  method?: string;
};
const auditContext = new AsyncLocalStorage<AuditContext>();
export function runWithAuditContext<T>(context: AuditContext, operation: () => T): T {
  return auditContext.run(context, operation);
}

export interface AuditMetadata {
  [key: string]: AuditMetadataValue;
}
export type AuditMetadataValue = string | number | boolean | null | AuditMetadata | AuditMetadataValue[];

export type AuditLogInput = {
  eventType: AuditEventType;
  result: AuditResult;
  actorUserId?: string;
  actorEmailHash?: string;
  actorRole?: "ADMIN" | "USER";
  sessionRef?: string;
  reason?: "completed" | "rejected" | "observed" | "rate-limited" | "unavailable" | "csrf" | "role" | "cloudflare";
  before?: { enabled?: boolean; accountStatus?: "ACTIVE" | "INACTIVE" | "BLOCKED" | "PENDING_ACTIVATION" };
  after?: { enabled?: boolean; accountStatus?: "ACTIVE" | "INACTIVE" | "BLOCKED" | "PENDING_ACTIVATION" };
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
const SENSITIVE_METADATA_KEY = /(?:token|code|password|passwd|passphrase|secret|privatekey|credential|authorization|authheader|cookie|session|assertion|verifier|nonce|otp|totp|apikey|clientkey)/u;
const URL_METADATA_KEY = /(?:url|uri)/u;
const URL_VALUE = /(?:\b(?:https?|ftp):\/\/|(?:^|\s)www\.)/iu;
const ENCODED_URL_VALUE = /\b(?:https?|ftp)(?:%3a|:)(?:%2f|\/){2}/iu;
const PROTOCOL_RELATIVE_URL = /(?:^|[\s"'(])\/\/[^\s/]+/u;
const CREDENTIAL_ASSIGNMENT = /(?:^|[^A-Za-z0-9])(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|authorization|auth[_-]?code|code|password|passwd|passphrase|client[_-]?secret|secret|private[_-]?key|api[_-]?key|credential|cookie|session(?:[_-]?(?:id|key|token))?|state|nonce|verifier|recovery[_-]?code|otp|totp)\s*[:=]\s*[^\s,;&]+/iu;
const PRIVATE_KEY_MATERIAL = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/iu;
const JWT_VALUE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u;
const AUTHORIZATION_VALUE = /\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_=-]{8,}/iu;
const EMAIL_VALUE = /[^\s@]+@[^\s@]+\.[^\s@]+/u;
const OPAQUE_CREDENTIAL_VALUE = /^[A-Za-z0-9+/_=-]{32,}$/u;
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

export async function writeAuditLogInTransaction(
  transaction: PrismaTypes.TransactionClient,
  input: AuditLogInput
): Promise<void> {
  await transaction.auditLog.create({ data: createAuditLogData(input) });
}

const PERSISTED_METADATA_KEYS = new Set([
  "source", "cloudflareAccessPresent", "userAgentHash", "requestId", "route", "method", "requestRef", "ceremonyRef", "deviceRef", "targetRef", "userRef", "connectionRef", "clientRef", "invitationRef", "emailRef", "verificationFactor", "rememberedBrowser", "enabled", "scope", "error", "revokedCount", "deletedCount", "deletedRateLimitCount", "retentionDays", "redirectUrisChanged", "launchUrlConfigured", "originChanged", "redirectUriCount", "accessJwtRequired", "accessJwtStatus", "accessJwtReason", "nameChanged", "slugChanged", "launchUrlChanged"
]);
export function safePersistedAuditMetadata(value: unknown): AuditMetadata | undefined {
  const sanitized = sanitizeAuditMetadata(value as AuditMetadata);
  if (!sanitized) return undefined;
  return Object.fromEntries(Object.entries(sanitized).filter(([key, entry]) => {
    const validEmailRef = key !== "emailRef" || (typeof entry === "string" && emailHashReference(entry) === entry);
    return validEmailRef && ((entry === REDACTED_METADATA_VALUE && isSensitiveMetadataKey(key, entry)) || (PERSISTED_METADATA_KEYS.has(key) && (entry === null || ["string", "boolean", "number"].includes(typeof entry))));
  }));
}
function digestReference(value: unknown): string | undefined {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value) ? value : undefined;
}
function emailHashReference(value: string | undefined): string | undefined {
  return value && /^(?:[a-f0-9]{64}|hmac-v1:[a-f0-9]{16}:[a-f0-9]{64})$/u.test(value) ? value : undefined;
}
function identifier(value: unknown, pattern = /^[a-zA-Z0-9_.-]{1,80}$/u): string | undefined {
  return typeof value === "string" && pattern.test(value) ? value : undefined;
}
export function safeAuditState(input: unknown): AuditLogInput["before"] {
  if (!input || typeof input !== "object" || Array.isArray(input)) return undefined;
  const value = input as AuditLogInput["before"] & object;
  return {
    ...(typeof value.enabled === "boolean" ? { enabled: value.enabled } : {}),
    ...(["ACTIVE", "INACTIVE", "BLOCKED", "PENDING_ACTIVATION"].includes(value.accountStatus ?? "") ? { accountStatus: value.accountStatus } : {})
  };
}
export function createAuditLogData(input: AuditLogInput) {
  const context = auditContext.getStore();
  const metadata = safePersistedAuditMetadata(input.metadata);
  const failed = input.result === "FAILURE" || input.result === "DENIED";
  return {
    eventType: input.eventType,
    result: input.result,
    actorUserId: input.actorUserId,
    actorEmailHash: emailHashReference(input.actorEmailHash),
    resource: identifier(input.resource),
    message: input.message ? sanitizeMetadataString(input.message, "message").slice(0, MAX_MESSAGE_LENGTH) : undefined,
    metadata,
    schemaVersion: 1,
    category: input.eventType.startsWith("AUTH_") ? "AUTH" : input.eventType.startsWith("SECOND_FACTOR_") || input.eventType.startsWith("RECOVERY_CODES_") || input.eventType === "RECOVERY_CODE_CONSUMED" || input.eventType.includes("DEVICE") ? "SECURITY" : input.eventType.split("_")[0],
    severity: failed ? "WARNING" : "INFO",
    action: input.eventType.toLowerCase().replaceAll("_", "."),
    reason: input.reason ?? (failed ? "rejected" : input.result === "INFO" ? "observed" : "completed"),
    actorRef: input.actorUserId ? hashAuditIdentifier(input.actorUserId) : emailHashReference(input.actorEmailHash) ? hashAuditIdentifier(input.actorEmailHash!) : undefined,
    actorRole: input.actorRole === "ADMIN" || input.actorRole === "USER" ? input.actorRole : undefined,
    targetRef: digestReference(metadata?.targetRef ?? metadata?.userRef ?? metadata?.connectionRef),
    sessionRef: digestReference(input.sessionRef),
    deviceRef: digestReference(metadata?.deviceRef),
    requestId: identifier(context?.requestId ?? metadata?.requestId, /^[a-f0-9-]{36}$/u),
    service: context?.service ?? (typeof metadata?.source === "string" && /^(hub|portal|admin|account)-/u.test(metadata.source) ? "hub" : undefined),
    route: identifier(context?.route ?? metadata?.route, /^\/[a-zA-Z0-9/_.:-]{0,100}$/u),
    method: identifier(context?.method ?? metadata?.method, /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/u),
    networkProvenance: "unavailable",
    beforeState: safeAuditState(input.before),
    afterState: safeAuditState(input.after)
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

export function hashAuditSessionReference(sessionId: string): string {
  return hashAuditIdentifier(sessionId);
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
  // The Next ingress proxy removes the caller's value and generates this header.
  const requestId = identifier(headers.get("x-virki-audit-request-id"), /^[a-f0-9-]{36}$/u);
  const route = identifier(headers.get("x-virki-audit-route"), /^\/[a-zA-Z0-9/_.:-]{0,100}$/u);
  const method = identifier(headers.get("x-virki-audit-method"), /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/u);

  return {
    source,
    cloudflareAccessPresent: Boolean(headers.get("cf-access-jwt-assertion")),
    userAgentHash: userAgentHash ?? null,
    ...(requestId ? { requestId } : {}),
    ...(route ? { route } : {}),
    ...(method ? { method } : {})
  };
}

export async function cleanupExpiredAuditLogs(
  now = new Date()
): Promise<{ deletedCount: number; retentionDays: number; cutoff: Date }> {
  const result = await prisma.$queryRaw<Array<{ deletedCount: bigint; retentionDays: number }>>(Prisma.sql`
    SELECT cleanup.deleted_count AS "deletedCount", cleanup.retention_days AS "retentionDays"
    FROM virki_security.delete_expired_audit_logs() AS cleanup
  `);
  const deletedCount = Number(result[0]?.deletedCount ?? 0n);
  const retentionDays = result[0]?.retentionDays;
  if (!Number.isSafeInteger(deletedCount) || deletedCount < 0 || typeof retentionDays !== "number" || !Number.isInteger(retentionDays) || retentionDays < MIN_AUDIT_LOG_RETENTION_DAYS || retentionDays > MAX_AUDIT_LOG_RETENTION_DAYS) {
    throw new Error("Audit cleanup returned an invalid database policy or deleted-row count.");
  }

  return {
    deletedCount,
    retentionDays,
    cutoff: new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000)
  };
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

    const entry = value[rawKey];
    if (isSensitiveMetadataKey(key, entry)) {
      sanitized[key] = REDACTED_METADATA_VALUE;
      continue;
    }

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

function isSensitiveMetadataKey(key: string, value: unknown): boolean {
  const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
  if (SENSITIVE_METADATA_KEY.test(normalizedKey)) {
    return true;
  }

  // URL/URI-named keys hold booleans or counts as often as URLs; those values cannot carry a URL.
  const cannotCarryUrl = typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value));
  return URL_METADATA_KEY.test(normalizedKey) && !cannotCarryUrl;
}

function sanitizeMetadataString(value: string, key: string): string {
  if (key === "emailRef") {
    return emailHashReference(value) === value ? value : REDACTED_METADATA_VALUE;
  }

  const inspectionValue = replaceAuditControlCharacters(value.slice(0, MAX_METADATA_INSPECTION_LENGTH), "");

  const canonicalValue = replaceAuditControlCharacters(value.slice(0, MAX_METADATA_INSPECTION_LENGTH), " ");

  if (hasSensitiveMetadataValue(inspectionValue, key) || hasSensitiveMetadataValue(canonicalValue, key)) {
    return REDACTED_METADATA_VALUE;
  }

  return canonicalValue.slice(0, MAX_METADATA_STRING_LENGTH);
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
    || EMAIL_VALUE.test(candidate)
  ) {
    return true;
  }

  if (!OPAQUE_CREDENTIAL_VALUE.test(candidate)) {
    return false;
  }

  return !isAuditDigestReference(key, candidate);
}

function isAuditDigestReference(key: string, value: string): boolean {
  if (key === "requestId" && /^[a-f0-9-]{36}$/u.test(value)) return true;
  return /(?:refs?|hash)$/iu.test(key) && /^[a-f0-9]{64}$/iu.test(value);
}
