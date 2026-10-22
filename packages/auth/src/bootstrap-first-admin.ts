import { PrismaClient, prisma } from "@virki/database";
import type { Prisma as PrismaTypes } from "@virki/database";
import { hashAuditEmail, writeAuditLogInTransaction } from "./audit";
import { hashPassword, normalizeEmail } from "./index";

async function countApplicationRows(transaction: PrismaTypes.TransactionClient): Promise<number[]> {
  return Promise.all([
    transaction.user.count(),
    transaction.session.count(),
    transaction.loginRateLimit.count(),
    transaction.projectConnection.count(),
    transaction.userProjectGrant.count(),
    transaction.oidcArtifact.count(),
    transaction.auditLog.count(),
    transaction.emailOutboxMessage.count(),
    transaction.emailDeliveryAttempt.count(),
    transaction.totpFactor.count(),
    transaction.recoveryCode.count(),
    transaction.deviceChallenge.count(),
    transaction.trustedDevice.count(),
    transaction.accountRecoveryRequest.count(),
    transaction.sanitizedAuditReference.count(),
    transaction.administrativeCredential.count(),
    transaction.administrativeRecoveryCode.count(),
    transaction.securityElevation.count()
  ]);
}

const BOOTSTRAP_LOCK_ID = 4_852_716_032_158_417_203n;
const AUDIT_LOG_COUNT_INDEX = 6;
const RATE_LIMIT_COUNT_INDEX = 2;
const BOOTSTRAP_AUDIT_PAGE_SIZE = 128;
const AUDIT_EMAIL_HASH_PATTERN = /^(?:[a-f0-9]{64}|hmac-v1:[a-f0-9]{16}:[a-f0-9]{64})$/u;
const AUDIT_REQUEST_ID_PATTERN = /^[a-f0-9-]{36}$/u;
const SAFE_LOGIN_AUDIT_METADATA_KEYS = new Set(["source", "cloudflareAccessPresent", "userAgentHash", "requestId", "route", "method"]);
const PREBOOTSTRAP_LOGIN_CSRF_SOURCES = new Set([
  "login-origin", "login-csrf", "login-verification-origin", "login-verification-csrf"
]);

function isSafeAnonymousEmailHash(value: string | null): boolean {
  return value === null || AUDIT_EMAIL_HASH_PATTERN.test(value);
}

function isSafePrebootstrapLoginMetadata(metadata: PrismaTypes.JsonValue, allowedSources: ReadonlySet<string>): boolean {
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) return false;
  const fields = Object.keys(metadata);
  if (fields.some((field) => !SAFE_LOGIN_AUDIT_METADATA_KEYS.has(field))) return false;
  if (typeof metadata.source !== "string" || !allowedSources.has(metadata.source) ||
      typeof metadata.cloudflareAccessPresent !== "boolean" ||
      !(metadata.userAgentHash === null || (typeof metadata.userAgentHash === "string" && /^[a-f0-9]{64}$/u.test(metadata.userAgentHash)))) return false;

  const hasRoute = Object.hasOwn(metadata, "route");
  const hasMethod = Object.hasOwn(metadata, "method");
  if (hasRoute !== hasMethod) return false;
  if (Object.hasOwn(metadata, "requestId") && (typeof metadata.requestId !== "string" || !AUDIT_REQUEST_ID_PATTERN.test(metadata.requestId))) return false;
  if (hasRoute) {
    const expectsVerification = metadata.source.includes("verification");
    if (metadata.route !== (expectsVerification ? "/api/login/verify" : "/api/login") || metadata.method !== "POST") return false;
  }
  return true;
}

function isHarmlessPrebootstrapAccessDenial(record: {
  eventType: string;
  result: string;
  reason: string | null;
  resource: string | null;
  message: string | null;
  actorEmailHash: string | null;
  metadata: PrismaTypes.JsonValue;
}): boolean {
  if ((record.eventType !== "ACCESS_JWT_MISSING" && record.eventType !== "ACCESS_JWT_INVALID") ||
      record.result !== "DENIED" || record.reason !== "cloudflare" || record.resource !== "hub" ||
      record.message !== null || record.actorEmailHash !== null) return false;
  if (record.metadata === null || typeof record.metadata !== "object" || Array.isArray(record.metadata)) return false;
  const metadata = record.metadata;
  const fields = Object.keys(metadata).sort();
  const expectedStatus = record.eventType === "ACCESS_JWT_MISSING" ? "missing" : "invalid";
  return fields.length === 3 && fields[0] === "accessJwtStatus" && fields[1] === "requestId" && fields[2] === "source" &&
    metadata.source === "hub-ingress" && metadata.accessJwtStatus === expectedStatus &&
    typeof metadata.requestId === "string" && AUDIT_REQUEST_ID_PATTERN.test(metadata.requestId);
}

function isHarmlessPrebootstrapRateLimit(record: {
  result: string;
  reason: string | null;
  resource: string | null;
  message: string | null;
  actorEmailHash: string | null;
  metadata: PrismaTypes.JsonValue;
}): boolean {
  if (record.result !== "DENIED" || (record.reason !== "rate-limited" && record.reason !== "unavailable") || record.message !== null) return false;
  if (record.resource === "sso.rate-limit") return record.actorEmailHash === null && record.metadata === null;
  if ((record.resource !== "hub" && record.resource !== "portal") || !isSafeAnonymousEmailHash(record.actorEmailHash)) return false;
  return isSafePrebootstrapLoginMetadata(record.metadata, new Set([`${record.resource}-login`]));
}

function isHarmlessPrebootstrapLoginCsrf(record: {
  result: string;
  reason: string | null;
  resource: string | null;
  message: string | null;
  actorEmailHash: string | null;
  metadata: PrismaTypes.JsonValue;
}): boolean {
  return record.result === "DENIED" && record.reason === "csrf" && record.resource === "identity.security" &&
    record.message === null && record.actorEmailHash === null &&
    isSafePrebootstrapLoginMetadata(record.metadata, PREBOOTSTRAP_LOGIN_CSRF_SOURCES);
}

function isHarmlessPrebootstrapCleanupAudit(record: {
  eventType: string;
  result: string;
  reason: string | null;
  resource: string | null;
  message: string | null;
  actorUserId: string | null;
  actorEmailHash: string | null;
  actorRole: string | null;
  sessionRef: string | null;
  metadata: PrismaTypes.JsonValue;
}): boolean {
  if (record.actorUserId !== null || record.actorRole !== null || record.sessionRef !== null) return false;
  if (record.eventType === "ACCESS_JWT_MISSING" || record.eventType === "ACCESS_JWT_INVALID") {
    return isHarmlessPrebootstrapAccessDenial(record);
  }
  if (record.eventType === "RATE_LIMIT_REACHED") return isHarmlessPrebootstrapRateLimit(record);
  if (record.eventType === "CSRF_DENIED") return isHarmlessPrebootstrapLoginCsrf(record);
  // Anonymous failures and request counters establish no account ownership. Keep their immutable history.
  if (record.eventType === "AUTH_LOGIN_FAILURE" && record.result === "FAILURE" &&
      ["hub", "portal"].includes(record.resource ?? "") &&
      isSafeAnonymousEmailHash(record.actorEmailHash) &&
      ["Login failed.", "Login rate limit reached.", "Login rate limit unavailable.", "Security verification failed."].includes(record.message ?? "")) return true;
  if (record.actorEmailHash === null && record.result === "FAILURE" && (
    (record.eventType === "SSO_AUTHORIZATION_DENIED" && record.resource === "sso.authorization" && record.message === "OIDC authorization request rejected.") ||
    (record.eventType === "SSO_TOKEN_REJECTED" && record.resource === "sso.token" && record.message === "OIDC token request rejected.")
  )) return true;
  if (record.eventType !== "AUTH_SESSION_CLEANUP" || record.result !== "SUCCESS" ||
      record.resource !== "session" || record.message !== "Inactive sessions cleaned up." ||
      record.actorUserId !== null || record.actorEmailHash !== null) return false;
  const metadata = record.metadata;
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) return false;
  const fields = Object.keys(metadata).sort();
  return fields.length === 3 &&
    fields[0] === "deletedCount" && fields[1] === "deletedRateLimitCount" && fields[2] === "source" &&
    metadata.source === "sessions-cleanup" && metadata.deletedCount === 0 &&
    typeof metadata.deletedRateLimitCount === "number" && Number.isSafeInteger(metadata.deletedRateLimitCount) && metadata.deletedRateLimitCount >= 0;
}

async function verifyBootstrapDatabaseIsVirgin(transaction: PrismaTypes.TransactionClient): Promise<void> {
  const counts = await countApplicationRows(transaction);
  if (counts.some((count, index) => index !== AUDIT_LOG_COUNT_INDEX && index !== RATE_LIMIT_COUNT_INDEX && count !== 0)) {
    throw new FirstAdminBootstrapError("DATABASE_NOT_VIRGIN");
  }
  const auditCount = counts[AUDIT_LOG_COUNT_INDEX] ?? 0;
  if (auditCount === 0) return;
  // No finite allowance: anonymous traffic must not exhaust first-admin bootstrap.
  // All identity-bearing tables remain empty, and successful identity history is rejected.
  let examined = 0;
  let cursor: string | undefined;
  while (examined < auditCount) {
    const audits = await transaction.auditLog.findMany({
      take: BOOTSTRAP_AUDIT_PAGE_SIZE,
      orderBy: { id: "asc" },
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      select: {
        id: true, eventType: true, result: true, resource: true, message: true,
        reason: true, actorUserId: true, actorEmailHash: true, actorRole: true, sessionRef: true, metadata: true
      }
    });
    if (audits.length === 0 || audits.some((audit) => !isHarmlessPrebootstrapCleanupAudit(audit))) {
      throw new FirstAdminBootstrapError("DATABASE_NOT_VIRGIN");
    }
    examined += audits.length;
    cursor = audits.at(-1)!.id;
  }
  if (examined !== auditCount) {
    throw new FirstAdminBootstrapError("DATABASE_NOT_VIRGIN");
  }
}

export class FirstAdminBootstrapError extends Error {
  constructor(readonly code: "INPUT_INVALID" | "DATABASE_NOT_VIRGIN" | "INTERACTIVE_TTY_REQUIRED" | "PRODUCTION_CONTEXT_REQUIRED" | "DATABASE_TARGET_INVALID" | "FIRST_INSTALL_NOT_ENABLED") {
    super(code);
    this.name = "FirstAdminBootstrapError";
  }
}

type BootstrapInput = {
  email: string;
  displayName?: string;
  password: string;
};

type BootstrapDependencies = {
  database?: Pick<PrismaClient, "$transaction">;
  hashPassword?: (password: string) => Promise<string>;
  hashAdminEmail?: (email: string) => string;
  writeAudit?: typeof writeAuditLogInTransaction;
  now?: Date;
};

export async function bootstrapFirstAdmin(input: BootstrapInput, dependencies: BootstrapDependencies = {}): Promise<{ id: string }> {
  const email = normalizeEmail(input.email);
  const displayName = input.displayName?.trim() || "";
  if (!/^\S+@\S+\.\S+$/u.test(email) || email.length > 320 || input.password.length < 16 || input.password.length > 256 || containsControlCharacter(input.password) || displayName.length > 80 || containsControlCharacter(displayName)) {
    throw new FirstAdminBootstrapError("INPUT_INVALID");
  }

  const database = dependencies.database ?? prisma;
  const hash = dependencies.hashPassword ?? hashPassword;
  const hashEmail = dependencies.hashAdminEmail ?? hashAuditEmail;
  const writeAudit = dependencies.writeAudit ?? writeAuditLogInTransaction;
  const now = dependencies.now ?? new Date();
  // Argon2 is intentionally expensive. Keep it outside the bounded Prisma
  // transaction so the advisory lock cannot time out during password hashing.
  const passwordHash = await hash(input.password);

  return database.$transaction(async (transaction) => {
    // Postgres advisory lock returns void; Prisma $queryRaw cannot deserialize
    // that type (P2010). Select a supported integer from the locking function.
    await transaction.$queryRaw`SELECT 1::integer AS acquired FROM pg_advisory_xact_lock(${BOOTSTRAP_LOCK_ID})`;
    await verifyBootstrapDatabaseIsVirgin(transaction);

    const user = await transaction.user.create({
      data: {
        email,
        emailNormalized: email,
        displayName: displayName || null,
        passwordHash,
        role: "ADMIN",
        isActive: true,
        accountStatus: "ACTIVE",
        emailVerifiedAt: null,
        secondFactorMethod: "EMAIL",
        createdAt: now
      },
      select: { id: true }
    });
    await writeAudit(transaction, {
      eventType: "ACCOUNT_CREATED",
      result: "SUCCESS",
      actorUserId: user.id,
      actorEmailHash: hashEmail(email),
      resource: "identity.admin",
      message: "Initial ADMIN account provisioned through restricted operator bootstrap."
    });
    return user;
  }, { isolationLevel: "Serializable" });
}

function containsControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint < 0x20 || codePoint === 0x7f;
  });
}

export function assertProductionBootstrapContext(env: NodeJS.ProcessEnv): void {
  if (env.VIRKI_FIRST_INSTALL_BOOTSTRAP !== "enabled") throw new FirstAdminBootstrapError("FIRST_INSTALL_NOT_ENABLED");
  if (env.NODE_ENV !== "production") throw new FirstAdminBootstrapError("PRODUCTION_CONTEXT_REQUIRED");
  try {
    const url = new URL(env.DATABASE_URL ?? "");
    if (url.protocol !== "postgresql:" || url.hostname !== "postgres" || (url.port !== "" && url.port !== "5432") || decodeURIComponent(url.username) !== "virki_runtime" || url.pathname !== "/virki" || (url.searchParams.has("schema") && url.searchParams.get("schema") !== "public")) {
      throw new Error("invalid database target");
    }
  } catch {
    throw new FirstAdminBootstrapError("DATABASE_TARGET_INVALID");
  }
  if (!/^[a-f0-9]{64}$/iu.test(env.VIRKI_AUDIT_HASH_SECRET ?? "")) {
    throw new FirstAdminBootstrapError("PRODUCTION_CONTEXT_REQUIRED");
  }
}

async function readTerminalLine(label: string, secret = false, maxLength = 320): Promise<string> {
  const input = process.stdin;
  if (!input.isTTY || typeof input.setRawMode !== "function" || !process.stdout.isTTY) {
    throw new FirstAdminBootstrapError("INTERACTIVE_TTY_REQUIRED");
  }

  process.stdout.write(label);
  input.setEncoding("utf8");
  input.setRawMode(true);
  input.resume();
  return new Promise((resolve, reject) => {
    let value = "";
    const finish = (error?: Error) => {
      input.off("data", onData);
      input.off("error", onError);
      input.setRawMode(false);
      input.pause();
      process.stdout.write("\n");
      if (error) reject(error);
      else resolve(value);
    };
    const onError = (error: Error) => finish(error);
    const onData = (chunk: string) => {
      for (const character of chunk) {
        if (character === "\u0003") {
          finish(new Error("cancelled"));
          return;
        }
        if (character === "\r" || character === "\n") {
          finish();
          return;
        }
        if (character === "\u007f" || character === "\b") {
          if (value.length > 0) {
            value = Array.from(value).slice(0, -1).join("");
            if (!secret) process.stdout.write("\b \b");
          }
          continue;
        }
        if (/^[\u0020-\u007e]$/u.test(character)) {
          value += character;
          if (!secret) process.stdout.write(character);
        } else if (!containsControlCharacter(character)) {
          value += character;
          if (!secret) process.stdout.write(character);
        }
        if (Array.from(value).length > maxLength) {
          finish(new Error("input too long"));
          return;
        }
      }
    };
    input.on("data", onData);
    input.once("error", onError);
  });
}

async function runInteractiveBootstrap(): Promise<void> {
  assertProductionBootstrapContext(process.env);
  const email = await readTerminalLine("Initial ADMIN email: ", false, 320);
  const displayName = await readTerminalLine("Display name (optional): ", false, 80);
  const password = await readTerminalLine("Initial ADMIN password (16+ characters): ", true, 256);
  const confirmation = await readTerminalLine("Confirm password: ", true, 256);
  if (password !== confirmation) {
    throw new FirstAdminBootstrapError("INPUT_INVALID");
  }
  await bootstrapFirstAdmin({ email, displayName, password });
  console.log("Initial ADMIN account created. Complete email verification during the first sign-in.");
}

if (process.argv[1] && process.argv[1].replaceAll("\\", "/").endsWith("/bootstrap-first-admin.ts")) {
  runInteractiveBootstrap()
  .catch((error) => {
      const message = error instanceof FirstAdminBootstrapError
        ? error.code === "DATABASE_NOT_VIRGIN"
          ? "First ADMIN bootstrap refused because application data already exists."
          : error.code === "INTERACTIVE_TTY_REQUIRED"
            ? "First ADMIN bootstrap requires an interactive protected terminal."
          : error.code === "FIRST_INSTALL_NOT_ENABLED"
            ? "First ADMIN bootstrap requires the explicit first-install operation."
            : error.code === "DATABASE_TARGET_INVALID"
              ? "First ADMIN bootstrap refused because the database target is not the isolated Virki database."
              : error.code === "PRODUCTION_CONTEXT_REQUIRED"
                ? "First ADMIN bootstrap requires the protected Virki production runtime."
                : "First ADMIN bootstrap input is invalid."
        : "First ADMIN bootstrap failed; no credential details are available in this output.";
      console.error(message);
      process.exitCode = 1;
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
