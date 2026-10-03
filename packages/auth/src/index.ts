import { createHash, randomBytes } from "node:crypto";
import { hash, verify } from "@node-rs/argon2";
import { prisma, type Prisma } from "@bielos/database";
import { SESSION_COOKIE_NAME, SESSION_TTL_SECONDS } from "./constants";
import { createLoginAccountRateLimitIdentifierHash, createLoginAttemptRateLimitIdentifierHash, createLoginRateLimitIdentifierHash, createRateLimitIdentifierHash, getLoginRateLimitRefundState, isTrustedClientAddress, scopeLoginRateLimitEmail } from "./rate-limit-config";

export { SESSION_COOKIE_NAME, SESSION_TTL_SECONDS };
export { isTrustedClientAddress } from "./rate-limit-config";
export {
  createAuditRequestMetadata,
  hashAuditEmail,
  hashAuditIdentifier,
  hashAuditUserAgent,
  writeAuditLog,
  writeAuditLogRequired,
  writeAuditLogInTransaction,
  type AuditEventType,
  type AuditLogInput,
  type AuditMetadata,
  type AuditResult
} from "./audit";
export * from "./email";

const SESSION_TOKEN_BYTES = 32;
const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,t=3,p=1$KWdtXzW0AylnuGwdi+AYHQ$/T76IyJJw69emqMKm2cc7E1k2lQFMBFp/qTumxvHvHw";
const LOGIN_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 5;
const LOGIN_ACCOUNT_RATE_LIMIT_MAX_ATTEMPTS = 20;
const LOGIN_RATE_LIMIT_RETENTION_MS = 24 * 60 * 60 * 1000;
const LOGIN_RATE_LIMIT_LOCK_TIMEOUT_MS = 5_000;
const LOGIN_SOURCE_RATE_LIMIT_MAX_ATTEMPTS = 30;

export type AuthenticatedUser = {
  id: string;
  email: string;
  displayName: string | null;
  role: string;
};

export type AuthenticatedSession = {
  id: string;
  createdAt: Date;
  expiresAt: Date;
  authenticationMethods: string[];
  user: AuthenticatedUser;
};

export type CreatedSession = {
  token: string;
  expiresAt: Date;
};

export type SessionCookieOptions = {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: "/";
  expires: Date;
};

export type ExpiredSessionCookieOptions = {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: "/";
  expires: Date;
  maxAge: 0;
};

export type LoginRateLimitResult = {
  allowed: boolean;
  retryAfterSeconds?: number;
  failureMode?: "limiter-unavailable";
};

export type RateLimitAttemptResult =
  | { allowed: false }
  | { allowed: true; windowStartedAt: Date };

export type LoginRole = "ADMIN" | "USER";

export type LoginAuthenticationResult =
  | { user: AuthenticatedUser; failureMode?: never }
  | {
      user: null;
      failureMode: "invalid-credentials" | "rate-limited" | "limiter-unavailable";
    };

type AuthenticationUserRecord = {
  id: string;
  email: string;
  displayName: string | null;
  passwordHash: string | null;
  role: string;
  isActive: boolean;
  accountStatus: string;
};

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function checkLoginRateLimit(
  identifier: string,
  now = new Date()
): Promise<LoginRateLimitResult> {
  try {
    await pruneExpiredLoginRateLimits(now);
    const entry = await prisma.loginRateLimit.findUnique({
      where: { identifierHash: hashLoginRateLimitIdentifier(identifier) },
      select: {
        attempts: true,
        windowStartedAt: true,
        blockedUntil: true
      }
    });

    if (!entry) {
      return { allowed: true };
    }

    if (entry.blockedUntil && entry.blockedUntil > now) {
      return {
        allowed: false,
        retryAfterSeconds: Math.ceil((entry.blockedUntil.getTime() - now.getTime()) / 1000)
      };
    }

    if (isRateLimitWindowExpired(entry.windowStartedAt, now)) {
      return { allowed: true };
    }

    if (entry.attempts >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS) {
      const resetAt = getRateLimitWindowResetAt(entry.windowStartedAt);
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((resetAt.getTime() - now.getTime()) / 1000))
      };
    }

    return { allowed: true };
  } catch {
    return { allowed: false, failureMode: "limiter-unavailable" };
  }
}

export async function recordFailedLogin(identifier: string, now = new Date()): Promise<void> {
  const identifierHash = hashLoginRateLimitIdentifier(identifier);
  await prisma.$transaction(async (transaction) => {
    await lockLoginRateLimitIdentifier(transaction, identifierHash);
    await recordFailedLoginEntry(transaction, identifierHash, now);
  });
}

export async function lockRateLimitIdentifierInTransaction(
  transaction: Prisma.TransactionClient,
  identifier: string
): Promise<void> {
  await lockLoginRateLimitIdentifier(transaction, hashRateLimitIdentifier(identifier));
}

export async function consumeRateLimitAttemptInTransaction(
  transaction: Prisma.TransactionClient,
  identifier: string,
  now = new Date(),
  maxAttempts = LOGIN_RATE_LIMIT_MAX_ATTEMPTS
): Promise<RateLimitAttemptResult> {
  const identifierHash = hashRateLimitIdentifier(identifier);
  await lockLoginRateLimitIdentifier(transaction, identifierHash);

  const existing = await transaction.loginRateLimit.findUnique({
    where: { identifierHash },
    select: {
      attempts: true,
      windowStartedAt: true,
      blockedUntil: true
    }
  });
  const expiresAt = new Date(now.getTime() + LOGIN_RATE_LIMIT_RETENTION_MS);

  if (!existing || isRateLimitWindowExpired(existing.windowStartedAt, now)) {
    if (!existing) {
      await transaction.loginRateLimit.create({
        data: {
          identifierHash,
          attempts: 1,
          windowStartedAt: now,
          blockedUntil: null,
          expiresAt
        }
      });
    } else {
      await transaction.loginRateLimit.update({
        where: { identifierHash },
        data: {
          attempts: 1,
          windowStartedAt: now,
          blockedUntil: null,
          expiresAt
        }
      });
    }
    return { allowed: true, windowStartedAt: now };
  }

  if (isLoginRateLimitBlocked(existing, now, maxAttempts)) {
    return { allowed: false };
  }

  const attempts = Math.min(existing.attempts + 1, maxAttempts);
  await transaction.loginRateLimit.update({
    where: { identifierHash },
    data: {
      attempts,
      blockedUntil:
        attempts >= maxAttempts
          ? getRateLimitWindowResetAt(existing.windowStartedAt)
          : null,
      expiresAt
    }
  });
  return { allowed: true, windowStartedAt: existing.windowStartedAt };
}

async function refundRateLimitAttemptInTransaction(
  transaction: Prisma.TransactionClient,
  identifier: string,
  reservationWindowStartedAt: Date,
  maxAttempts: number
): Promise<void> {
  const identifierHash = hashRateLimitIdentifier(identifier);
  await lockLoginRateLimitIdentifier(transaction, identifierHash);

  const existing = await transaction.loginRateLimit.findUnique({
    where: { identifierHash },
    select: {
      attempts: true,
      windowStartedAt: true,
      blockedUntil: true
    }
  });
  if (!existing) return;

  const refund = getLoginRateLimitRefundState(existing, reservationWindowStartedAt, maxAttempts);
  if (!refund) return;

  await transaction.loginRateLimit.update({
    where: { identifierHash },
    data: refund
  });
}

export async function clearLoginRateLimit(identifier: string): Promise<void> {
  const identifierHash = hashLoginRateLimitIdentifier(identifier);
  await prisma.$transaction(async (transaction) => {
    await lockLoginRateLimitIdentifier(transaction, identifierHash);
    await transaction.loginRateLimit.deleteMany({ where: { identifierHash } });
  });
}

export async function cleanupExpiredLoginRateLimits(now = new Date()): Promise<number> {
  return pruneExpiredLoginRateLimits(now);
}

export async function hashPassword(password: string): Promise<string> {
  return hash(password, {
    algorithm: 2,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
    outputLen: 32
  });
}

export async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}

export function generateSessionToken(): string {
  return randomBytes(SESSION_TOKEN_BYTES).toString("base64url");
}

export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function getSessionExpiresAt(now = new Date()): Date {
  return new Date(now.getTime() + SESSION_TTL_SECONDS * 1000);
}

export function getSessionCookieOptions(expiresAt: Date): SessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt
  };
}

export function getExpiredSessionCookieOptions(): ExpiredSessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: new Date(0),
    maxAge: 0
  };
}

export async function authenticateUser(
  email: string,
  password: string
): Promise<AuthenticatedUser | null> {
  return authenticateUserFromLookup(
    () => findAuthenticationUser(prisma, email),
    password
  );
}

export async function authenticateUserWithRateLimit(
  email: string,
  password: string,
  now = new Date(),
  trustedClientAddress?: string,
  requiredRole?: LoginRole
): Promise<LoginAuthenticationResult> {
  let sourceIdentifier: string | null = null;
  let sourceReservation: Extract<RateLimitAttemptResult, { allowed: true }> | null = null;
  let authenticationTransactionStarted = false;
  try {
    if (process.env.NODE_ENV === "production" && !isTrustedClientAddress(trustedClientAddress)) {
      return { user: null, failureMode: "limiter-unavailable" };
    }
    if (trustedClientAddress) {
      if (!isTrustedClientAddress(trustedClientAddress)) return { user: null, failureMode: "limiter-unavailable" };
      const loginSourceIdentifier = `login-source-failure:v3:${requiredRole ?? "unscoped"}:${trustedClientAddress}`;
      sourceIdentifier = loginSourceIdentifier;
      const sourceAttempt = await prisma.$transaction((transaction) =>
        consumeRateLimitAttemptInTransaction(
          transaction,
          loginSourceIdentifier,
          now,
          LOGIN_SOURCE_RATE_LIMIT_MAX_ATTEMPTS
        )
      );
      if (!sourceAttempt.allowed) return { user: null, failureMode: "rate-limited" };
      sourceReservation = sourceAttempt;
    }
    const rateLimitEmail = scopeLoginRateLimitEmail(email, requiredRole);
    const accountIdentifierHash = createLoginAccountRateLimitIdentifierHash(rateLimitEmail);
    const identifierHash = createLoginAttemptRateLimitIdentifierHash(rateLimitEmail, trustedClientAddress);
    await pruneExpiredLoginRateLimits(now);

    const activeSourceReservation = sourceReservation;
    const activeSourceIdentifier = sourceIdentifier;
    authenticationTransactionStarted = true;
    const result = await prisma.$transaction<LoginAuthenticationResult>(
      async (transaction): Promise<LoginAuthenticationResult> => {
        await lockLoginRateLimitIdentifier(transaction, accountIdentifierHash);
        await lockLoginRateLimitIdentifier(transaction, identifierHash);
        const accountEntry = await transaction.loginRateLimit.findUnique({
          where: { identifierHash: accountIdentifierHash },
          select: {
            attempts: true,
            windowStartedAt: true,
            blockedUntil: true
          }
        });

        if (accountEntry && isLoginRateLimitBlocked(accountEntry, now, LOGIN_ACCOUNT_RATE_LIMIT_MAX_ATTEMPTS)) {
          return { user: null, failureMode: "rate-limited" };
        }

        const entry = await transaction.loginRateLimit.findUnique({
          where: { identifierHash },
          select: {
            attempts: true,
            windowStartedAt: true,
            blockedUntil: true
          }
        });

        if (entry && isLoginRateLimitBlocked(entry, now)) {
          return { user: null, failureMode: "rate-limited" };
        }

        const user = await authenticateUserFromLookup(
          () => findAuthenticationUser(transaction, email),
          password,
          requiredRole
        );

        if (!user) {
          await recordFailedLoginEntry(transaction, identifierHash, now);
          await recordFailedLoginEntry(transaction, accountIdentifierHash, now, LOGIN_ACCOUNT_RATE_LIMIT_MAX_ATTEMPTS);
          return { user: null, failureMode: "invalid-credentials" };
        }

        if (activeSourceIdentifier && activeSourceReservation) {
          await refundRateLimitAttemptInTransaction(
            transaction,
            activeSourceIdentifier,
            activeSourceReservation.windowStartedAt,
            LOGIN_SOURCE_RATE_LIMIT_MAX_ATTEMPTS
          );
        }
        await transaction.loginRateLimit.deleteMany({ where: { identifierHash: { in: [accountIdentifierHash, identifierHash] } } });
        return { user };
      },
      { maxWait: 5_000, timeout: 15_000 }
    );
    if (result.user || result.failureMode === "invalid-credentials") {
      sourceReservation = null;
    } else if (sourceReservation && activeSourceIdentifier) {
      const reservationToRelease = sourceReservation;
      sourceReservation = null;
      await prisma.$transaction((transaction) =>
        refundRateLimitAttemptInTransaction(
          transaction,
          activeSourceIdentifier,
          reservationToRelease.windowStartedAt,
          LOGIN_SOURCE_RATE_LIMIT_MAX_ATTEMPTS
        )
      );
    }
    return result;
  } catch {
    if (sourceReservation && sourceIdentifier && !authenticationTransactionStarted) {
      const reservationToRelease = sourceReservation;
      const identifierToRelease = sourceIdentifier;
      try {
        await prisma.$transaction((transaction) =>
          refundRateLimitAttemptInTransaction(
            transaction,
            identifierToRelease,
            reservationToRelease.windowStartedAt,
            LOGIN_SOURCE_RATE_LIMIT_MAX_ATTEMPTS
          )
        );
      } catch {
        // Preserve the generic limiter failure; an unreleased reservation expires with its window.
      }
    }
    return { user: null, failureMode: "limiter-unavailable" };
  }
}

async function authenticateUserFromLookup(
  lookup: () => Promise<AuthenticationUserRecord | null>,
  password: string,
  requiredRole?: LoginRole
): Promise<AuthenticatedUser | null> {
  const user = await lookup();

  // An account of another role is indistinguishable from a missing one, so the
  // public portal cannot be used to guess (or lock out) ADMIN passwords.
  if (!user?.isActive || user.accountStatus !== "ACTIVE" || !user.passwordHash || (requiredRole && user.role !== requiredRole)) {
    await verifyPassword(DUMMY_PASSWORD_HASH, password);
    return null;
  }

  const passwordMatches = await verifyPassword(user.passwordHash, password);

  if (!passwordMatches) {
    return null;
  }

  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    role: user.role
  };
}

export async function createSession(userId: string): Promise<CreatedSession> {
  const token = generateSessionToken();
  const tokenHash = hashSessionToken(token);
  const expiresAt = getSessionExpiresAt();

  await prisma.session.create({
    data: {
      userId,
      sessionKey: randomBytes(24).toString("base64url"),
      tokenHash,
      expiresAt
    }
  });

  return { token, expiresAt };
}

export async function getSessionByToken(token: string): Promise<AuthenticatedSession | null> {
  const tokenHash = hashSessionToken(token);
  const session = await prisma.session.findUnique({
    where: { tokenHash },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          displayName: true,
          role: true,
          isActive: true,
          accountStatus: true
        }
      }
    }
  });

  if (
    !session ||
    session.revokedAt ||
    session.expiresAt <= new Date() ||
    !session.user.isActive ||
    session.user.accountStatus !== "ACTIVE"
  ) {
    return null;
  }

  return {
    id: session.id,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    authenticationMethods: session.authenticationMethods,
    user: {
      id: session.user.id,
      email: session.user.email,
      displayName: session.user.displayName,
      role: session.user.role
    }
  };
}

export async function revokeSessionToken(token: string): Promise<number> {
  const result = await prisma.session.updateMany({
    where: {
      tokenHash: hashSessionToken(token),
      revokedAt: null
    },
    data: {
      revokedAt: new Date()
    }
  });

  return result.count;
}

export async function cleanupInactiveSessions(now = new Date()): Promise<number> {
  const result = await prisma.session.deleteMany({
    where: {
      OR: [
        { expiresAt: { lt: now } },
        { revokedAt: { not: null } }
      ]
    }
  });

  return result.count;
}

function isRateLimitWindowExpired(windowStartedAt: Date, now: Date): boolean {
  return getRateLimitWindowResetAt(windowStartedAt) <= now;
}

function getRateLimitWindowResetAt(windowStartedAt: Date): Date {
  return new Date(windowStartedAt.getTime() + LOGIN_RATE_LIMIT_WINDOW_MS);
}

async function pruneExpiredLoginRateLimits(now: Date): Promise<number> {
  const result = await prisma.loginRateLimit.deleteMany({
    where: { expiresAt: { lte: now } }
  });

  return result.count;
}

async function lockLoginRateLimitIdentifier(
  transaction: Prisma.TransactionClient,
  identifierHash: string
): Promise<void> {
  await transaction.$queryRaw`
    SELECT set_config('lock_timeout', ${`${LOGIN_RATE_LIMIT_LOCK_TIMEOUT_MS}ms`}, true)
  `;
  await transaction.$queryRaw`
    SELECT pg_advisory_xact_lock(hashtextextended(${identifierHash}, 0)) IS NULL AS "locked"
  `;
}

async function recordFailedLoginEntry(
  transaction: Prisma.TransactionClient,
  identifierHash: string,
  now: Date,
  maxAttempts = LOGIN_RATE_LIMIT_MAX_ATTEMPTS
): Promise<void> {
  const existing = await transaction.loginRateLimit.findUnique({
    where: { identifierHash },
    select: {
      attempts: true,
      windowStartedAt: true
    }
  });
  const expiresAt = new Date(now.getTime() + LOGIN_RATE_LIMIT_RETENTION_MS);

  if (!existing) {
    await transaction.loginRateLimit.create({
      data: {
        identifierHash,
        attempts: 1,
        windowStartedAt: now,
        blockedUntil: null,
        expiresAt
      }
    });
    return;
  }

  if (isRateLimitWindowExpired(existing.windowStartedAt, now)) {
    await transaction.loginRateLimit.update({
      where: { identifierHash },
      data: {
        attempts: 1,
        windowStartedAt: now,
        blockedUntil: null,
        expiresAt
      }
    });
    return;
  }

  const attempts = Math.min(existing.attempts + 1, maxAttempts);
  await transaction.loginRateLimit.update({
    where: { identifierHash },
    data: {
      attempts,
      blockedUntil:
        attempts >= maxAttempts
          ? getRateLimitWindowResetAt(existing.windowStartedAt)
          : null,
      expiresAt
    }
  });
}

function isLoginRateLimitBlocked(
  entry: {
    attempts: number;
    windowStartedAt: Date;
    blockedUntil: Date | null;
  },
  now: Date,
  maxAttempts = LOGIN_RATE_LIMIT_MAX_ATTEMPTS
): boolean {
  if (entry.blockedUntil && entry.blockedUntil > now) {
    return true;
  }

  return (
    !isRateLimitWindowExpired(entry.windowStartedAt, now) &&
    entry.attempts >= maxAttempts
  );
}

function findAuthenticationUser(
  client: Pick<Prisma.TransactionClient, "user">,
  email: string
): Promise<AuthenticationUserRecord | null> {
  return client.user.findUnique({
    where: { email: normalizeEmail(email) },
    select: {
      id: true,
      email: true,
      displayName: true,
      passwordHash: true,
      role: true,
      isActive: true,
      accountStatus: true
    }
  });
}

function hashLoginRateLimitIdentifier(identifier: string): string {
  return createLoginRateLimitIdentifierHash(normalizeRateLimitIdentifier(identifier));
}

function hashRateLimitIdentifier(identifier: string): string {
  return createRateLimitIdentifierHash(identifier);
}

function normalizeRateLimitIdentifier(identifier: string): string {
  const normalized = normalizeEmail(identifier);
  return normalized || "unknown";
}
