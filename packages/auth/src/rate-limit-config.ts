import { createHmac } from "node:crypto";
import { isIP } from "node:net";

const SYNTHETIC_NON_PRODUCTION_KEY = "virki-synthetic-non-production-rate-limit-key";
const CONFIGURATION_UNAVAILABLE_MESSAGE = "Login rate limiter configuration unavailable.";

export type LoginRateLimitConfigurationState =
  | { available: true; source: "environment" | "synthetic" }
  | { available: false; source: "missing-production-secret" };

export type LoginRateLimitReservationState = {
  attempts: number;
  windowStartedAt: Date;
  blockedUntil: Date | null;
};

export function getLoginRateLimitRefundState(
  existing: LoginRateLimitReservationState,
  reservationWindowStartedAt: Date,
  maxAttempts: number
): Pick<LoginRateLimitReservationState, "attempts" | "blockedUntil"> | null {
  if (existing.windowStartedAt.getTime() !== reservationWindowStartedAt.getTime()) return null;

  const attempts = Math.max(existing.attempts - 1, 0);
  return {
    attempts,
    blockedUntil: attempts < maxAttempts ? null : existing.blockedUntil
  };
}

export function getLoginRateLimitConfigurationState(
  env: NodeJS.ProcessEnv = process.env
): LoginRateLimitConfigurationState {
  const configuredKey = env.VIRKI_RATE_LIMIT_HASH_SECRET;

  if (configuredKey && configuredKey.trim().length > 0) {
    return { available: true, source: "environment" };
  }

  if (env.NODE_ENV === "production") {
    return { available: false, source: "missing-production-secret" };
  }

  return { available: true, source: "synthetic" };
}

export function createLoginRateLimitIdentifierHash(
  normalizedIdentifier: string,
  env: NodeJS.ProcessEnv = process.env
): string {
  return createRateLimitIdentifierHash(normalizedIdentifier, env);
}

export function createLoginAccountRateLimitIdentifierHash(
  email: string,
  env: NodeJS.ProcessEnv = process.env
): string {
  return createLoginRateLimitIdentifierHash(email.trim().toLowerCase() || "unknown", env);
}

// Keeps counters for one login surface (hub = ADMIN, portal = USER) from locking out the other.
export function scopeLoginRateLimitEmail(email: string, role: string | undefined): string {
  const normalizedEmail = email.trim().toLowerCase() || "unknown";
  return role ? `login-role:${role}:${normalizedEmail}` : normalizedEmail;
}

export function createLoginAttemptRateLimitIdentifierHash(
  email: string,
  trustedClientAddress: string | undefined,
  env: NodeJS.ProcessEnv = process.env
): string {
  const normalizedEmail = email.trim().toLowerCase() || "unknown";
  const sourceAddress = trustedClientAddress ?? "unscoped";
  return createLoginRateLimitIdentifierHash(`login-attempt\0${normalizedEmail}\0${sourceAddress}`, env);
}

export function isTrustedClientAddress(value: string | undefined): value is string {
  if (!value || value.length > 64 || value !== value.trim() || value.includes(",")) return false;
  return isIP(value) !== 0;
}

export function createRateLimitIdentifierHash(
  identifier: string,
  env: NodeJS.ProcessEnv = process.env
): string {
  return createHmac("sha256", resolveLoginRateLimitHashKey(env))
    .update(identifier, "utf8")
    .digest("hex");
}

function resolveLoginRateLimitHashKey(env: NodeJS.ProcessEnv): string {
  const state = getLoginRateLimitConfigurationState(env);

  if (!state.available) {
    throw new Error(CONFIGURATION_UNAVAILABLE_MESSAGE);
  }

  return state.source === "environment"
    ? (env.VIRKI_RATE_LIMIT_HASH_SECRET as string)
    : SYNTHETIC_NON_PRODUCTION_KEY;
}
