import { createHmac } from "node:crypto";

const SYNTHETIC_NON_PRODUCTION_KEY = "bielos-synthetic-non-production-rate-limit-key";
const CONFIGURATION_UNAVAILABLE_MESSAGE = "Login rate limiter configuration unavailable.";

export type LoginRateLimitConfigurationState =
  | { available: true; source: "environment" | "synthetic" }
  | { available: false; source: "missing-production-secret" };

export function getLoginRateLimitConfigurationState(
  env: NodeJS.ProcessEnv = process.env
): LoginRateLimitConfigurationState {
  const configuredKey = env.BIELOS_RATE_LIMIT_HASH_SECRET;

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
    ? (env.BIELOS_RATE_LIMIT_HASH_SECRET as string)
    : SYNTHETIC_NON_PRODUCTION_KEY;
}
