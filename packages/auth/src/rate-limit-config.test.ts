import assert from "node:assert/strict";
import test from "node:test";

import {
  createLoginRateLimitIdentifierHash,
  getLoginRateLimitConfigurationState
} from "./rate-limit-config";

const syntheticDatabaseUrl = "postgresql://example.invalid/synthetic-test";
const syntheticSecret = "replace-with-test-secret";

test("production requires a dedicated non-empty rate-limit key", () => {
  assert.deepEqual(
    getLoginRateLimitConfigurationState({
      NODE_ENV: "production",
      BIELOS_RATE_LIMIT_HASH_SECRET: syntheticSecret
    }),
    { available: true, source: "environment" }
  );
  assert.deepEqual(getLoginRateLimitConfigurationState({ NODE_ENV: "production" }), {
    available: false,
    source: "missing-production-secret"
  });
  assert.deepEqual(
    getLoginRateLimitConfigurationState({
      NODE_ENV: "production",
      BIELOS_RATE_LIMIT_HASH_SECRET: "   "
    }),
    { available: false, source: "missing-production-secret" }
  );
});

test("production never derives the rate-limit key from the database target", () => {
  const env = {
    NODE_ENV: "production",
    DATABASE_URL: syntheticDatabaseUrl
  };

  assert.deepEqual(getLoginRateLimitConfigurationState(env), {
    available: false,
    source: "missing-production-secret"
  });
  assert.throws(
    () => createLoginRateLimitIdentifierHash("member@example.invalid", env),
    (error: unknown) => {
      assert.equal(error instanceof Error, true);
      const message = error instanceof Error ? error.message : String(error);
      assert.equal(message, "Login rate limiter configuration unavailable.");
      assert.equal(message.includes(syntheticDatabaseUrl), false);
      assert.equal(message.includes("BIELOS_RATE_LIMIT_HASH_SECRET"), false);
      return true;
    }
  );
});

test("development and test use a deterministic synthetic fallback", () => {
  const developmentHash = createLoginRateLimitIdentifierHash("member@example.invalid", {
    NODE_ENV: "development",
    DATABASE_URL: syntheticDatabaseUrl
  });
  const testHash = createLoginRateLimitIdentifierHash("member@example.invalid", {
    NODE_ENV: "test",
    DATABASE_URL: "postgresql://different.example.invalid/ignored"
  });

  assert.deepEqual(getLoginRateLimitConfigurationState({ NODE_ENV: "test" }), {
    available: true,
    source: "synthetic"
  });
  assert.equal(developmentHash, testHash);
  assert.match(testHash, /^[a-f0-9]{64}$/);
});

test("an explicit non-production key overrides the synthetic fallback", () => {
  const configuredHash = createLoginRateLimitIdentifierHash("member@example.invalid", {
    NODE_ENV: "test",
    BIELOS_RATE_LIMIT_HASH_SECRET: syntheticSecret
  });
  const fallbackHash = createLoginRateLimitIdentifierHash("member@example.invalid", {
    NODE_ENV: "test"
  });

  assert.deepEqual(
    getLoginRateLimitConfigurationState({
      NODE_ENV: "development",
      BIELOS_RATE_LIMIT_HASH_SECRET: syntheticSecret
    }),
    { available: true, source: "environment" }
  );
  assert.notEqual(configuredHash, fallbackHash);
});
