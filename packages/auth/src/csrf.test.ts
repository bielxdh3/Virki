import assert from "node:assert/strict";
import test from "node:test";
import { createCsrfToken, CSRF_TOKEN_TTL_MS, validateCsrfToken } from "./csrf";

const firstKey = "11".repeat(32);
const secondKey = "22".repeat(32);
const issuedAt = 1_800_000_000_000;

test("CSRF tokens validate across app instances with a shared configured key and bind to their form scope", () => {
  const appA = { NODE_ENV: "production", BIELOS_CSRF_SIGNING_KEY: firstKey } as NodeJS.ProcessEnv;
  const appB = { NODE_ENV: "production", BIELOS_CSRF_SIGNING_KEY: firstKey } as NodeJS.ProcessEnv;
  const token = createCsrfToken({ env: appA, now: issuedAt, scope: "account-security" });

  assert.deepEqual(validateCsrfToken(token, { env: appB, now: issuedAt + 1, scope: "account-security" }), { valid: true });
  assert.deepEqual(validateCsrfToken(token, { env: appB, now: issuedAt + 1, scope: "logout" }), { valid: false, reason: "wrong-scope" });
});

test("CSRF key rotation accepts the previous key only while it is explicitly configured", () => {
  const previousToken = createCsrfToken({
    env: { NODE_ENV: "production", BIELOS_CSRF_SIGNING_KEY: firstKey } as NodeJS.ProcessEnv,
    now: issuedAt,
    scope: "login"
  });
  const rotatingApp = {
    NODE_ENV: "production",
    BIELOS_CSRF_SIGNING_KEY: secondKey,
    BIELOS_CSRF_SIGNING_KEY_PREVIOUS: firstKey
  } as NodeJS.ProcessEnv;

  assert.deepEqual(validateCsrfToken(previousToken, { env: rotatingApp, now: issuedAt + 1, scope: "login" }), { valid: true });
  assert.deepEqual(validateCsrfToken(previousToken, {
    env: { NODE_ENV: "production", BIELOS_CSRF_SIGNING_KEY: secondKey } as NodeJS.ProcessEnv,
    now: issuedAt + 1,
    scope: "login"
  }), { valid: false, reason: "invalid" });
});

test("CSRF rejects malformed, expired, future-dated and unconfigured production tokens", () => {
  const env = { NODE_ENV: "production", BIELOS_CSRF_SIGNING_KEY: firstKey } as NodeJS.ProcessEnv;
  const token = createCsrfToken({ env, now: issuedAt, scope: "login" });

  assert.deepEqual(validateCsrfToken("v2.malformed", { env, now: issuedAt, scope: "login" }), { valid: false, reason: "malformed" });
  assert.deepEqual(validateCsrfToken(token, { env, now: issuedAt + CSRF_TOKEN_TTL_MS, scope: "login" }), { valid: false, reason: "expired" });
  const futureToken = createCsrfToken({ env, now: issuedAt + 10 * CSRF_TOKEN_TTL_MS, scope: "login" });
  assert.deepEqual(validateCsrfToken(futureToken, { env, now: issuedAt, scope: "login" }), { valid: false, reason: "invalid" });
  assert.deepEqual(validateCsrfToken(token, { env: { NODE_ENV: "production" } as NodeJS.ProcessEnv, now: issuedAt, scope: "login" }), { valid: false, reason: "misconfigured" });
  assert.throws(() => createCsrfToken({ env: { NODE_ENV: "production" } as NodeJS.ProcessEnv, now: issuedAt, scope: "login" }));
});
