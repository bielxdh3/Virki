import assert from "node:assert/strict";
import test from "node:test";
import { sanitizeAuditMetadata, writeAuditLogInTransaction, type AuditMetadata, type AuditLogInput } from "./audit";

test("audit persistence keeps useful nested references", async () => {
  const digest = "0123456789abcdef".repeat(4);
  const metadata: AuditMetadata = {
    source: "admin-project-access-grant",
    accessJwtPresent: true,
    nested: {
      requestRef: digest,
      userAgentHash: digest,
      status: "valid"
    },
    counts: [1, 2, 3]
  };

  assert.deepEqual(sanitizeAuditMetadata(metadata), metadata);
});

test("audit persistence redacts credential keys and secret-like values at every depth", async () => {
  const passwordKey = ["pass", "word"].join("");
  const tokenKey = ["to", "ken"].join("");
  const clientSecretKey = ["client", "_secret"].join("");
  const metadata: AuditMetadata = {
    source: "hub-login",
    detail: "Bearer synthetic-bearer-material",
    explanation: [passwordKey, "=synthetic-password-material"].join(""),
    privateKeyDetails: ["-----BEGIN ", "PRIVATE KEY", "----- synthetic-placeholder"].join(""),
    opaque: "AbCd0123".repeat(6),
    nested: {
      [tokenKey]: "synthetic-token-material",
      authorizationCode: "synthetic-code-material",
      [passwordKey]: "synthetic-password-material",
      [clientSecretKey]: "synthetic-secret-material",
      private_key: "synthetic-private-key-material",
      recoveryCode: "654321",
      endpointUrl: "https://service.invalid/callback"
    }
  };

  assert.deepEqual(sanitizeAuditMetadata(metadata), {
    source: "hub-login",
    detail: "[REDACTED]",
    explanation: "[REDACTED]",
    privateKeyDetails: "[REDACTED]",
    opaque: "[REDACTED]",
    nested: {
      token: "[REDACTED]",
      authorizationCode: "[REDACTED]",
      password: "[REDACTED]",
      client_secret: "[REDACTED]",
      private_key: "[REDACTED]",
      recoveryCode: "[REDACTED]",
      endpointUrl: "[REDACTED]"
    }
  });
});

test("audit persistence rejects suspicious URL values and URL-shaped fields", async () => {
  const metadata: AuditMetadata = {
    url: "https://service.invalid/callback",
    callback: "https://service.invalid/callback?code=synthetic-code&state=synthetic-state",
    encoded: "https%3A%2F%2Fservice.invalid%2Fcallback%3Ftoken%3Dsynthetic-token",
    protocolRelative: "//service.invalid/callback?access_token=synthetic-token",
    note: "invalid_request"
  };

  assert.deepEqual(sanitizeAuditMetadata(metadata), {
    url: "[REDACTED]",
    callback: "[REDACTED]",
    encoded: "[REDACTED]",
    protocolRelative: "[REDACTED]",
    note: "invalid_request"
  });
});

test("audit persistence strips controls and bounds keys, arrays, and strings", async () => {
  const metadata: AuditMetadata = {
    note: "bounded ".repeat(20),
    control: "first\u0000second\nthird\u200fend",
    entries: Array.from({ length: 15 }, (_, index) => index),
    nested: Object.fromEntries(Array.from({ length: 15 }, (_, index) => [`key${index}`, index]))
  };

  const persisted = sanitizeAuditMetadata(metadata) as Record<string, unknown>;
  assert.equal((persisted.note as string).length, 80);
  assert.equal(persisted.control, "first second third end");
  assert.deepEqual(persisted.entries, Array.from({ length: 12 }, (_, index) => index));
  assert.deepEqual(Object.keys(persisted.nested as object), Array.from({ length: 12 }, (_, index) => `key${index}`));
});

test("transactional audit persistence sanitizes metadata and propagates storage errors", async () => {
  let createdData: Record<string, unknown> | undefined;
  const create = async ({ data }: { data: Record<string, unknown> }) => {
    createdData = data;
    return {};
  };
  const transaction = { auditLog: { create } } as unknown as Parameters<typeof writeAuditLogInTransaction>[0];
  const input: AuditLogInput = {
    eventType: "ACCOUNT_STATE_CHANGED",
    result: "SUCCESS",
    message: "Account updated.",
    metadata: { password: "placeholder", enabled: false }
  };

  await writeAuditLogInTransaction(transaction, input);
  assert.equal((createdData?.metadata as Record<string, unknown>).password, "[REDACTED]");
  assert.equal((createdData?.metadata as Record<string, unknown>).enabled, false);

  const failure = new Error("synthetic audit storage failure");
  const failedTransaction = {
    auditLog: {
      create: async () => {
        throw failure;
      }
    }
  } as unknown as Parameters<typeof writeAuditLogInTransaction>[0];
  await assert.rejects(writeAuditLogInTransaction(failedTransaction, input), (error) => error === failure);
});
