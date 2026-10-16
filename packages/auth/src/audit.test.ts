import assert from "node:assert/strict";
import test from "node:test";
import { formatAuditEmailReference, getAuditLogRetentionDays, hashAuditEmail, sanitizeAuditMetadata, writeAuditCleanupResultIfNeeded, writeAuditLogForMaintenanceRequired, writeAuditLogInTransaction, type AuditMetadata, type AuditLogInput } from "./audit";

test("audit email references use keyed, versioned pseudonyms and preserve legacy display", () => {
  const firstKey = "11".repeat(32);
  const secondKey = "22".repeat(32);
  const first = hashAuditEmail("Member@example.invalid", { NODE_ENV: "production", VIRKI_AUDIT_HASH_SECRET: firstKey } as NodeJS.ProcessEnv);
  const normalized = hashAuditEmail(" member@example.invalid ", { NODE_ENV: "production", VIRKI_AUDIT_HASH_SECRET: firstKey } as NodeJS.ProcessEnv);
  const rotated = hashAuditEmail("member@example.invalid", { NODE_ENV: "production", VIRKI_AUDIT_HASH_SECRET: secondKey } as NodeJS.ProcessEnv);

  assert.equal(first, normalized);
  assert.match(first, /^hmac-v1:[a-f0-9]{16}:[a-f0-9]{64}$/u);
  assert.notEqual(first, rotated);
  assert.equal(formatAuditEmailReference(first), first.split(":")[2].slice(0, 10));
  assert.equal(formatAuditEmailReference("0123456789abcdef".repeat(4)), "0123456789");
  assert.throws(() => hashAuditEmail("member@example.invalid", { NODE_ENV: "production" } as NodeJS.ProcessEnv));
});

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

test("audit persistence keeps boolean and numeric url/uri flags while redacting URL-valued fields", async () => {
  const metadata: AuditMetadata = {
    redirectUrisChanged: true,
    launchUrlConfigured: false,
    originChanged: true,
    redirectUriCount: 2,
    redirectUri: "https://x.example/cb",
    launchUrl: "https://x.example/launch",
    callbackUrl: "relative/path",
    redirectUris: ["https://x.example/cb"],
    tokenRevoked: true,
    sessionCount: 3,
    otpConfigured: true,
    referrer: "https://x.example/"
  };

  assert.deepEqual(sanitizeAuditMetadata(metadata), {
    redirectUrisChanged: true,
    launchUrlConfigured: false,
    originChanged: true,
    redirectUriCount: 2,
    redirectUri: "[REDACTED]",
    launchUrl: "[REDACTED]",
    callbackUrl: "[REDACTED]",
    redirectUris: "[REDACTED]",
    tokenRevoked: "[REDACTED]",
    sessionCount: "[REDACTED]",
    otpConfigured: "[REDACTED]",
    referrer: "[REDACTED]"
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

test("maintenance audit append is parameterized, sanitized, and does not read or return AuditLog rows", async () => {
  let query: { sql: string; values: unknown[] } | undefined;
  await writeAuditLogForMaintenanceRequired({
    eventType: "AUTH_AUDIT_LOG_CLEANUP",
    result: "SUCCESS",
    message: "Cleanup complete.",
    metadata: { source: "audit-log-cleanup", token: "synthetic-secret" }
  }, async (statement) => {
    query = statement;
    return 1;
  });

  assert.ok(query);
  assert.match(query.sql, /INSERT INTO "AuditLog"/u);
  assert.doesNotMatch(query.sql, /SELECT|RETURNING/u);
  const serializedMetadata = query.values.find((value) => typeof value === "string" && value.includes("audit-log-cleanup"));
  assert.equal(typeof serializedMetadata, "string");
  assert.equal(JSON.parse(String(serializedMetadata)).token, "[REDACTED]");
  assert.ok(query.values.includes("AUTH_AUDIT_LOG_CLEANUP"));
});

test("audit cleanup skips no-op persistence so an empty first-install database stays virgin", async () => {
  const recorded: AuditLogInput[] = [];
  const write = async (input: AuditLogInput) => { recorded.push(input); };

  await writeAuditCleanupResultIfNeeded({ deletedCount: 0, retentionDays: 180 }, write);
  assert.deepEqual(recorded, []);

  await writeAuditCleanupResultIfNeeded({ deletedCount: 2, retentionDays: 180 }, write);
  assert.deepEqual(recorded, [{
    eventType: "AUTH_AUDIT_LOG_CLEANUP",
    result: "SUCCESS",
    resource: "audit-log",
    message: "Expired audit logs cleaned up.",
    metadata: { source: "audit-log-cleanup", deletedCount: 2, retentionDays: 180 }
  }]);
});

test("blank audit retention configuration uses the documented 180-day default", () => {
  assert.equal(getAuditLogRetentionDays({}), 180);
  assert.equal(getAuditLogRetentionDays({ AUDIT_LOG_RETENTION_DAYS: "" }), 180);
  assert.equal(getAuditLogRetentionDays({ AUDIT_LOG_RETENTION_DAYS: "  " }), 180);
  assert.equal(getAuditLogRetentionDays({ AUDIT_LOG_RETENTION_DAYS: "0" }), 1);
  assert.equal(getAuditLogRetentionDays({ AUDIT_LOG_RETENTION_DAYS: "30" }), 30);
});
