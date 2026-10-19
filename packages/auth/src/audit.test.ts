import assert from "node:assert/strict";
import test from "node:test";
import { formatAuditEmailReference, hashAuditEmail, sanitizeAuditMetadata, writeAuditLogInTransaction, type AuditMetadata, type AuditLogInput } from "./audit";

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
    actorUserId: "verified-admin-id",
    actorRole: "ADMIN",
    sessionRef: "a".repeat(64),
    message: "Account updated.",
    metadata: { password: "placeholder", enabled: false }
  };

  await writeAuditLogInTransaction(transaction, input);
  assert.equal(createdData?.actorUserId, "verified-admin-id");
  assert.equal(createdData?.actorRole, "ADMIN");
  assert.equal(createdData?.sessionRef, "a".repeat(64));
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

test("redacts the canonical control-normalized value recursively", () => {
  for (const control of ["\t", "\0", "\u200b", "\u202e", "\u0085"]) {
    const result = sanitizeAuditMetadata({ detail: `Bearer${control}abcdefghijklmnop`, nested: { values: [`Basic${control}abcdefghijklmnop`] } });
    assert.equal(result?.detail, "[REDACTED]");
    assert.deepEqual(result?.nested, { values: ["[REDACTED]"] });
  }
});
