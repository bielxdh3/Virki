import assert from "node:assert/strict";
import test from "node:test";
import { encryptOidcPayload } from "@virki/auth/oidc-secrets";
import { deleteExpiredOidcArtifacts, PrismaOidcAdapter } from "./adapter";

const env = { VIRKI_OIDC_ADAPTER_KEY: "ab".repeat(32) };

test("expired OIDC artifacts are deleted using the indexed expiry cutoff", async () => {
  const now = new Date("2026-10-02T12:00:00.000Z");
  const calls: unknown[] = [];
  const database = {
    oidcArtifact: {
      deleteMany: async (args: unknown) => {
        calls.push(args);
        return { count: 3 };
      }
    }
  };

  assert.equal(await deleteExpiredOidcArtifacts(database as never, now), 3);
  assert.deepEqual(calls, [{ where: { expiresAt: { lte: now } } }]);
});

test("OIDC artifact consume uses compare-and-set so a code cannot be replayed concurrently", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  const whereArgs: unknown[] = [];
  let updates = 0;
  const database = {
    oidcArtifact: {
      findUnique: async () => ({ payloadCiphertext: encryptOidcPayload(JSON.stringify({ jti: "short-lived" }), env) }),
      updateMany: async (args: unknown) => { whereArgs.push(args); updates += 1; return { count: 1 }; }
    }
  };
  try {
    await new PrismaOidcAdapter("AuthorizationCode", database as never).consume("one-time-code");
    assert.equal(updates, 1);
    assert.match(JSON.stringify(whereArgs[0]), /consumedAt/);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("OIDC artifact consume rejects a raced or already-consumed artifact", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  const database = { oidcArtifact: {
    findUnique: async () => ({ payloadCiphertext: encryptOidcPayload(JSON.stringify({ jti: "short-lived" }), env) }),
    updateMany: async () => ({ count: 0 })
  } };
  try {
    await assert.rejects(() => new PrismaOidcAdapter("AuthorizationCode", database as never).consume("one-time-code"));
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("OIDC artifacts cannot be consumed after their stored row is revoked", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  try {
    const database = { oidcArtifact: { findUnique: async () => null } };
    await assert.rejects(() => new PrismaOidcAdapter("AuthorizationCode", database as never).consume("revoked-code"), /OIDC artifact was not found/u);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("grant-bound OIDC artifacts lock and recheck active account, connection, and USER grant before persistence", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  const calls: Array<{ kind: string; sql?: string; values?: unknown[] }> = [];
  try {
    const database = {
      $transaction: async (callback: (transaction: unknown) => Promise<void>) => callback({
        $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          calls.push({ kind: "lock", sql: strings.join("?"), values });
          return [{ id: "active-grant", redirectUris: ["https://project.example.invalid/callback"] }];
        },
        oidcArtifact: { upsert: async () => { calls.push({ kind: "upsert" }); } }
      }),
      oidcArtifact: { upsert: async () => { calls.push({ kind: "unexpected-direct-upsert" }); } },
      projectConnection: {}
    };

    await new PrismaOidcAdapter("AccessToken", database as never).upsert("token-id", {
      accountId: "user-id",
      clientId: "client-id",
      grantId: "provider-grant-id"
    } as never, 300);

    assert.deepEqual(calls.map(({ kind }) => kind), ["lock", "upsert"]);
    assert.match(calls[0].sql ?? "", /grant_record\."revokedAt" IS NULL[\s\S]*account_record\."role" = 'USER'[\s\S]*account_record\."isActive" = TRUE[\s\S]*account_record\."accountStatus" = 'ACTIVE'[\s\S]*connection_record\."enabled" = TRUE/u);
    assert.match(calls[0].sql ?? "", /FOR UPDATE OF grant_record, account_record, connection_record/u);
    assert.match(calls[0].sql ?? "", /connection_record\."redirectUris" AS "redirectUris"/u);
    assert.deepEqual(calls[0].values, ["user-id", "client-id"]);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("authorization codes are persisted only for a redirect URI that is still registered", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  let upserts = 0;
  try {
    const database = {
      $transaction: async (callback: (transaction: unknown) => Promise<void>) => callback({
        $queryRaw: async () => [{ id: "active-grant", redirectUris: ["https://project.example.invalid/new-callback"] }],
        oidcArtifact: { upsert: async () => { upserts += 1; } }
      }),
      oidcArtifact: { upsert: async () => { upserts += 1; } },
      projectConnection: {}
    };
    const adapter = new PrismaOidcAdapter("AuthorizationCode", database as never);
    const context = { accountId: "user-id", clientId: "client-id", grantId: "provider-grant-id" };

    await adapter.upsert("current-code", { ...context, redirectUri: "https://project.example.invalid/new-callback" } as never, 300);
    await assert.rejects(
      () => adapter.upsert("stale-code", { ...context, redirectUri: "https://project.example.invalid/old-callback" } as never, 300),
      /OIDC redirect URI is no longer registered/u
    );
    assert.equal(upserts, 1);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("grant-bound token persistence fails closed when the USER grant has been revoked", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  let upserted = false;
  try {
    const database = {
      $transaction: async (callback: (transaction: unknown) => Promise<void>) => callback({
        $queryRaw: async () => [],
        oidcArtifact: { upsert: async () => { upserted = true; } }
      }),
      oidcArtifact: { upsert: async () => { upserted = true; } },
      projectConnection: {}
    };

    await assert.rejects(() => new PrismaOidcAdapter("AccessToken", database as never).upsert("token-id", {
      accountId: "user-id",
      clientId: "client-id",
      grantId: "provider-grant-id"
    } as never, 300), /OIDC authorization is no longer active/u);
    assert.equal(upserted, false);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("OIDC provider Grant records recheck active project access before persistence", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  const calls: Array<{ kind: string; sql?: string; values?: unknown[]; args?: unknown }> = [];
  try {
    const database = {
      $transaction: async (callback: (transaction: unknown) => Promise<void>) => callback({
        $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          calls.push({ kind: "lock", sql: strings.join("?"), values });
          return [{ id: "active-grant" }];
        },
        oidcArtifact: { upsert: async (args: unknown) => { calls.push({ kind: "upsert", args }); } }
      }),
      oidcArtifact: { upsert: async () => { calls.push({ kind: "unexpected-direct-upsert" }); } },
      projectConnection: {}
    };

    await assert.rejects(() => new PrismaOidcAdapter("Grant", database as never).upsert("provider-grant-id", { clientId: "client-id" } as never, 300), /OIDC artifact authorization is incomplete/u);
    assert.equal(calls.length, 0);
    await new PrismaOidcAdapter("Grant", database as never).upsert("provider-grant-id", { accountId: "user-id", clientId: "client-id" } as never, 300);
    assert.deepEqual(calls.map(({ kind }) => kind), ["lock", "upsert"]);
    assert.match(calls[0].sql ?? "", /grant_record\."revokedAt" IS NULL[\s\S]*account_record\."role" = 'USER'[\s\S]*account_record\."isActive" = TRUE[\s\S]*account_record\."accountStatus" = 'ACTIVE'[\s\S]*connection_record\."enabled" = TRUE/u);
    assert.deepEqual(calls[0].values, ["user-id", "client-id"]);
    assert.equal((calls[1].args as { create: { grantHash: string | null } }).create.grantHash, null);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("OIDC provider Grant persistence fails closed when project access was revoked", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  let upserted = false;
  try {
    const database = {
      $transaction: async (callback: (transaction: unknown) => Promise<void>) => callback({
        $queryRaw: async () => [],
        oidcArtifact: { upsert: async () => { upserted = true; } }
      }),
      oidcArtifact: { upsert: async () => { upserted = true; } },
      projectConnection: {}
    };

    await assert.rejects(() => new PrismaOidcAdapter("Grant", database as never).upsert("provider-grant-id", {
      accountId: "user-id",
      clientId: "client-id"
    } as never, 300), /OIDC authorization is no longer active/u);
    assert.equal(upserted, false);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});
