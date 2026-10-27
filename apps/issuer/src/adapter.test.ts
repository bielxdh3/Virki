import assert from "node:assert/strict";
import test from "node:test";
import { encryptOidcPayload, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { deleteExpiredOidcArtifacts, PrismaOidcAdapter } from "./adapter";

const env = { VIRKI_OIDC_ADAPTER_KEY: "ab".repeat(32) };

test("nonpositive or invalid OIDC TTL removes existing storage instead of creating an unbounded artifact", async () => {
  const previous = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  const calls: unknown[] = [];
  const database = { oidcArtifact: {
    deleteMany: async (args: unknown) => { calls.push(args); return { count: 1 }; },
    upsert: async () => assert.fail("An invalid TTL must never persist an artifact.")
  } };
  try {
    for (const ttl of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      await new PrismaOidcAdapter("Interaction", database as never).upsert("expired", {} as never, ttl);
    }
    assert.deepEqual(calls, Array.from({ length: 4 }, () => ({ where: { model: "Interaction", idHash: hashOidcIdentifier("expired") } })));
  } finally {
    if (previous === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = previous;
  }
});

test("pending Interaction indexes nested client and authenticated session without inventing a pre-login account", async () => {
  const previous = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  const rows: Array<{ create: { clientIdHash: string | null; accountIdHash: string | null } }> = [];
  const calls: Array<{ kind: string; sql?: string; values?: unknown[] }> = [];
  try {
    const database = {
      $transaction: async (operation: (transaction: unknown) => Promise<void>) => operation({
        $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          calls.push({ kind: "connection-lock", sql: strings.join("?"), values });
          return [{ id: "connection-id" }];
        },
        oidcArtifact: { upsert: async (args: typeof rows[number]) => { calls.push({ kind: "upsert" }); rows.push(args); } }
      }),
      oidcArtifact: { upsert: async () => assert.fail("Interaction persistence must share the connection lock transaction.") },
      projectConnection: {}
    };
    const adapter = new PrismaOidcAdapter("Interaction", database as never);
    await adapter.upsert("before-login", { params: { client_id: "client" } } as never, 300);
    await adapter.upsert("after-login", { params: { client_id: "client" }, session: { accountId: "user" } } as never, 300);
    await adapter.upsert("login-result", { params: { client_id: "client" }, result: { login: { accountId: "result-user" } } } as never, 300);
    assert.deepEqual(rows.map(({ create }) => [create.clientIdHash, create.accountIdHash]), [
      [hashOidcIdentifier("client"), null],
      [hashOidcIdentifier("client"), hashOidcIdentifier("user")],
      [hashOidcIdentifier("client"), hashOidcIdentifier("result-user")]
    ]);
    assert.deepEqual(calls.map(({ kind }) => kind), ["connection-lock", "upsert", "connection-lock", "upsert", "connection-lock", "upsert"]);
    assert.match(calls[0].sql ?? "", /FROM "ProjectConnection"[\s\S]*"clientId" = \?[\s\S]*"enabled" = TRUE[\s\S]*FOR UPDATE/u);
    assert.deepEqual(calls[0].values, ["client"]);
  } finally {
    if (previous === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = previous;
  }
});

test("pre-login Interaction persistence fails closed for disabled or deleted clients", async () => {
  const previous = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  try {
    for (const state of ["disabled", "deleted"]) {
      let upserted = false;
      const database = {
        $transaction: async (operation: (transaction: unknown) => Promise<void>) => operation({
          $queryRaw: async () => [],
          oidcArtifact: { upsert: async () => { upserted = true; } }
        }),
        oidcArtifact: { upsert: async () => { upserted = true; } },
        projectConnection: {}
      };
      await assert.rejects(
        () => new PrismaOidcAdapter("Interaction", database as never).upsert("pending", { params: { client_id: `client-${state}` } } as never, 300),
        /client/iu
      );
      assert.equal(upserted, false, `${state} clients must not persist interactions`);
    }
  } finally {
    if (previous === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = previous;
  }
});

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

test("an unavailable client-secret decryption key makes the client unavailable without throwing", async () => {
  const previous = process.env.VIRKI_OIDC_ADAPTER_KEY;
  delete process.env.VIRKI_OIDC_ADAPTER_KEY;
  try {
    const database = {
      projectConnection: {
        findUnique: async () => ({
          clientId: "client-id",
          clientSecretCiphertext: "v1.synthetic.synthetic.synthetic",
          name: "Synthetic project",
          origin: "https://project.example.invalid",
          redirectUris: ["https://project.example.invalid/callback"],
          enabled: true
        })
      }
    };
    assert.equal(await new PrismaOidcAdapter("Client", database as never).find("client-id"), undefined);
  } finally {
    if (previous === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = previous;
  }
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
    await assert.rejects(() => new PrismaOidcAdapter("AuthorizationCode", database as never).consume("revoked-code"), /invalid_grant/u);
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
          return calls.length === 1
            ? [{ id: "active-grant", redirectUris: ["https://project.example.invalid/callback"] }]
            : [{ id: "provider-grant" }];
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

    assert.deepEqual(calls.map(({ kind }) => kind), ["lock", "lock", "upsert"]);
    const authorizationSql = calls[0].sql ?? "";
    assert.match(authorizationSql, /WITH connection_record AS MATERIALIZED \([\s\S]*FROM "ProjectConnection"[\s\S]*"enabled" = TRUE[\s\S]*FOR UPDATE\s*\)/u);
    assert.match(authorizationSql, /grant_record\."revokedAt" IS NULL[\s\S]*account_record\."role" = 'USER'[\s\S]*account_record\."isActive" = TRUE[\s\S]*account_record\."accountStatus" = 'ACTIVE'[\s\S]*FOR UPDATE OF grant_record, account_record/u);
    assert.ok(authorizationSql.indexOf("FOR UPDATE") < authorizationSql.indexOf("FOR UPDATE OF grant_record, account_record"), "the connection row lock must be acquired before grant and account locks");
    assert.match(authorizationSql, /connection_record\."redirectUris" AS "redirectUris"/u);
    assert.deepEqual(calls[0].values, ["client-id", "user-id"]);
    assert.match(calls[1].sql ?? "", /FROM "OidcArtifact"[\s\S]*"model" = 'Grant'[\s\S]*FOR UPDATE/u);
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
        oidcArtifact: { findUnique: async () => ({ expiresAt: null }), upsert: async () => { upserts += 1; } }
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

test("authorization code redemption rejects a redirect removed after issuance", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  const redirectUri = "https://project.example.invalid/previous-callback";
  const stored = {
    payloadCiphertext: encryptOidcPayload(JSON.stringify({
      accountId: "user-id", clientId: "client-id", redirectUri, grantId: "grant-id"
    }), env),
    expiresAt: new Date(Date.now() + 90_000)
  };
  let currentlyRegistered = true;
  try {
    const database = {
      oidcArtifact: { findUnique: async () => stored },
      projectConnection: { findUnique: async () => ({
        enabled: true,
        redirectUris: currentlyRegistered ? [redirectUri] : ["https://project.example.invalid/new-callback"]
      }) }
    };
    const adapter = new PrismaOidcAdapter("AuthorizationCode", database as never);
    assert.equal((await adapter.find("issued-code"))?.redirectUri, redirectUri);
    currentlyRegistered = false;
    await assert.rejects(() => adapter.find("issued-code"), /invalid_grant/u);
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
    } as never, 300), /invalid_grant/u);
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
    const authorizationSql = calls[0].sql ?? "";
    assert.match(authorizationSql, /WITH connection_record AS MATERIALIZED \([\s\S]*FROM "ProjectConnection"[\s\S]*"enabled" = TRUE[\s\S]*FOR UPDATE\s*\)/u);
    assert.match(authorizationSql, /grant_record\."revokedAt" IS NULL[\s\S]*account_record\."role" = 'USER'[\s\S]*account_record\."isActive" = TRUE[\s\S]*account_record\."accountStatus" = 'ACTIVE'[\s\S]*FOR UPDATE OF grant_record, account_record/u);
    assert.ok(authorizationSql.indexOf("FOR UPDATE") < authorizationSql.indexOf("FOR UPDATE OF grant_record, account_record"), "the connection row lock must be acquired before grant and account locks");
    assert.deepEqual(calls[0].values, ["client-id", "user-id"]);
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
    } as never, 300), /invalid_grant/u);
    assert.equal(upserted, false);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("grant-bound token persistence fails closed when the provider Grant artifact was purged or expired", async () => {
  const original = process.env.VIRKI_OIDC_ADAPTER_KEY;
  process.env.VIRKI_OIDC_ADAPTER_KEY = env.VIRKI_OIDC_ADAPTER_KEY;
  let upserted = false;
  let grant: { expiresAt: Date | null } | null = null;
  try {
    const database = {
      $transaction: async (callback: (transaction: unknown) => Promise<void>) => callback({
        $queryRaw: async (query: TemplateStringsArray) => {
          if (query.join("").includes('FROM "UserProjectGrant"')) return [{ id: "active-grant", redirectUris: ["https://project.example.invalid/callback"] }];
          return grant && (!grant.expiresAt || grant.expiresAt > new Date()) ? [{ id: "provider-grant" }] : [];
        },
        oidcArtifact: { upsert: async () => { upserted = true; } }
      }),
      oidcArtifact: {},
      projectConnection: {}
    };
    const payload = { accountId: "user-id", clientId: "client-id", grantId: "provider-grant-id" } as never;
    const adapter = new PrismaOidcAdapter("AccessToken", database as never);
    await assert.rejects(() => adapter.upsert("t", payload, 300), /invalid_grant/u);
    grant = { expiresAt: new Date(Date.now() - 1000) };
    await assert.rejects(() => adapter.upsert("t", payload, 300), /invalid_grant/u);
    assert.equal(upserted, false);
    grant = { expiresAt: null };
    await adapter.upsert("t", payload, 300);
    assert.equal(upserted, true);
  } finally {
    if (original === undefined) delete process.env.VIRKI_OIDC_ADAPTER_KEY;
    else process.env.VIRKI_OIDC_ADAPTER_KEY = original;
  }
});

test("replaying a grant locks its provider Grant before deleting grant-bound artifacts", async () => {
  const calls: unknown[] = [];
  const database = {
    $transaction: async (operation: (transaction: unknown) => Promise<void>) => operation({
      $queryRaw: async (query: TemplateStringsArray) => { calls.push(query.join("")); return []; },
      oidcArtifact: { deleteMany: async (args: unknown) => { calls.push(args); return { count: 2 }; } }
    })
  };
  await new PrismaOidcAdapter("AuthorizationCode", database as never).revokeByGrantId("one-time-grant");
  assert.equal(calls.length, 2);
  assert.match(String(calls[0]), /FROM "OidcArtifact"[\s\S]*FOR UPDATE/u);
  const where = (calls[1] as { where: { OR: Array<Record<string, string>> } }).where;
  assert.equal(where.OR.length, 2);
  assert.equal(where.OR[0].grantHash, where.OR[1].idHash);
  assert.equal(where.OR[1].model, "Grant");
});
