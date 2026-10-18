import assert from "node:assert/strict";
import test from "node:test";
import { assertProductionBootstrapContext, bootstrapFirstAdmin, FirstAdminBootstrapError } from "./bootstrap-first-admin";

const dataModels = [
  "user",
  "session",
  "loginRateLimit",
  "projectConnection",
  "userProjectGrant",
  "oidcArtifact",
  "auditLog",
  "emailOutboxMessage",
  "emailDeliveryAttempt",
  "totpFactor",
  "recoveryCode",
  "deviceChallenge",
  "trustedDevice",
  "accountRecoveryRequest",
  "sanitizedAuditReference",
  "administrativeCredential",
  "administrativeRecoveryCode",
  "securityElevation"
] as const;

type AuditFixture = {
  eventType: string;
  result: string;
  resource: string | null;
  message: string | null;
  actorUserId: string | null;
  actorEmailHash: string | null;
  metadata: unknown;
};

const noopAudit = {
  eventType: "AUTH_SESSION_CLEANUP",
  result: "SUCCESS",
  resource: "session",
  message: "Inactive sessions cleaned up.",
  actorUserId: null,
  actorEmailHash: null,
  metadata: { source: "sessions-cleanup", deletedCount: 0, deletedRateLimitCount: 0 }
};

function createDatabase(
  overrides: Partial<Record<(typeof dataModels)[number], number>> = {},
  auditRows: AuditFixture[] = []
) {
  const calls: string[] = [];
  let createdUser: Record<string, unknown> | undefined;
  let auditInput: Record<string, unknown> | undefined;
  const transaction = Object.fromEntries(dataModels.map((name) => [name, {
    count: async () => {
      calls.push(`count:${name}`);
      return overrides[name] ?? 0;
    }
  }])) as Record<string, unknown> & {
    user: { count: () => Promise<number>; create: (input: { data: Record<string, unknown> }) => Promise<{ id: string }> };
    $queryRaw: (query: TemplateStringsArray) => Promise<unknown>;
  };
  transaction.user.create = async ({ data }) => {
    calls.push("create:user");
    createdUser = data;
    return { id: "created-admin" };
  };
  transaction.$queryRaw = async (strings: TemplateStringsArray) => {
    assert.match(strings[0], /^SELECT 1::integer AS acquired FROM pg_advisory_xact_lock\(/u);
    calls.push("lock");
    return [{ acquired: 1 }];
  };
  transaction.auditLog = {
    ...(transaction.auditLog as object),
    findMany: async (args?: { take?: number; cursor?: { id: string }; skip?: number; orderBy?: { id: string } }) => {
      calls.push("read:auditLog");
      if (args?.take === undefined || args.take > 128 || args.take < 1 || args.orderBy?.id !== "asc") {
        throw new Error("Audit bootstrap must use bounded, deterministic pages.");
      }
      const records = auditRows.map((record, index) => ({ ...record, id: `audit-${String(index).padStart(6, "0")}` }));
      const position = args.cursor ? records.findIndex((record) => record.id === args.cursor?.id) : -1;
      if (args.cursor && position < 0) throw new Error("Unknown audit cursor.");
      return records.slice(position + (args.cursor ? (args.skip ?? 0) : 1), position + (args.cursor ? (args.skip ?? 0) : 1) + args.take);
    }
  };
  const database = {
    $transaction: async (callback: (tx: typeof transaction) => Promise<unknown>) => callback(transaction)
  };
  return {
    database,
    calls,
    get createdUser() { return createdUser; },
    get auditInput() { return auditInput; },
    setAudit(input: Record<string, unknown>) { auditInput = input; }
  };
}

const validInput = {
  email: "  Owner@Example.com ",
  displayName: "Owner",
  password: "correct horse battery staple"
};

test("first ADMIN bootstrap writes only to a completely virgin database", async () => {
  const fixture = createDatabase();
  const result = await bootstrapFirstAdmin(validInput, {
    database: fixture.database as never,
    hashPassword: async (password) => `argon2:${password.length}`,
    hashAdminEmail: (email) => `pseudonym:${email}`,
    writeAudit: async (_transaction, input) => fixture.setAudit(input as unknown as Record<string, unknown>),
    now: new Date("2026-10-08T00:00:00.000Z")
  });

  assert.deepEqual(result, { id: "created-admin" });
  assert.equal(fixture.calls[0], "lock");
  assert.deepEqual(fixture.calls.slice(1, -1), dataModels.map((name) => `count:${name}`));
  assert.equal(fixture.calls.at(-1), "create:user");
  assert.deepEqual(fixture.createdUser, {
    email: "owner@example.com",
    emailNormalized: "owner@example.com",
    displayName: "Owner",
    passwordHash: `argon2:${validInput.password.length}`,
    role: "ADMIN",
    isActive: true,
    accountStatus: "ACTIVE",
    emailVerifiedAt: null,
    secondFactorMethod: "EMAIL",
    createdAt: new Date("2026-10-08T00:00:00.000Z")
  });
  assert.equal(fixture.auditInput?.eventType, "ACCOUNT_CREATED");
  assert.equal(fixture.auditInput?.actorUserId, "created-admin");
  assert.equal(fixture.auditInput?.actorEmailHash, "pseudonym:owner@example.com");
  assert.equal(fixture.auditInput?.message, "Initial ADMIN account provisioned through restricted operator bootstrap.");
});

test("first ADMIN bootstrap accepts ONLY preserved zero-change session-cleanup audits", async () => {
  const fixture = createDatabase({ auditLog: 2 }, [{ ...noopAudit }, { ...noopAudit }]);
  const result = await bootstrapFirstAdmin(validInput, {
    database: fixture.database as never,
    hashPassword: async () => "argon2:hashed",
    hashAdminEmail: () => "pseudonym:admin",
    writeAudit: async (_transaction, input) => fixture.setAudit(input as unknown as Record<string, unknown>)
  });
  assert.equal(result.id, "created-admin");
  assert.equal(fixture.calls.filter((call) => call === "read:auditLog").length, 1);
  assert.equal(fixture.auditInput?.eventType, "ACCOUNT_CREATED");
});

test("bootstrap refuses suspicious audit rows", async () => {
  const suspicious = [
    { ...noopAudit, eventType: "ACCOUNT_CREATED" },
    { ...noopAudit, result: "FAILURE" },
    { ...noopAudit, resource: "identity.admin" },
    { ...noopAudit, message: "something else" },
    { ...noopAudit, actorUserId: "existing-user" },
    { ...noopAudit, actorEmailHash: "some-hash" },
    { ...noopAudit, metadata: { ...noopAudit.metadata, deletedCount: 1 } },
    { ...noopAudit, metadata: { ...noopAudit.metadata, deletedRateLimitCount: -1 } },
    { ...noopAudit, metadata: { ...noopAudit.metadata, source: "other" } },
    { ...noopAudit, metadata: { ...noopAudit.metadata, extra: "unexpected" } }
  ];
  for (const record of suspicious) {
    const fixture = createDatabase({ auditLog: 1 }, [record]);
    await assert.rejects(
      bootstrapFirstAdmin(validInput, {
        database: fixture.database as never,
        hashPassword: async () => "argon2:hashed",
        writeAudit: async () => assert.fail("Audit must not be written for a rejected bootstrap.")
      }),
      (error) => error instanceof FirstAdminBootstrapError && error.code === "DATABASE_NOT_VIRGIN"
    );
    assert.equal(fixture.createdUser, undefined);
  }
});

test("anonymous failed login traffic and rate-limit rows cannot exhaust first ADMIN bootstrap", async () => {
  const rows = Array.from({ length: 64 }, () => ({ ...noopAudit, eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource: "portal", message: "Login failed.", actorEmailHash: "ab".repeat(32), metadata: { source: "portal-login" } }));
  const fixture = createDatabase({ auditLog: rows.length, loginRateLimit: 64 }, rows);
  const result = await bootstrapFirstAdmin(validInput, {
    database: fixture.database as never,
    hashPassword: async () => "argon2:hashed",
    hashAdminEmail: () => "pseudonym:admin",
    writeAudit: async (_transaction, input) => fixture.setAudit(input as unknown as Record<string, unknown>)
  });
  assert.equal(result.id, "created-admin");
  assert.equal(fixture.auditInput?.eventType, "ACCOUNT_CREATED");
});

test("no-op maintenance audits cannot consume a finite prebootstrap allowance", async () => {
  const rows = Array.from({ length: 64 }, () => ({ ...noopAudit }));
  const fixture = createDatabase({ auditLog: rows.length }, rows);
  const result = await bootstrapFirstAdmin(validInput, { database: fixture.database as never, hashPassword: async () => "argon2:hashed", hashAdminEmail: () => "pseudonym:admin", writeAudit: async () => undefined });
  assert.equal(result.id, "created-admin");
});

test("bootstrap validates a large anonymous audit history in bounded pages, including its last row", async () => {
  const rows = Array.from({ length: 301 }, () => ({ ...noopAudit }));
  const fixture = createDatabase({ auditLog: rows.length }, rows);
  const result = await bootstrapFirstAdmin(validInput, {
    database: fixture.database as never,
    hashPassword: async () => "argon2:hashed",
    hashAdminEmail: () => "pseudonym:admin",
    writeAudit: async () => undefined
  });
  assert.equal(result.id, "created-admin");
  assert.equal(fixture.calls.filter((call) => call === "read:auditLog").length, 3);

  const invalid = createDatabase({ auditLog: rows.length }, [...rows.slice(0, -1), { ...noopAudit, actorUserId: "existing-user" }]);
  await assert.rejects(
    bootstrapFirstAdmin(validInput, { database: invalid.database as never, hashPassword: async () => "argon2:hashed", writeAudit: async () => assert.fail("Do not create an admin.") }),
    (error) => error instanceof FirstAdminBootstrapError && error.code === "DATABASE_NOT_VIRGIN"
  );
  assert.equal(invalid.createdUser, undefined);
});

test("expensive password hashing completes before acquiring the transaction lock", async () => {
  const fixture = createDatabase();
  let hashCompleted = false;
  await bootstrapFirstAdmin(validInput, {
    database: {
      $transaction: (callback: (tx: unknown) => Promise<unknown>) => {
        assert.equal(hashCompleted, true, "Argon2 must not consume Prisma transaction time");
        return fixture.database.$transaction(callback as never);
      }
    } as never,
    hashPassword: async () => {
      await new Promise<void>((resolve) => setImmediate(resolve));
      hashCompleted = true;
      return "argon2:hashed";
    },
    hashAdminEmail: () => "pseudonym:admin",
    writeAudit: async (_transaction, input) => fixture.setAudit(input as unknown as Record<string, unknown>)
  });
  assert.ok(hashCompleted);
});

test("bootstrap refuses any pre-existing application data and creates no ADMIN", async () => {
  for (const model of dataModels) {
    if (model === "loginRateLimit") continue; // Anonymous request counters carry no identity state.
    const fixture = createDatabase({ [model]: 1 });

    await assert.rejects(
      bootstrapFirstAdmin(validInput, {
        database: fixture.database as never,
        hashPassword: async () => "unused",
        hashAdminEmail: () => "unused",
        writeAudit: async () => assert.fail("Audit must not be written for a blocked bootstrap.")
      }),
      (error) => error instanceof FirstAdminBootstrapError && error.code === "DATABASE_NOT_VIRGIN"
    );
    assert.equal(fixture.createdUser, undefined, `No ADMIN is created when ${model} contains a row.`);
    assert.ok(!fixture.calls.includes("create:user"));
  }
});

test("bootstrap rejects weak or control-character input before opening a transaction", async () => {
  let transactionStarted = false;
  const database = {
    $transaction: async () => {
      transactionStarted = true;
      throw new Error("Unexpected transaction.");
    }
  };

  await assert.rejects(
    bootstrapFirstAdmin({ ...validInput, password: "short" }, {
      database: database as never,
      hashPassword: async () => "unused",
      hashAdminEmail: () => "unused",
      writeAudit: async () => undefined
    }),
    (error) => error instanceof FirstAdminBootstrapError && error.code === "INPUT_INVALID"
  );
  assert.equal(transactionStarted, false);

  await assert.rejects(
    bootstrapFirstAdmin({ ...validInput, displayName: "Owner\nADMIN" }, {
      database: database as never,
      hashPassword: async () => "unused",
      hashAdminEmail: () => "unused",
      writeAudit: async () => undefined
    }),
    (error) => error instanceof FirstAdminBootstrapError && error.code === "INPUT_INVALID"
  );
  assert.equal(transactionStarted, false);
});

test("interactive bootstrap requires the explicit Virki target and rejects legacy or non-production databases", () => {
  const environment = {
    NODE_ENV: "production",
    VIRKI_FIRST_INSTALL_BOOTSTRAP: "enabled",
    DATABASE_URL: "postgresql://virki_runtime@postgres:5432/virki?schema=public",
    VIRKI_AUDIT_HASH_SECRET: "a".repeat(64)
  };
  assert.doesNotThrow(() => assertProductionBootstrapContext(environment));
  assert.throws(
    () => assertProductionBootstrapContext({ ...environment, VIRKI_FIRST_INSTALL_BOOTSTRAP: undefined }),
    (error) => error instanceof FirstAdminBootstrapError && error.code === "FIRST_INSTALL_NOT_ENABLED"
  );
  assert.throws(
    () => assertProductionBootstrapContext({ ...environment, DATABASE_URL: "postgresql://virki_runtime@postgres:5432/legacy?schema=public" }),
    (error) => error instanceof FirstAdminBootstrapError && error.code === "DATABASE_TARGET_INVALID"
  );
  assert.throws(
    () => assertProductionBootstrapContext({ ...environment, NODE_ENV: "development" }),
    (error) => error instanceof FirstAdminBootstrapError && error.code === "PRODUCTION_CONTEXT_REQUIRED"
  );
});
