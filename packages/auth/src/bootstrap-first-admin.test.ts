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

function createDatabase(overrides: Partial<Record<(typeof dataModels)[number], number>> = {}) {
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
    $queryRaw: (query: unknown) => Promise<unknown>;
  };
  transaction.user.create = async ({ data }) => {
    calls.push("create:user");
    createdUser = data;
    return { id: "created-admin" };
  };
  transaction.$queryRaw = async () => {
    calls.push("lock");
    return [];
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

test("bootstrap refuses any pre-existing application data and creates no ADMIN", async () => {
  for (const model of dataModels) {
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
