import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { errors } from "oidc-provider";
import { hashAuditSessionReference, writeAuditLogInTransaction } from "@virki/auth";
import { requireSecurityElevationInTransaction } from "@virki/auth/administration";
import { deleteProjectConnectionInTransaction, PROJECT_CONNECTION_MUTATION_ISOLATION_LEVEL, setProjectConnectionEnabledInTransaction } from "@virki/auth/oidc-connection";
import { encryptOidcClientSecret, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { prisma, type Prisma } from "@virki/database";
import { createTestUser, integrationOptions, seedAdminSessionWithElevation } from "../../../packages/auth/src/integration-fixtures";
import { PrismaOidcAdapter } from "./adapter";

type ArtifactModel = "Interaction" | "AccessToken";
type ArtifactHooks = {
  onTransaction?: (pid: number) => void;
  afterUpsert?: () => Promise<void>;
  afterDeleteMany?: () => Promise<void>;
};
type ConnectionFixture = {
  userId: string;
  connectionId: string;
  clientId: string;
  clientIdHash: string;
  grantId: string;
};

after(() => prisma.$disconnect());

for (const model of ["Interaction", "AccessToken"] as const) {
  test(`${model} writes serialize with connection deletion when the writer locks first`, integrationOptions, async () => {
    const fixture = await createFixture(model);
    const persisted = deferred();
    const releaseWriter = deferred();
    const writerTransaction = deferred<number>();
    let deletion: Promise<unknown> | undefined;
    const write = writeArtifact(fixture, model, new PrismaOidcAdapter(model, instrumentedDatabase({
      onTransaction: (pid) => writerTransaction.resolve(pid),
      afterUpsert: async () => { persisted.resolve(); await releaseWriter.promise; }
    }) as never)).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));

    try {
      const started = await Promise.race([
        writerTransaction.promise.then((pid) => ({ kind: "transaction" as const, pid })),
        write.then((outcome) => ({ kind: "finished" as const, outcome }))
      ]);
      assert.equal(started.kind, "transaction", "the adapter must persist through its connection-lock transaction");
      assert.ok(started.kind === "transaction");
      await persisted.promise;

      const deletionTransaction = deferred<number>();
      deletion = runTransaction((transaction) => deleteProjectConnectionInTransaction(transaction, fixture.connectionId), {
        onTransaction: (pid) => deletionTransaction.resolve(pid)
      });
      const deletionPid = await deletionTransaction.promise;
      await waitForBlockedPostgresQuery(deletionPid, started.pid, '"ProjectConnection"');

      releaseWriter.resolve();
      assert.equal((await write).ok, true);
      await deletion;
      assert.equal(await prisma.projectConnection.count({ where: { id: fixture.connectionId } }), 0);
      assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } }), 0);
    } finally {
      releaseWriter.resolve();
      await Promise.allSettled([write, deletion ?? Promise.resolve()]);
      await cleanupFixture(fixture);
    }
  });

  test(`${model} writes cannot recreate artifacts when connection deletion locks first`, integrationOptions, async () => {
    const fixture = await createFixture(model);
    const artifactsCleared = deferred();
    const releaseDeletion = deferred();
    const deletionTransaction = deferred<number>();
    const adapterTransaction = deferred<number>();
    let write: Promise<{ ok: boolean; error?: unknown }> | undefined;
    const deletion = runTransaction((transaction) => deleteProjectConnectionInTransaction(transaction, fixture.connectionId), {
      onTransaction: (pid) => deletionTransaction.resolve(pid),
      afterDeleteMany: async () => { artifactsCleared.resolve(); await releaseDeletion.promise; }
    }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));

    try {
      const deletionPid = await deletionTransaction.promise;
      await artifactsCleared.promise;
      write = writeArtifact(fixture, model, new PrismaOidcAdapter(model, instrumentedDatabase({
        onTransaction: (pid) => adapterTransaction.resolve(pid)
      }) as never)).then(() => ({ ok: true }), (error: unknown) => ({ ok: false, error }));

      const started = await Promise.race([
        adapterTransaction.promise.then((pid) => ({ kind: "transaction" as const, pid })),
        write.then((outcome) => ({ kind: "finished" as const, outcome }))
      ]);
      if (started.kind !== "transaction") {
        releaseDeletion.resolve();
        const deletionOutcome = await deletion;
        assert.ok(deletionOutcome.ok, describeOperationOutcome("Deletion transaction", deletionOutcome));
        assert.fail(`The ${model} writer finished before entering its transaction; expected it to wait for the deletion lock. ${describeWriteOutcome(started.outcome)}`);
      }

      const waitResult = await Promise.race([
        waitForBlockedPostgresQuery(started.pid, deletionPid, '"ProjectConnection"').then(() => ({ kind: "blocked" as const })),
        write.then((outcome) => ({ kind: "finished" as const, outcome }))
      ]);
      if (waitResult.kind !== "blocked") {
        releaseDeletion.resolve();
        const deletionOutcome = await deletion;
        assert.ok(deletionOutcome.ok, describeOperationOutcome("Deletion transaction", deletionOutcome));
        const expectedError = model === "Interaction" ? errors.InvalidClient : errors.InvalidGrant;
        assert.fail(`The ${model} writer finished before PostgreSQL reported it blocked by the deletion transaction; expected a lock wait then ${expectedError.name}. ${describeWriteOutcome(waitResult.outcome)}`);
      }

      releaseDeletion.resolve();
      const deletionOutcome = await deletion;
      assert.ok(deletionOutcome.ok, describeOperationOutcome("Connection deletion", deletionOutcome));
      const outcome = await write;
      const expectedError = model === "Interaction" ? errors.InvalidClient : errors.InvalidGrant;
      assert.equal(outcome.ok, false, `the ${model} write must reject after the connection is deleted`);
      assert.ok(!outcome.ok && outcome.error instanceof expectedError,
        `the ${model} write must reject with ${expectedError.name}, not a deadlock or other database error. ${describeWriteOutcome(outcome)}`);
      assert.equal(await prisma.projectConnection.count({ where: { id: fixture.connectionId } }), 0);
      assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } }), 0);
    } finally {
      releaseDeletion.resolve();
      await Promise.allSettled([deletion, write ?? Promise.resolve()]);
      await cleanupFixture(fixture);
    }
  });
}

test("disabling a connection clears artifacts and rejects later Interaction writes", integrationOptions, async () => {
  const fixture = await createFixture("Interaction");
  try {
    await writeArtifact(fixture, "Interaction", new PrismaOidcAdapter("Interaction"));
    assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } }), 2, "the provider Grant and Interaction should both exist");

    await runTransaction((transaction) => setProjectConnectionEnabledInTransaction(transaction, fixture.connectionId, false));
    assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } }), 0);
    await assert.rejects(writeArtifact(fixture, "Interaction", new PrismaOidcAdapter("Interaction")), /client/iu);
    assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } }), 0);
  } finally {
    await cleanupFixture(fixture);
  }
});

test("disabling a connection waits for an in-flight Interaction and then clears its artifact", integrationOptions, async () => {
  const fixture = await createFixture("Interaction");
  const persisted = deferred();
  const releaseWriter = deferred();
  const writerTransaction = deferred<number>();
  let disable: Promise<unknown> | undefined;
  const write = writeArtifact(fixture, "Interaction", new PrismaOidcAdapter("Interaction", instrumentedDatabase({
    onTransaction: (pid) => writerTransaction.resolve(pid),
    afterUpsert: async () => { persisted.resolve(); await releaseWriter.promise; }
  }) as never)).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));

  try {
    const writerStarted = await Promise.race([
      writerTransaction.promise.then((pid) => ({ kind: "transaction" as const, pid })),
      write.then((outcome) => ({ kind: "finished" as const, outcome }))
    ]);
    assert.equal(writerStarted.kind, "transaction", "the adapter must hold the common connection lock through its write");
    assert.ok(writerStarted.kind === "transaction");
    await persisted.promise;

    const disableTransaction = deferred<number>();
    disable = runTransaction((transaction) => setProjectConnectionEnabledInTransaction(transaction, fixture.connectionId, false), {
      onTransaction: (pid) => disableTransaction.resolve(pid)
    });
    const disablePid = await disableTransaction.promise;
    await waitForBlockedPostgresQuery(disablePid, writerStarted.pid, '"ProjectConnection"');

    releaseWriter.resolve();
    assert.equal((await write).ok, true);
    await disable;
    assert.equal(await prisma.projectConnection.findUniqueOrThrow({ where: { id: fixture.connectionId }, select: { enabled: true } }).then(({ enabled }) => enabled), false);
    assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } }), 0);
  } finally {
    releaseWriter.resolve();
    await Promise.allSettled([write, disable ?? Promise.resolve()]);
    await cleanupFixture(fixture);
  }
});

test("connection deletion rollback restores the connection, grant and artifacts together", integrationOptions, async () => {
  const fixture = await createFixture("Interaction");
  const admin = await createTestUser({ role: "ADMIN", label: "connection-delete-admin" });
  const elevation = await seedAdminSessionWithElevation(admin.id, "PROJECT_CONNECTION_MANAGE");
  try {
    await writeArtifact(fixture, "Interaction", new PrismaOidcAdapter("Interaction"));
    const before = await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } });
    assert.equal(before, 2);
    const auditCount = await prisma.auditLog.count({ where: { actorUserId: admin.id, eventType: "PROJECT_CONNECTION_REVOKED" } });

    await assert.rejects(runTransaction(async (transaction) => {
      const [settings] = await transaction.$queryRaw<Array<{ isolation: string }>>`SELECT current_setting('transaction_isolation') AS isolation`;
      assert.equal(settings.isolation, "read committed");
      await requireSecurityElevationInTransaction(transaction, admin.id, elevation.sessionId, "PROJECT_CONNECTION_MANAGE", new Date());
      await deleteProjectConnectionInTransaction(transaction, fixture.connectionId);
      await writeAuditLogInTransaction(transaction, {
        eventType: "PROJECT_CONNECTION_REVOKED",
        result: "SUCCESS",
        actorUserId: admin.id,
        actorRole: "ADMIN",
        sessionRef: hashAuditSessionReference(elevation.sessionId),
        resource: "project.connection",
        message: "External connection deleted and OIDC artifacts cleared.",
        metadata: { connectionRef: hashOidcIdentifier(fixture.connectionId) }
      });
      throw new Error("force transaction rollback");
    }), /force transaction rollback/u);

    assert.equal(await prisma.projectConnection.count({ where: { id: fixture.connectionId } }), 1);
    assert.equal(await prisma.userProjectGrant.count({ where: { connectionId: fixture.connectionId, userId: fixture.userId } }), 1);
    assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: fixture.clientIdHash } }), before);
    assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.id, eventType: "PROJECT_CONNECTION_REVOKED" } }), auditCount);
  } finally {
    await cleanupFixture(fixture);
    await prisma.user.deleteMany({ where: { id: admin.id } });
  }
});

async function createFixture(label: string): Promise<ConnectionFixture> {
  const user = await createTestUser({ label: `connection-delete-${label.toLowerCase()}` });
  const clientId = `client-${randomUUID()}`;
  const connection = await prisma.projectConnection.create({ data: {
    name: "Connection deletion race",
    slug: clientId,
    origin: "https://project.integration.invalid",
    clientId,
    clientSecretCiphertext: encryptOidcClientSecret(randomBytes(32).toString("base64url")),
    redirectUris: ["https://project.integration.invalid/callback"]
  } });
  await prisma.userProjectGrant.create({ data: { userId: user.id, connectionId: connection.id } });
  const fixture = {
    userId: user.id,
    connectionId: connection.id,
    clientId,
    clientIdHash: hashOidcIdentifier(clientId),
    grantId: `grant-${randomUUID()}`
  };
  await new PrismaOidcAdapter("Grant").upsert(fixture.grantId, { accountId: user.id, clientId } as never, 300);
  return fixture;
}

async function writeArtifact(fixture: ConnectionFixture, model: ArtifactModel, adapter: PrismaOidcAdapter): Promise<void> {
  const payload = model === "Interaction"
    ? { params: { client_id: fixture.clientId } }
    : { accountId: fixture.userId, clientId: fixture.clientId, grantId: fixture.grantId };
  await adapter.upsert(randomBytes(24).toString("base64url"), payload as never, 300);
}

async function runTransaction<T>(
  work: (transaction: Prisma.TransactionClient) => Promise<T>,
  hooks: ArtifactHooks = {}
): Promise<T> {
  return prisma.$transaction(async (transaction) => {
    const [backend] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    hooks.onTransaction?.(backend.pid);
    return work(instrumentTransaction(transaction, hooks));
  }, { isolationLevel: PROJECT_CONNECTION_MUTATION_ISOLATION_LEVEL, timeout: 10_000 });
}

function instrumentedDatabase(hooks: ArtifactHooks) {
  return {
    oidcArtifact: instrumentArtifactDelegate(prisma.oidcArtifact, hooks),
    projectConnection: prisma.projectConnection,
    $transaction: (operation: (transaction: unknown) => Promise<void>, options?: unknown) => prisma.$transaction(async (transaction) => {
      const [backend] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
      hooks.onTransaction?.(backend.pid);
      return operation(instrumentTransaction(transaction, hooks));
    }, options as never)
  };
}

function instrumentTransaction(transaction: Prisma.TransactionClient, hooks: ArtifactHooks): Prisma.TransactionClient {
  const oidcArtifact = instrumentArtifactDelegate(transaction.oidcArtifact, hooks);
  return new Proxy(transaction, {
    get(target, property, receiver) {
      if (property === "oidcArtifact") return oidcArtifact;
      return Reflect.get(target, property, receiver);
    }
  });
}

function instrumentArtifactDelegate<T extends object>(delegate: T, hooks: ArtifactHooks): T {
  return new Proxy(delegate, {
    get(target, property, receiver) {
      const method = Reflect.get(target, property, receiver);
      if (property === "upsert" && hooks.afterUpsert) {
        return async (...args: unknown[]) => {
          const result = await (method as (...values: unknown[]) => unknown).apply(target, args);
          await hooks.afterUpsert?.();
          return result;
        };
      }
      if (property === "deleteMany" && hooks.afterDeleteMany) {
        return async (...args: unknown[]) => {
          const result = await (method as (...values: unknown[]) => unknown).apply(target, args);
          await hooks.afterDeleteMany?.();
          return result;
        };
      }
      return method;
    }
  });
}

async function waitForBlockedPostgresQuery(waiterPid: number, blockerPid: number, queryFragment: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const [activity] = await prisma.$queryRaw<Array<{ blocked: boolean }>>`
      SELECT EXISTS (
        SELECT 1 FROM pg_stat_activity
        WHERE pid = ${waiterPid}
          AND wait_event_type = 'Lock'
          AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
          AND query LIKE ${`%${queryFragment}%`}
      ) AS blocked
    `;
    if (activity.blocked) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  const [diagnostics] = await prisma.$queryRaw<Array<{
    waiterState: string | null;
    waiterWaitEventType: string | null;
    waiterWaitEvent: string | null;
    waiterBlockers: number[] | null;
    blockerState: string | null;
    blockerWaitEventType: string | null;
    blockerWaitEvent: string | null;
    blockerBlockers: number[] | null;
  }>>`
    SELECT waiter.state AS "waiterState",
      waiter.wait_event_type AS "waiterWaitEventType",
      waiter.wait_event AS "waiterWaitEvent",
      pg_blocking_pids(waiter.pid) AS "waiterBlockers",
      blocker.state AS "blockerState",
      blocker.wait_event_type AS "blockerWaitEventType",
      blocker.wait_event AS "blockerWaitEvent",
      pg_blocking_pids(blocker.pid) AS "blockerBlockers"
    FROM (SELECT 1) AS seed
    LEFT JOIN pg_stat_activity AS waiter ON waiter.pid = ${waiterPid}
    LEFT JOIN pg_stat_activity AS blocker ON blocker.pid = ${blockerPid}
  `;
  throw new Error(`Timed out waiting for PostgreSQL lock wait on ${queryFragment}. Safe lock diagnostics: ${JSON.stringify({ waiterPid, blockerPid, ...diagnostics })}`);
}

function describeWriteOutcome(outcome: { ok: boolean; error?: unknown }): string {
  if (outcome.ok) return "The writer unexpectedly succeeded.";
  return `The writer rejected. ${describeFailure(outcome.error)}`;
}

function describeOperationOutcome(operation: string, outcome: { ok: true } | { ok: false; error: unknown }): string {
  return outcome.ok ? `${operation} unexpectedly succeeded.` : `${operation} failed. ${describeFailure(outcome.error)}`;
}

function describeFailure(error: unknown): string {
  if (!error || typeof error !== "object") return `The operation failed with a non-error value of type ${typeof error}.`;
  const candidate = error as { name?: unknown; code?: unknown; meta?: { code?: unknown }; cause?: { code?: unknown } };
  const diagnostics = {
    errorType: typeof candidate.name === "string" ? candidate.name : "unknown",
    code: typeof candidate.code === "string" ? candidate.code : undefined,
    sqlState: typeof candidate.meta?.code === "string"
      ? candidate.meta.code
      : typeof candidate.cause?.code === "string" ? candidate.cause.code : undefined
  };
  return `Safe error diagnostics: ${JSON.stringify(diagnostics)}`;
}

async function cleanupFixture(fixture: ConnectionFixture): Promise<void> {
  await prisma.oidcArtifact.deleteMany({ where: { clientIdHash: fixture.clientIdHash } });
  await prisma.projectConnection.deleteMany({ where: { id: fixture.connectionId } });
  await prisma.user.deleteMany({ where: { id: fixture.userId } });
}

function deferred(): { promise: Promise<void>; resolve: () => void };
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void };
function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
