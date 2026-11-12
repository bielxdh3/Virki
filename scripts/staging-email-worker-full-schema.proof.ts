// Run ONLY inside the one-shot owned PostgreSQL 18 internal-network fixture.
// No SMTP: message dispatch goes to an in-memory deterministic transport.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma, PrismaClient } from "@virki/database";
import { assertScopedEmailWorkerRole, requireScopedEmailWorkerRole } from "../packages/auth/src/email-worker-role";
import { createDeterministicTestTransport, processNextEmailMessage } from "../packages/auth/src/email";

const workerUrl = new URL(process.env.DATABASE_URL ?? "");
const runtimeUrl = new URL(process.env.VIRKI_PROOF_RUNTIME_URL ?? "");
const migratorUrl = new URL(process.env.MIGRATION_DATABASE_URL ?? "");
const wrongUrl = new URL(process.env.VIRKI_PROOF_WRONG_URL ?? "");
const expectedHost = "postgres";
function valid(url: URL, role: string) {
  return url.hostname === expectedHost && url.username === role &&
    /^\/virki_worker_full_[a-f0-9]{12}$/u.test(url.pathname) &&
    url.search === "?schema=public" && url.port === "5432";
}
if (process.env.VIRKI_STAGING_WORKER_FULL_SCHEMA_PROOF !== "owned-internal-network" ||
    process.env.VIRKI_EMAIL_WORKER_SCOPED_ROLE !== "required" ||
    process.env.NODE_ENV !== "test" ||
    !valid(workerUrl, "virki_email_worker") ||
    !valid(runtimeUrl, "virki_runtime") ||
    !valid(migratorUrl, "virki_migrator") ||
    !valid(wrongUrl, "virki_email_worker") ||
    [workerUrl, runtimeUrl, migratorUrl, wrongUrl].some((url) =>
      url.pathname !== workerUrl.pathname || url.port !== workerUrl.port) ||
    workerUrl.password === wrongUrl.password) {
  throw new Error("Refusing non-disposable or unscoped Prisma proof target.");
}
const runtime = new PrismaClient({ datasources: { db: { url: runtimeUrl.href } } });
const migrator = new PrismaClient({ datasources: { db: { url: migratorUrl.href } } });
const wrongCredential = new PrismaClient({ datasources: { db: { url: wrongUrl.href } } });
after(async () => {
  await Promise.allSettled([prisma.$disconnect(), runtime.$disconnect(),
    migrator.$disconnect(), wrongCredential.$disconnect()]);
});

test("true SCRAM login and actual Prisma scoped worker process one mail safely", async () => {
  const [{ who, database }] = await prisma.$queryRaw<Array<{who: string; database: string}>>`
    SELECT current_user AS who, current_database() AS database
  `;
  assert.equal(who, "virki_email_worker");
  assert.equal(database, workerUrl.pathname.slice(1));
  await assertScopedEmailWorkerRole(prisma);
  await assert.rejects(wrongCredential.$queryRaw`SELECT current_user`,
    /authentication failed|P1000/iu, "wrong password must NOT authenticate under real SCRAM");
  await assert.rejects(prisma.user.findFirst({ select: { id: true } }),
    /permission denied|42501|P2010/u, "worker must not read User");
  await assert.rejects(prisma.auditLog.findFirst({ select: { id: true } }),
    /permission denied|42501|P2010/u, "worker must not read AuditLog");

  const id = randomUUID();
  await runtime.emailOutboxMessage.create({ data: {
    id, idempotencyKey: randomUUID(), kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "scope-proof@example.invalid", locale: "en",
    payload: { version: 1, publicValues: {} }, status: "QUEUED"
  } });
  await assert.rejects(prisma.emailOutboxMessage.update({
    where: { id }, data: { recipientEmail: "hijacked@example.invalid" }
  }), /permission denied|42501|P2010/u, "worker must never alter recipient");
  const { sent, transport } = createDeterministicTestTransport();
  assert.equal(await processNextEmailMessage(transport, new Date(), prisma), "sent");
  assert.deepEqual(sent.map((message) => message.to), ["scope-proof@example.invalid"]);
  const row = await runtime.emailOutboxMessage.findUniqueOrThrow({
    where: { id }, include: { deliveryAttempts: true }
  });
  assert.equal(row.status, "SENT");
  assert.equal(row.attemptCount, 1);
  assert.equal(row.deliveryAttempts.length, 1);
  assert.equal(row.deliveryAttempts[0]?.status, "SENT");
});

test("PUBLIC and MAINTAIN drift stop the scoped worker before another dispatch", async () => {
  const id = randomUUID();
  await runtime.emailOutboxMessage.create({ data: {
    id, idempotencyKey: randomUUID(), kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "drift-proof@example.invalid", locale: "en",
    payload: { version: 1, publicValues: {} }, status: "QUEUED"
  } });
  const { sent, transport } = createDeterministicTestTransport();
  const processScopedCycle = async () => {
    if (requireScopedEmailWorkerRole(process.env.VIRKI_EMAIL_WORKER_SCOPED_ROLE)) {
      await assertScopedEmailWorkerRole(prisma);
    }
    return processNextEmailMessage(transport, new Date(), prisma);
  };
  for (const { grant, revoke } of [
    { grant: 'GRANT UPDATE ("status") ON public."EmailOutboxMessage" TO PUBLIC',
      revoke: 'REVOKE UPDATE ("status") ON public."EmailOutboxMessage" FROM PUBLIC' },
    { grant: 'GRANT MAINTAIN ON public."EmailOutboxMessage" TO virki_email_worker',
      revoke: 'REVOKE MAINTAIN ON public."EmailOutboxMessage" FROM virki_email_worker' }
  ]) {
    await migrator.$executeRawUnsafe(grant);
    try {
      await assert.rejects(processScopedCycle(), /not scoped for staging/u,
        "the same gate-then-process cycle must reject privilege drift before claiming mail");
      assert.deepEqual(sent, [], "no SMTP attempt may start after a denied gate");
      assert.equal((await runtime.emailOutboxMessage.findUniqueOrThrow({ where: { id } })).status, "QUEUED");
      assert.equal(await runtime.emailDeliveryAttempt.count({ where: { messageId: id } }), 0,
        "failed role guard must not create a phantom delivery attempt");
    } finally {
      await migrator.$executeRawUnsafe(revoke);
    }
    await assertScopedEmailWorkerRole(prisma);
  }
  assert.equal(await processScopedCycle(), "sent");
  assert.deepEqual(sent.map((item) => item.to), ["drift-proof@example.invalid"]);
});

test("real scoped Prisma worker persists a failed delivery without privileged writes", async () => {
  await assertScopedEmailWorkerRole(prisma);
  const id = randomUUID();
  await runtime.emailOutboxMessage.create({ data: {
    id, idempotencyKey: randomUUID(), kind: "EMAIL_TWO_FACTOR",
    recipientEmail: "failed-proof@example.invalid", locale: "en",
    payload: { version: 1, publicValues: {} }, status: "QUEUED"
  } });
  let attempted = 0;
  const rejectedTransport = { async send() { attempted += 1; throw new Error("local fixture failure"); } };
  assert.equal(await processNextEmailMessage(rejectedTransport, new Date(), prisma), "retryable-failure");
  assert.equal(attempted, 1);
  const row = await runtime.emailOutboxMessage.findUniqueOrThrow({
    where: { id }, include: { deliveryAttempts: true }
  });
  assert.equal(row.status, "RETRYABLE_FAILURE");
  assert.equal(row.attemptCount, 1);
  assert.equal(row.deliveryAttempts.length, 1);
  assert.equal(row.deliveryAttempts[0]?.status, "FAILED");
  assert.equal(row.deliveryAttempts[0]?.errorCode, "transport-failure");
});
