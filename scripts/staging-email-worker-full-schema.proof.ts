// Run ONLY inside the one-shot owned PostgreSQL 18 internal-network fixture.
// No SMTP: message dispatch goes to an in-memory deterministic transport.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { after, test } from "node:test";
import { prisma, PrismaClient } from "@virki/database";
import { assertScopedEmailWorkerRole, requireScopedEmailWorkerRole } from "../packages/auth/src/email-worker-role";
import { createDeterministicTestTransport, enqueueEmailMessageForClient, processNextEmailMessage } from "../packages/auth/src/email";
import { createLoopbackSmtpSink } from "./integration/loopback-smtp-sink.mjs";

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

test("actual scoped worker process sends over verified loopback STARTTLS AUTH only", async () => {
  await assertScopedEmailWorkerRole(prisma);
  assert.equal(existsSync("/proc/self/ns/net"), true, "SMTP fixture must execute inside the owned Linux network");
  assert.equal(readFileSync("/proc/net/route", "utf8").split(/\r?\n/u).slice(1)
    .some((line) => /^\S+\s+00000000\s+/u.test(line)), false,
  "isolated Docker SMTP fixture must have no default IPv4 route");
  const sender = "wire-sender@integration.invalid";
  const recipient = "scope-wire@integration.invalid";
  const smtpUser = "smtp-wire@integration.invalid";
  const smtpPassword = randomBytes(32).toString("hex");
  assert.equal(process.env.VIRKI_SCOPED_SMTP_CERT_DIR, "/app/.virki-scoped-smtp");
  const ca = path.join(process.env.VIRKI_SCOPED_SMTP_CERT_DIR, "ca.pem");
  const certificatePath = path.join(process.env.VIRKI_SCOPED_SMTP_CERT_DIR, "server.pem");
  const privateKeyPath = path.join(process.env.VIRKI_SCOPED_SMTP_CERT_DIR, "server.key");
  let sink: Awaited<ReturnType<typeof createLoopbackSmtpSink>> | undefined;
  let worker: ReturnType<typeof spawn> | undefined;
  try {
    sink = await createLoopbackSmtpSink({
      certificate: readFileSync(certificatePath), privateKey: readFileSync(privateKeyPath),
      username: smtpUser, password: smtpPassword, recipient
    });
    const outbox = await enqueueEmailMessageForClient(runtime, {
      idempotencyKey: randomUUID(), kind: "EMAIL_TWO_FACTOR", recipientEmail: recipient,
      locale: "en", payload: { publicValues: {}, protectedValues: { code: "987654" } }
    });
    assert.equal(outbox.status, "QUEUED");
    const env = {
      NODE_ENV: "test", DATABASE_URL: workerUrl.href,
      VIRKI_EMAIL_WORKER_SCOPED_ROLE: "required",
      VIRKI_EMAIL_OUTBOX_KEY: process.env.VIRKI_EMAIL_OUTBOX_KEY ?? "",
      VIRKI_EMAIL_TRANSPORT: "smtp",
      VIRKI_EMAIL_SMTP_HOST: "127.0.0.1",
      VIRKI_EMAIL_SMTP_PORT: String(sink.port), VIRKI_EMAIL_SMTP_SECURE: "false",
      VIRKI_EMAIL_SMTP_USER: smtpUser, VIRKI_EMAIL_SMTP_PASSWORD: smtpPassword,
      VIRKI_EMAIL_FROM: sender, NODE_EXTRA_CA_CERTS: ca,
      VIRKI_EMAIL_MIN_SEND_INTERVAL_MS: "250",
      VIRKI_PORTAL_URL: "http://localhost:3000", VIRKI_HUB_URL: "http://localhost:3001",
      PATH: "/usr/bin:/bin", LANG: "C"
    };
    worker = spawn(process.execPath,
      ["node_modules/tsx/dist/cli.mjs", "packages/auth/src/email-worker.ts"],
      { cwd: "/app", env, stdio: "ignore" });
    const receipt = await sink.received;
    assert.equal(receipt.code, "987654");
    assert.deepEqual(sink.observations(), { accepted: 1, authenticated: 1, upgraded: 1 },
      "real worker must authenticate with STARTTLS before one exact message");
    let outcome: {
      status: string;
      attemptCount: number;
      deliveryAttempts: Array<{ status: string; smtpHeaderMessageId: string | null }>;
    } | null = null;
    for (let retry = 0; retry < 80; retry += 1) {
      outcome = await runtime.emailOutboxMessage.findUnique({
        where: { id: outbox.id }, include: { deliveryAttempts: true }
      });
      if (outcome?.status === "SENT") break;
      if (worker.exitCode !== null) throw new Error("Actual scoped worker exited before SMTP persistence.");
      await delay(100);
    }
    assert.equal(outcome?.status, "SENT");
    assert.equal(outcome?.attemptCount, 1);
    assert.equal(outcome?.deliveryAttempts.length, 1);
    assert.equal(outcome?.deliveryAttempts[0]?.status, "SENT");
    assert.equal(outcome?.deliveryAttempts[0]?.smtpHeaderMessageId, receipt.messageId);
    await assertScopedEmailWorkerRole(prisma);
  } finally {
    if (worker && worker.exitCode === null) {
      const stopped = once(worker, "exit").then(() => true);
      worker.kill("SIGTERM");
      if (!await Promise.race([stopped, delay(2_000).then(() => false)])) {
        worker.kill("SIGKILL");
        await Promise.race([stopped, delay(2_000)]);
      }
    }
    if (sink) await sink.close();
  }
});
