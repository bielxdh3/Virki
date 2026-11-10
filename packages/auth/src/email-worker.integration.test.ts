import assert from "node:assert/strict";
import { randomInt, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { claimNextEmailMessage, createDeterministicTestTransport, enqueueEmailMessage, processNextEmailMessage } from "./email";
import { runEmailWorkerLoop } from "./email-worker-loop";
import { integrationOptions, uniqueEmail } from "./integration-fixtures";

after(() => prisma.$disconnect());

const OLD_SLEEP_PER_MESSAGE_MS = 5_000;

test("processing messages with no lease are reclaimed once and stale finalizers are fenced", integrationOptions, async () => {
  const now = new Date("2026-10-19T12:00:00.000Z");
  const message = await prisma.emailOutboxMessage.create({
    data: {
      idempotencyKey: randomUUID(),
      kind: "EMAIL_TWO_FACTOR",
      recipientEmail: uniqueEmail("outbox-missing-lease"),
      locale: "en",
      payload: { publicValues: {}, protectedValues: {} },
      status: "PROCESSING",
      attemptCount: 1,
      availableAt: new Date(0),
      processingLeaseExpiresAt: null,
      createdAt: new Date(0),
      updatedAt: new Date(0)
    },
    select: { id: true }
  });

  const reclaimed = await claimNextEmailMessage(now);
  assert.equal(reclaimed?.id, message.id);
  assert.equal(reclaimed?.attemptCount, 2);
  assert.deepEqual(await prisma.emailDeliveryAttempt.findMany({ where: { messageId: message.id }, select: { attempt: true, status: true, errorCode: true } }), [
    { attempt: 1, status: "FAILED", errorCode: "worker-interrupted" }
  ]);

  const staleFinalizer = await prisma.emailOutboxMessage.updateMany({
    where: { id: message.id, status: "PROCESSING", attemptCount: 1 },
    data: { status: "SENT", sentAt: now, processingLeaseExpiresAt: null }
  });
  assert.equal(staleFinalizer.count, 0);
  const current = await prisma.emailOutboxMessage.findUniqueOrThrow({ where: { id: message.id }, select: { status: true, attemptCount: true, processingLeaseExpiresAt: true } });
  assert.equal(current.status, "PROCESSING");
  assert.equal(current.attemptCount, 2);
  assert.ok(current.processingLeaseExpiresAt && current.processingLeaseExpiresAt > now);
  // This deliberately stale synthetic row must not pollute later, unrelated
  // benchmark batches. Delete ONLY the fixture created above in this DB.
  await prisma.$transaction([
    prisma.emailDeliveryAttempt.deleteMany({ where: { messageId: message.id } }),
    prisma.emailOutboxMessage.delete({ where: { id: message.id } })
  ]);
});

// Global outbox scheduling is intentional in production. This precise-order
// physical regression needs a freshly created exclusive disposable DB, not
// the shared multi-file DB used by the generic integration runner.
const isolatedWorkerOptions = {
  skip: integrationOptions.skip || (process.env.VIRKI_EMAIL_WORKER_DEDICATED_DB === "confirmed"
    ? false : "requires an exclusive, newly migrated disposable worker database")
};

test("exhausted head rows are reconciled without an idle pause before a queued OTP", isolatedWorkerOptions, async () => {
  const now = new Date();
  const recipient = uniqueEmail("worker-after-exhausted");
  const eligibleBefore = await prisma.emailOutboxMessage.count({
    where: { OR: [
      { status: { in: ["QUEUED", "RETRYABLE_FAILURE"] }, availableAt: { lte: now } },
      { status: "PROCESSING", processingLeaseExpiresAt: { lte: now } },
      { status: "PROCESSING", processingLeaseExpiresAt: null }
    ] }
  });
  assert.equal(eligibleBefore, 0, "this scheduling test requires a new dedicated disposable outbox");

  const exhaustedIds: string[] = [];
  for (let i = 0; i < 3; i += 1) {
    const row = await prisma.emailOutboxMessage.create({
      data: {
        idempotencyKey: randomUUID(), kind: "EMAIL_TWO_FACTOR",
        recipientEmail: uniqueEmail(`exhausted-${i}`), locale: "en",
        payload: { publicValues: {}, protectedValues: {} },
        status: "PROCESSING", attemptCount: 5, availableAt: new Date(0),
        processingLeaseExpiresAt: new Date(now.getTime() - 60_000),
        createdAt: new Date(i), updatedAt: new Date(i)
      }, select: { id: true }
    });
    exhaustedIds.push(row.id);
  }
  await enqueueEmailMessage({ idempotencyKey: randomUUID(), kind: "EMAIL_TWO_FACTOR",
    recipientEmail: recipient, locale: "en",
    payload: { publicValues: {}, protectedValues: { code: "000123" } } });

  const { sent, transport } = createDeterministicTestTransport();
  const outcomes: string[] = [];
  const sleeps: number[] = [];
  await runEmailWorkerLoop({
    processNext: async () => {
      const outcome = await processNextEmailMessage(transport);
      outcomes.push(outcome);
      return outcome;
    },
    sleep: async (ms) => { sleeps.push(ms); },
    isStopping: () => sent.some((item) => item.to === recipient) || outcomes.length >= 12,
    sendIntervalMs: 0
  });

  assert.deepEqual(outcomes, ["reconciled", "reconciled", "reconciled", "sent"],
    "three exhausted rows must not cause three false idle polls before the real OTP");
  assert.deepEqual(sleeps, [], "no idle, retry or failure delay is justified by successful reconciliation");
  assert.deepEqual(sent.map((item) => item.to), [recipient]);
  const terminalized = await prisma.emailOutboxMessage.findMany({
    where: { id: { in: exhaustedIds } }, select: { status: true, attemptCount: true,
      deliveryAttempts: { select: { attempt: true, status: true, errorCode: true } } }
  });
  assert.equal(terminalized.length, 3);
  for (const row of terminalized) {
    assert.equal(row.status, "TERMINAL_FAILURE");
    assert.equal(row.attemptCount, 5);
    assert.deepEqual(row.deliveryAttempts, [{ attempt: 5, status: "FAILED", errorCode: "worker-interrupted" }]);
  }
});

async function drainBatch(count: number) {
  const recipients = Array.from({ length: count }, (_, index) => uniqueEmail(`worker-batch-${index}`));
  const codes = new Map(recipients.map((recipient) => [recipient, randomInt(0, 1_000_000)]));
  for (const recipient of recipients) {
    await enqueueEmailMessage({
      idempotencyKey: randomUUID(),
      kind: "EMAIL_TWO_FACTOR",
      recipientEmail: recipient,
      locale: "en",
      payload: {
        publicValues: { displayName: "Integration" },
        protectedValues: { code: String(codes.get(recipient)).padStart(6, "0") }
      }
    });
  }

  const ours = new Set(recipients);
  const { sent, transport } = createDeterministicTestTransport();
  const maxCalls = count * 3 + 50;
  let calls = 0;
  let iterationErrors = 0;
  const started = Date.now();

  await runEmailWorkerLoop({
    processNext: () => {
      calls += 1;
      return processNextEmailMessage(transport);
    },
    sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    isStopping: () => {
      const reached = sent.filter((message) => ours.has(message.to)).length === count;
      return reached || calls > maxCalls;
    },
    sendIntervalMs: 0,
    onIterationError: () => {
      iterationErrors += 1;
    }
  });
  const elapsedMs = Date.now() - started;

  const rows = await prisma.emailOutboxMessage.findMany({
    where: { recipientEmail: { in: recipients } },
    select: {
      recipientEmail: true,
      status: true,
      attemptCount: true,
      sentAt: true,
      deliveryAttempts: { select: { attempt: true, status: true } }
    }
  });
  return { recipients, sent, rows, calls, elapsedMs, iterationErrors, maxCalls };
}

function assertBatchDrained(result: Awaited<ReturnType<typeof drainBatch>>, count: number) {
  assert.ok(result.calls <= result.maxCalls, "the worker reached the batch without stalling");
  assert.equal(result.iterationErrors, 0);
  assert.equal(result.rows.length, count);
  for (const row of result.rows) {
    assert.equal(row.status, "SENT", `${row.recipientEmail} is SENT`);
    assert.equal(row.attemptCount, 1, `${row.recipientEmail} was attempted once`);
    assert.ok(row.sentAt, `${row.recipientEmail} has a sent timestamp`);
    assert.deepEqual(row.deliveryAttempts.map((attempt) => [attempt.attempt, attempt.status]), [[1, "SENT"]]);
  }

  const deliveredTo = result.sent.map((message) => message.to).filter((to) => result.recipients.includes(to));
  assert.equal(deliveredTo.length, count, "each recipient is delivered exactly once");
  assert.equal(new Set(deliveredTo).size, count);
}

for (const count of [20, 50, 100]) {
  test(`the worker drains a backlog of ${count} queued messages once each without fixed per-message delays`, integrationOptions, async () => {
    const result = await drainBatch(count);
    assertBatchDrained(result, count);

    const oldWorkerMinimumMs = count * OLD_SLEEP_PER_MESSAGE_MS;
    console.log(`email-worker backlog of ${count}: ${result.elapsedMs} ms over ${result.calls} iterations (old fixed-poll minimum ${oldWorkerMinimumMs} ms)`);
    assert.ok(result.elapsedMs < oldWorkerMinimumMs / 10, `drained ${count} messages in ${result.elapsedMs} ms`);
  });
}
