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
