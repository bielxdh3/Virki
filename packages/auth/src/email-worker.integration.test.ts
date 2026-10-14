import assert from "node:assert/strict";
import { randomInt, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createDeterministicTestTransport, enqueueEmailMessage, processNextEmailMessage } from "./email";
import { runEmailWorkerLoop } from "./email-worker-loop";
import { integrationOptions, uniqueEmail } from "./integration-fixtures";

after(() => prisma.$disconnect());

const OLD_SLEEP_PER_MESSAGE_MS = 5_000;

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
