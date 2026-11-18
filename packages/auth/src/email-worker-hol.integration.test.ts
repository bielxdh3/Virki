// EXCLUSIVE integration suite. Never run in the generic shared database: its
// scheduling assertions require the runner to have provisioned a new database.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createDeterministicTestTransport, enqueueEmailMessage, processNextEmailMessage } from "./email";
import { runEmailWorkerLoop } from "./email-worker-loop";
import { integrationOptions, uniqueEmail } from "./integration-fixtures";

after(() => prisma.$disconnect());

test("three exhausted head rows never delay a genuine queued OTP", integrationOptions, async () => {
  assert.equal(process.env.VIRKI_EMAIL_WORKER_DEDICATED_DB, "confirmed",
    "an exclusive disposable worker database must be verified by the runner");
  assert.equal(await prisma.emailOutboxMessage.count(), 0,
    "the entire outbox must be virgin, not merely free of currently eligible messages");
  assert.equal(await prisma.emailDeliveryAttempt.count(), 0);

  const now = new Date();
  const recipient = uniqueEmail("worker-after-exhausted");
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
    "exhausted attempts must not cause false idle polls before the real OTP");
  assert.deepEqual(sleeps, [], "committed reconciliation cannot trigger idle or failure sleeps");
  assert.deepEqual(sent.map((item) => item.to), [recipient]);
  const sentRow = await prisma.emailOutboxMessage.findFirstOrThrow({
    where: { recipientEmail: recipient },
    select: { status: true, attemptCount: true, deliveryAttempts: { select: { attempt: true, status: true } } }
  });
  assert.equal(sentRow.status, "SENT");
  assert.equal(sentRow.attemptCount, 1);
  assert.deepEqual(sentRow.deliveryAttempts, [{ attempt: 1, status: "SENT" }]);
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

test("concurrent workers cannot both claim or deliver the same OTP", integrationOptions, async () => {
  assert.equal(process.env.VIRKI_EMAIL_WORKER_DEDICATED_DB, "confirmed");
  const recipient = uniqueEmail("concurrent-worker");
  await enqueueEmailMessage({ idempotencyKey: randomUUID(), kind: "EMAIL_TWO_FACTOR",
    recipientEmail: recipient, locale: "en",
    payload: { publicValues: {}, protectedValues: { code: "567890" } } });
  const { sent, transport } = createDeterministicTestTransport();
  const now = new Date();
  // Synchronize two ACTUAL PostgreSQL transactions immediately after their
  // SELECT of the same pending row and BEFORE either compare-and-swap UPDATE.
  // Without this barrier, both promises could run serially and misleadingly
  // report `sent, idle`, never exercising the losing-CAS branch.
  let selectedByWorkers = 0;
  let releaseSelections: () => void = () => {};
  let rejectSelections: (error: Error) => void = () => {};
  const selectionsReady = new Promise<void>((resolve, reject) => {
    releaseSelections = resolve;
    rejectSelections = reject;
  });
  const selectionTimeout = setTimeout(() => rejectSelections(new Error("Both physical workers did not select the same OTP")), 10_000);
  const racingDatabase = {
    $transaction: (run: (transaction: unknown) => Promise<unknown>) => prisma.$transaction(async (transaction) => run({
      emailOutboxMessage: {
        findFirst: async (query: unknown) => {
          const candidate = await transaction.emailOutboxMessage.findFirst(query as never);
          if (candidate?.recipientEmail === recipient) {
            selectedByWorkers += 1;
            if (selectedByWorkers === 2) {
              clearTimeout(selectionTimeout);
              releaseSelections();
            }
            await selectionsReady;
          }
          return candidate;
        },
        updateMany: (query: unknown) => transaction.emailOutboxMessage.updateMany(query as never)
      },
      emailDeliveryAttempt: transaction.emailDeliveryAttempt
    }))
  } as never;
  const outcomes = await Promise.all([
    processNextEmailMessage(transport, now, racingDatabase),
    processNextEmailMessage(transport, now, racingDatabase)
  ]);
  clearTimeout(selectionTimeout);
  assert.equal(selectedByWorkers, 2, "two real workers must race on the same eligible database row");
  assert.deepEqual([...outcomes].sort(), ["contended", "sent"],
    "exactly one worker wins the CAS; the other must lose, not observe an empty queue");
  assert.deepEqual(sent.map((message) => message.to), [recipient]);
  const row = await prisma.emailOutboxMessage.findFirstOrThrow({ where: { recipientEmail: recipient },
    select: { status: true, attemptCount: true, deliveryAttempts: { select: { attempt: true, status: true } } } });
  assert.equal(row.status, "SENT");
  assert.equal(row.attemptCount, 1);
  assert.deepEqual(row.deliveryAttempts, [{ attempt: 1, status: "SENT" }]);
});
