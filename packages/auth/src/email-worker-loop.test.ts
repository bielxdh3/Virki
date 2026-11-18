import assert from "node:assert/strict";
import test from "node:test";
import {
  EMAIL_WORKER_FAILURE_PAUSE_MS,
  EMAIL_WORKER_IDLE_POLL_MS,
  parseEmailSendIntervalMs,
  runEmailWorkerLoop,
  type EmailProcessOutcome
} from "./email-worker-loop";

type Step = EmailProcessOutcome | Error;

// Scripted outcomes; the run ends in the sleep that follows the final scripted step.
function harness(steps: Step[]) {
  const sleeps: number[] = [];
  let calls = 0;
  let stopped = false;

  return {
    sleeps,
    get calls() {
      return calls;
    },
    run(extra: Partial<Parameters<typeof runEmailWorkerLoop>[0]> = {}) {
      return runEmailWorkerLoop({
        processNext: async () => {
          calls += 1;
          const step = steps.shift();
          if (step instanceof Error) throw step;
          return step ?? "idle";
        },
        sleep: async (milliseconds) => {
          sleeps.push(milliseconds);
          stopped = steps.length === 0;
        },
        isStopping: () => stopped,
        ...extra
      });
    }
  };
}

test("a backlog of sent messages drains without idle or failure pauses", async () => {
  const backlog: Step[] = Array.from({ length: 100 }, () => "sent" as const);
  const loop = harness([...backlog, "idle"]);

  await loop.run({ sendIntervalMs: 250 });

  assert.equal(loop.calls, 101);
  assert.deepEqual(loop.sleeps.slice(0, 100), Array.from({ length: 100 }, () => 250));
  assert.equal(loop.sleeps[100], EMAIL_WORKER_IDLE_POLL_MS);
  assert.equal(loop.sleeps.length, 101);
});

test("sent messages are not delayed when the send interval is zero", async () => {
  const loop = harness(["sent", "sent", "idle"]);

  await loop.run({ sendIntervalMs: 0 });

  assert.deepEqual(loop.sleeps, [EMAIL_WORKER_IDLE_POLL_MS]);
});

test("terminalized exhausted outbox items do not masquerade as an empty queue", async () => {
  const loop = harness(["reconciled", "reconciled", "sent", "idle"]);
  await loop.run({ sendIntervalMs: 0 });
  assert.equal(loop.calls, 4);
  assert.deepEqual(loop.sleeps, [EMAIL_WORKER_IDLE_POLL_MS],
    "cleaned-up exhausted rows must not each cause a five-second idle sleep");
});

test("a lost claim race pauses briefly rather than sleeping as an empty queue", async () => {
  const loop = harness(["contended", "sent", "idle"]);
  await loop.run({ sendIntervalMs: 0 });
  assert.equal(loop.calls, 3);
  assert.deepEqual(loop.sleeps, [EMAIL_WORKER_FAILURE_PAUSE_MS, EMAIL_WORKER_IDLE_POLL_MS]);
});

test("an idle queue waits the idle poll interval, five seconds by default", async () => {
  const loop = harness(["idle"]);

  await loop.run();

  assert.equal(EMAIL_WORKER_IDLE_POLL_MS, 5_000);
  assert.deepEqual(loop.sleeps, [5_000]);
});

test("retryable and terminal failures pause for the failure interval", async () => {
  const loop = harness(["retryable-failure", "terminal-failure", "idle"]);

  await loop.run({ failurePollMs: 1_000 });

  assert.equal(EMAIL_WORKER_FAILURE_PAUSE_MS, 1_000);
  assert.deepEqual(loop.sleeps, [1_000, 1_000, 5_000]);
});

test("a stop request observed after processing ends the loop without another call or sleep", async () => {
  let stopping = false;
  let calls = 0;

  await runEmailWorkerLoop({
    processNext: async () => {
      calls += 1;
      stopping = true;
      return "sent";
    },
    sleep: async () => {
      throw new Error("no sleep expected");
    },
    isStopping: () => stopping
  });

  assert.equal(calls, 1);
});

test("a stop request during a sleep ends the loop before the next message", async () => {
  let stopping = false;
  let calls = 0;

  await runEmailWorkerLoop({
    processNext: async () => {
      calls += 1;
      return "idle";
    },
    sleep: async () => {
      stopping = true;
    },
    isStopping: () => stopping
  });

  assert.equal(calls, 1);
});

test("a thrown error is reported, pauses for the failure interval and the loop continues", async () => {
  const loop = harness([new Error("database unavailable"), "sent", "idle"]);
  const reported: unknown[] = [];

  await loop.run({ sendIntervalMs: 250, failurePollMs: 1_000, onIterationError: (error) => reported.push(error) });

  assert.equal(reported.length, 1);
  assert.equal((reported[0] as Error).message, "database unavailable");
  assert.equal(loop.calls, 3);
  assert.deepEqual(loop.sleeps, [1_000, 250, 5_000]);
});

test("the send interval accepts integers from 0 to 60000 and falls back otherwise", () => {
  assert.equal(parseEmailSendIntervalMs(undefined), 250);
  assert.equal(parseEmailSendIntervalMs(""), 250);
  assert.equal(parseEmailSendIntervalMs("0"), 0);
  assert.equal(parseEmailSendIntervalMs(" 1500 "), 1500);
  assert.equal(parseEmailSendIntervalMs("60000"), 60_000);
  assert.equal(parseEmailSendIntervalMs("60001"), 250);
  assert.equal(parseEmailSendIntervalMs("-1"), 250);
  assert.equal(parseEmailSendIntervalMs("1.5"), 250);
  assert.equal(parseEmailSendIntervalMs("fast"), 250);
});
