import assert from "node:assert/strict";
import test from "node:test";

import {
  createSingleFlightProbe,
  getCoreOperationsSnapshot,
  resolveBoundedCoreProbe
} from "./operations";

test("marks a completed probe as verified", async () => {
  assert.equal(await resolveBoundedCoreProbe(async () => true, 50), "verified");
});

test("maps probe failures to unknown without leaking the error", async () => {
  assert.equal(
    await resolveBoundedCoreProbe(async () => {
      throw new Error("private failure detail");
    }, 50),
    "unknown"
  );
});

test("maps synchronous failures to unknown without rejecting", async () => {
  assert.equal(
    await resolveBoundedCoreProbe(() => {
      throw new Error("private synchronous failure detail");
    }, 50),
    "unknown"
  );
});

test("bounds a stalled probe and reports unknown", async () => {
  const startedAt = Date.now();
  assert.equal(
    await resolveBoundedCoreProbe(() => new Promise(() => undefined), 5),
    "unknown"
  );
  assert.equal(Date.now() - startedAt < 250, true);
});

test("coalesces concurrent probes and starts a new probe after settlement", async () => {
  let invocationCount = 0;
  let finishProbe: (() => void) | undefined;
  const sharedProbe = createSingleFlightProbe(
    () =>
      new Promise<void>((resolve) => {
        invocationCount += 1;
        finishProbe = resolve;
      })
  );

  const first = sharedProbe();
  const second = sharedProbe();
  await Promise.resolve();

  assert.equal(first, second);
  assert.equal(invocationCount, 1);

  finishProbe?.();
  await first;
  const third = sharedProbe();
  await Promise.resolve();

  assert.equal(invocationCount, 2);
  finishProbe?.();
  await third;
});

test("repeated timeouts share one unresolved probe instead of accumulating work", async () => {
  let invocationCount = 0;
  const stalledProbe = createSingleFlightProbe(() => {
    invocationCount += 1;
    return new Promise(() => undefined);
  });

  const results = await Promise.all(
    Array.from({ length: 20 }, () => resolveBoundedCoreProbe(stalledProbe, 5))
  );

  assert.equal(results.every((result) => result === "unknown"), true);
  assert.equal(invocationCount, 1);
});

test("snapshot remains safe and renderable when the database probe fails", async () => {
  const privateDetail = "synthetic-private-connection-detail";
  const snapshot = await getCoreOperationsSnapshot(async () => {
    throw new Error(privateDetail);
  }, 20);

  assert.deepEqual(snapshot, {
    hubRequest: "verified",
    authenticatedSession: "verified",
    database: "unknown"
  });
  assert.equal(JSON.stringify(snapshot).includes(privateDetail), false);
  assert.deepEqual(Object.keys(snapshot).sort(), [
    "authenticatedSession",
    "database",
    "hubRequest"
  ]);
});
