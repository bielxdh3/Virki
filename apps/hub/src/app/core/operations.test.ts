import assert from "node:assert/strict";
import test from "node:test";

import { createSingleFlightProbe, resolveBoundedCoreProbe } from "./operations";

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

test("bounds a stalled probe and reports unknown", async () => {
  assert.equal(
    await resolveBoundedCoreProbe(() => new Promise(() => undefined), 5),
    "unknown"
  );
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
