import assert from "node:assert/strict";
import test from "node:test";

import { resolveBoundedCoreProbe } from "./operations";

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
