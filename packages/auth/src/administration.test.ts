import assert from "node:assert/strict";
import test from "node:test";
import { resolveElevationDuration } from "./administration";

test("elevation duration requires explicit bounded or confirmed manual mode", () => {
  const now = new Date("2026-08-01T10:00:00.000Z");
  assert.deepEqual(resolveElevationDuration({ kind: "TIMED", minutes: 60 }, now), { manualUntilRevoked: false, expiresAt: new Date("2026-08-01T11:00:00.000Z") });
  assert.equal(resolveElevationDuration({ kind: "MANUAL", confirmed: true }, now).manualUntilRevoked, true);
  assert.throws(() => resolveElevationDuration({ kind: "MANUAL", confirmed: false }, now));
  assert.throws(() => resolveElevationDuration({ kind: "TIMED", minutes: 30 as never }, now));
});
