import assert from "node:assert/strict";
import test from "node:test";
import {
  ELEVATION_SCOPES,
  ELEVATION_SCOPE_ACTIONS,
  UI_ELEVATION_SCOPES,
  isElevationCeremonyOpen,
  resolveElevationDuration
} from "./administration";

test("an elevation email code expires after ten minutes even when the elevation itself is long-lived", () => {
  const sentAt = new Date("2026-08-01T10:00:00.000Z");
  const manual = resolveElevationDuration({ kind: "MANUAL", confirmed: true }, sentAt);
  const day = resolveElevationDuration({ kind: "TIMED", minutes: 1440 }, sentAt);
  for (const { expiresAt } of [manual, day]) {
    const ceremony = { createdAt: sentAt, expiresAt };
    assert.equal(isElevationCeremonyOpen(ceremony, new Date("2026-08-01T10:09:59.000Z")), true);
    assert.equal(isElevationCeremonyOpen(ceremony, new Date("2026-08-01T10:10:00.000Z")), false);
    assert.equal(isElevationCeremonyOpen(ceremony, new Date("2026-08-02T09:00:00.000Z")), false);
  }
  assert.equal(isElevationCeremonyOpen({ createdAt: sentAt, expiresAt: new Date("2026-08-01T10:05:00.000Z") }, new Date("2026-08-01T10:06:00.000Z")), false);
});

test("elevation duration requires explicit bounded or confirmed manual mode", () => {
  const now = new Date("2026-08-01T10:00:00.000Z");
  assert.deepEqual(resolveElevationDuration({ kind: "TIMED", minutes: 60 }, now), { manualUntilRevoked: false, expiresAt: new Date("2026-08-01T11:00:00.000Z") });
  assert.equal(resolveElevationDuration({ kind: "MANUAL", confirmed: true }, now).manualUntilRevoked, true);
  assert.throws(() => resolveElevationDuration({ kind: "MANUAL", confirmed: false }, now));
  assert.throws(() => resolveElevationDuration({ kind: "TIMED", minutes: 30 as never }, now));
});

test("elevation scope map exposes only implemented UI actions", () => {
  assert.deepEqual(ELEVATION_SCOPES, [
    "ACCOUNT_STATE_CHANGE",
    "PROJECT_ACCESS_CHANGE",
    "PROJECT_CONNECTION_MANAGE",
    "ADMIN_CREDENTIAL_CHANGE",
    "ADMIN_RECOVERY_REGENERATE"
  ]);
  assert.deepEqual(UI_ELEVATION_SCOPES, ELEVATION_SCOPES);
  assert.equal(ELEVATION_SCOPE_ACTIONS.PROJECT_ACCESS_CHANGE.ui, true);
  assert.equal(ELEVATION_SCOPE_ACTIONS.PROJECT_CONNECTION_MANAGE.ui, true);
  assert.equal(ELEVATION_SCOPE_ACTIONS.ADMIN_CREDENTIAL_CHANGE.ui, true);
  assert.equal(ELEVATION_SCOPE_ACTIONS.ADMIN_RECOVERY_REGENERATE.ui, true);
});
