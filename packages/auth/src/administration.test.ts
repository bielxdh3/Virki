import assert from "node:assert/strict";
import test from "node:test";
import {
  ELEVATION_SCOPES,
  ELEVATION_SCOPE_ACTIONS,
  UI_ELEVATION_SCOPES,
  resolveElevationDuration
} from "./administration";

test("elevation duration requires explicit bounded or confirmed manual mode", () => {
  const now = new Date("2026-08-01T10:00:00.000Z");
  assert.deepEqual(resolveElevationDuration({ kind: "TIMED", minutes: 60 }, now), { manualUntilRevoked: false, expiresAt: new Date("2026-08-01T11:00:00.000Z") });
  assert.equal(resolveElevationDuration({ kind: "MANUAL", confirmed: true }, now).manualUntilRevoked, true);
  assert.throws(() => resolveElevationDuration({ kind: "MANUAL", confirmed: false }, now));
  assert.throws(() => resolveElevationDuration({ kind: "TIMED", minutes: 30 as never }, now));
});

test("elevation scope map exposes only implemented UI actions", () => {
  assert.deepEqual(ELEVATION_SCOPES, [
    "ACCOUNT_APPLICATION_REVIEW",
    "ACCOUNT_ACTIVATION_REISSUE",
    "MODULE_ACCESS_CHANGE",
    "FEATURE_PERMISSION_CHANGE",
    "ACCOUNT_STATE_CHANGE",
    "GLOBAL_ROLE_CHANGE",
    "MODULE_CATALOG_CHANGE",
    "ADMIN_CREDENTIAL_CHANGE",
    "ADMIN_RECOVERY_REGENERATE",
    "PROJECT_OWNER_ACCESS_CHANGE",
    "CORE_PROJECT_ARCHIVE"
  ]);
  assert.deepEqual(UI_ELEVATION_SCOPES, [
    "ACCOUNT_APPLICATION_REVIEW",
    "ACCOUNT_ACTIVATION_REISSUE",
    "MODULE_ACCESS_CHANGE",
    "FEATURE_PERMISSION_CHANGE",
    "ACCOUNT_STATE_CHANGE",
    "PROJECT_OWNER_ACCESS_CHANGE",
    "CORE_PROJECT_ARCHIVE"
  ]);
  assert.equal(ELEVATION_SCOPE_ACTIONS.GLOBAL_ROLE_CHANGE.ui, false);
  assert.equal(ELEVATION_SCOPE_ACTIONS.MODULE_CATALOG_CHANGE.ui, false);
  assert.equal(ELEVATION_SCOPE_ACTIONS.ADMIN_CREDENTIAL_CHANGE.ui, false);
  assert.equal(ELEVATION_SCOPE_ACTIONS.ADMIN_RECOVERY_REGENERATE.ui, false);
});
