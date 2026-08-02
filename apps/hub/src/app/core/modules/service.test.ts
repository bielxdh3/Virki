import assert from "node:assert/strict";
import test from "node:test";
import { hasActiveModuleGrant } from "./service";

test("module access grants fail closed when expired, revoked, or ambiguous", () => {
  const now = new Date("2026-08-01T10:00:00.000Z");
  assert.equal(hasActiveModuleGrant({ status: "ACTIVE", accessDurationKind: "PERMANENT", expiresAt: null }, now), true);
  assert.equal(hasActiveModuleGrant({ status: "ACTIVE", accessDurationKind: "TEMPORARY", expiresAt: new Date("2026-08-01T09:00:00.000Z") }, now), false);
  assert.equal(hasActiveModuleGrant({ status: "REVOKED", accessDurationKind: "PERMANENT", expiresAt: null }, now), false);
});
