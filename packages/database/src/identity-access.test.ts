import assert from "node:assert/strict";
import test from "node:test";
import {
  INITIAL_MODULE_CATALOG,
  assertAccessDuration,
  canCreateRequest,
  createRequestKey,
  isAccessGrantActive,
  isPublicRequestableModule,
  normalizeIdentityEmail
} from "./identity-access";

test("normalizes identity email and keeps the catalog boundary explicit", () => {
  assert.equal(normalizeIdentityEmail("  OWNER@Example.COM "), "owner@example.com");
  assert.deepEqual(
    INITIAL_MODULE_CATALOG.filter(isPublicRequestableModule).map((module) => module.key),
    ["gymforge", "aip", "rootark"]
  );
  assert.equal(
    isPublicRequestableModule(INITIAL_MODULE_CATALOG.find((module) => module.key === "lvault")!),
    false
  );
});

test("enforces independent 24-hour request cooldown and explicit blocks", () => {
  const createdAt = new Date("2026-08-01T10:00:00.000Z");
  assert.equal(canCreateRequest(createdAt, new Date("2026-08-02T09:59:59.999Z")), false);
  assert.equal(canCreateRequest(createdAt, new Date("2026-08-02T10:00:00.000Z")), true);
  assert.equal(canCreateRequest(null, new Date(), null, true), false);
});

test("fails closed for expired temporary access and rejects ambiguous durations", () => {
  const now = new Date("2026-08-01T10:00:00.000Z");
  assert.equal(
    isAccessGrantActive(
      { status: "ACTIVE", accessDurationKind: "TEMPORARY", expiresAt: new Date("2026-08-01T09:00:00.000Z") },
      now
    ),
    false
  );
  assert.equal(
    isAccessGrantActive(
      { status: "ACTIVE", accessDurationKind: "PERMANENT", expiresAt: null },
      now
    ),
    true
  );
  assert.throws(() => assertAccessDuration("TEMPORARY", null));
  assert.throws(() => assertAccessDuration("PERMANENT", now));
  assert.notEqual(createRequestKey("u1", "m1", now), createRequestKey("u1", "m2", now));
});
