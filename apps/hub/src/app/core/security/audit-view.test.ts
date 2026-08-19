import assert from "node:assert/strict";
import test from "node:test";

import {
  getSafeAuditActorState,
  getSafeAuditEventType,
  getSafeAuditResource,
  getSafeAuditResult,
  normalizeCoreAuditFilter
} from "./audit-view";

test("allows known event types and replaces unknown values", () => {
  assert.equal(getSafeAuditEventType("CORE_PROJECT_CREATED"), "CORE_PROJECT_CREATED");
  assert.equal(getSafeAuditEventType("ADMIN_ELEVATION_ACTIVATED"), "ADMIN_ELEVATION_ACTIVATED");
  assert.equal(getSafeAuditEventType("ACCOUNT_APPLICATION_REVIEWED"), "ACCOUNT_APPLICATION_REVIEWED");
  assert.equal(getSafeAuditEventType("private injected event"), "OTHER_EVENT");
});

test("normalizes the owner-only audit filter to the safe categories", () => {
  assert.equal(normalizeCoreAuditFilter("infrastructure"), "infrastructure");
  assert.equal(normalizeCoreAuditFilter("actor-id"), "activity");
  assert.equal(normalizeCoreAuditFilter(undefined), "activity");
});

test("allows known results and replaces unknown values", () => {
  assert.equal(getSafeAuditResult("SUCCESS"), "SUCCESS");
  assert.equal(getSafeAuditResult("private result"), "OTHER");
});

test("reduces actors and resources to safe categories", () => {
  assert.equal(getSafeAuditActorState("internal-id"), "user");
  assert.equal(getSafeAuditActorState(null), "system");
  assert.equal(getSafeAuditResource("hub", "ACCESS_JWT_VALID"), "access");
  assert.equal(getSafeAuditResource("identity.elevation"), "security");
  assert.equal(getSafeAuditResource("identity.application"), "application");
  assert.equal(getSafeAuditResource("core.project-access"), "project-access");
  assert.equal(getSafeAuditResource("gymforge.workout"), "application");
  assert.equal(getSafeAuditResource("private/resource/value"), "other");
});
