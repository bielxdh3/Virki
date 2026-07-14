import assert from "node:assert/strict";
import test from "node:test";

import {
  getSafeAuditActorState,
  getSafeAuditEventType,
  getSafeAuditResource,
  getSafeAuditResult
} from "./audit-view";

test("allows known event types and replaces unknown values", () => {
  assert.equal(getSafeAuditEventType("CORE_PROJECT_CREATED"), "CORE_PROJECT_CREATED");
  assert.equal(getSafeAuditEventType("private injected event"), "OTHER_EVENT");
});

test("allows known results and replaces unknown values", () => {
  assert.equal(getSafeAuditResult("SUCCESS"), "SUCCESS");
  assert.equal(getSafeAuditResult("private result"), "OTHER");
});

test("reduces actors and resources to safe categories", () => {
  assert.equal(getSafeAuditActorState("internal-id"), "user");
  assert.equal(getSafeAuditActorState(null), "system");
  assert.equal(getSafeAuditResource("core.project-access"), "project-access");
  assert.equal(getSafeAuditResource("gymforge.workout"), "application");
  assert.equal(getSafeAuditResource("private/resource/value"), "other");
});
