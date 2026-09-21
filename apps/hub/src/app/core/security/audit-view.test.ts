import assert from "node:assert/strict";
import test from "node:test";

import {
  getSafeAuditActorState,
  getSafeAuditEventType,
  getSafeAuditCategory,
  getSafeAuditEventLabel,
  getAuditRangeLabel,
  getSafeAuditResource,
  getSafeAuditResult,
  normalizeCoreAuditFilter
} from "./audit-view";
import { parseAuditDate } from "./audit-service";

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
  assert.equal(getSafeAuditResource("identity.module"), "application");
  assert.equal(getSafeAuditResource("core.project-access"), "project-access");
  assert.equal(getSafeAuditResource("gymforge.workout"), "application");
  assert.equal(getSafeAuditResource("private/resource/value"), "other");
});

test("maps technical events to compact investigation labels", () => {
  assert.equal(getSafeAuditCategory("CORE_PROJECT_ACCESS_GRANTED", "core.project-access"), "access");
  assert.equal(getSafeAuditCategory("AUTH_SESSION_CLEANUP", "session"), "auth");
  assert.equal(getSafeAuditCategory("MODULE_ACCESS_REQUESTED", "identity.module"), "module");
  assert.equal(getSafeAuditCategory("unknown", "system"), "system");
  assert.equal(getSafeAuditEventLabel("AUTH_SESSION_CLEANUP"), "Limpeza de sessões");
  assert.equal(getSafeAuditEventLabel("untrusted event"), "Outro evento");
});

test("audit time filters accept bounded UTC dates and reject malformed values", () => {
  assert.equal(parseAuditDate("2026-09-18")?.toISOString(), "2026-09-18T00:00:00.000Z");
  assert.equal(parseAuditDate("2026-09-18", true)?.toISOString(), "2026-09-18T23:59:59.999Z");
  assert.equal(parseAuditDate("2026-02-30"), undefined);
  assert.equal(parseAuditDate("2026-09-18T00:00"), undefined);
});

test("audit range labels expose the bounded page window and retained total", () => {
  assert.equal(getAuditRangeLabel(1, 50, 125, "pt-BR"), "1–50 de 125");
  assert.equal(getAuditRangeLabel(51, 100, 125, "en"), "51–100 of 125");
  assert.equal(getAuditRangeLabel(0, 0, 0, "pt-BR"), "0 eventos");
});
