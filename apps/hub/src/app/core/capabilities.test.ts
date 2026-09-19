import assert from "node:assert/strict";
import test from "node:test";

import { CORE_CAPABILITY_MANIFEST_VALID, getActivityInboxEvents, getCoreHealthCards, getRecoveryCards } from "./capabilities";

test("Core capability manifest is versioned and validated", () => {
  assert.equal(CORE_CAPABILITY_MANIFEST_VALID, true);
});

test("health and recovery surfaces distinguish unavailable data", () => {
  const observedAt = "2026-09-18T12:00:00.000Z";
  const health = getCoreHealthCards({ hubRequest: "verified", authenticatedSession: "verified", database: "unknown", emailTransport: "unavailable", intake: "disabled", emailWorker: "not-checked" }, "pt-BR", observedAt);
  assert.equal(health[0]?.state, "unknown");
  assert.equal(health[1]?.state, "unavailable");
  assert.equal(health[0]?.observedAt, observedAt);
  assert.equal(getRecoveryCards("pt-BR", observedAt)[0]?.state, "unknown");
  assert.equal(getRecoveryCards("pt-BR", observedAt)[0]?.observedAt, observedAt);
  assert.deepEqual(getActivityInboxEvents(), []);
});
