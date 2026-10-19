import assert from "node:assert/strict";
import test from "node:test";
import { hashAuditIdentifier, hashAuditSessionReference } from "./audit";

test("session audit reference is derived from the persisted ID used by login, denial, OIDC, and logout", () => {
  const persistedSessionId = "session-db-id-123";
  const canonical = hashAuditIdentifier(persistedSessionId);
  assert.equal(hashAuditSessionReference(persistedSessionId), canonical);
});
