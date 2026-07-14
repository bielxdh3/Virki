import assert from "node:assert/strict";
import test from "node:test";

import {
  canRevokeOtherSession,
  isRevokeAllOtherSessionsConfirmed
} from "./session-policy";

test("allows only a different bounded session identifier", () => {
  assert.equal(canRevokeOtherSession("current", "other"), true);
  assert.equal(canRevokeOtherSession("current", "current"), false);
  assert.equal(canRevokeOtherSession("current", ""), false);
  assert.equal(canRevokeOtherSession("current", "x".repeat(129)), false);
});

test("requires the exact revoke-all confirmation value", () => {
  assert.equal(isRevokeAllOtherSessionsConfirmed("yes"), true);
  assert.equal(isRevokeAllOtherSessionsConfirmed("true"), false);
  assert.equal(isRevokeAllOtherSessionsConfirmed(""), false);
});
