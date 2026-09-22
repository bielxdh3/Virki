import assert from "node:assert/strict";
import test from "node:test";
import { isAdminRequestAllowed, isAdminRole } from "./admin-policy";

test("ADMIN routes require the exact hub surface and a valid Access assertion", () => {
  assert.equal(isAdminRequestAllowed("hub", true), true);
  assert.equal(isAdminRequestAllowed("hub", false), false);
  assert.equal(isAdminRequestAllowed("portal", true), false);
  assert.equal(isAdminRequestAllowed("unknown", true), false);
});

test("only the ADMIN role can enter the control plane", () => {
  assert.equal(isAdminRole("ADMIN"), true);
  assert.equal(isAdminRole("USER"), false);
  assert.equal(isAdminRole(null), false);
  assert.equal(isAdminRole(undefined), false);
});
