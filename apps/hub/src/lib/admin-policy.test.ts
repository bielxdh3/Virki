import assert from "node:assert/strict";
import test from "node:test";
import { isAdminRequestAllowed, isAdminRole, isHubAdminMutationSurface } from "./admin-policy";

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

test("Hub Access validation is only reached for requests on the Hub surface", () => {
  assert.equal(isHubAdminMutationSurface("hub"), true);
  assert.equal(isHubAdminMutationSurface("portal"), false);
  assert.equal(isHubAdminMutationSurface("unknown"), false);
});
