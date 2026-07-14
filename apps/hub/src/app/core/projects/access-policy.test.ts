import assert from "node:assert/strict";
import test from "node:test";

import {
  canRevokeCoreProjectAccess,
  canSetCoreProjectAccess,
  isCoreProjectAccessLevel,
  requiresActiveOwnerRetentionCheck
} from "./access-policy";

test("accepts only allowlisted project access levels", () => {
  assert.equal(isCoreProjectAccessLevel("VIEWER"), true);
  assert.equal(isCoreProjectAccessLevel("EDITOR"), true);
  assert.equal(isCoreProjectAccessLevel("OWNER"), true);
  assert.equal(isCoreProjectAccessLevel("ADMIN"), false);
});

test("limits admins to non-owner access rows", () => {
  assert.equal(canSetCoreProjectAccess("ADMIN", "VIEWER", null), true);
  assert.equal(canSetCoreProjectAccess("ADMIN", "EDITOR", "VIEWER"), true);
  assert.equal(canSetCoreProjectAccess("ADMIN", "OWNER", null), false);
  assert.equal(canSetCoreProjectAccess("ADMIN", "VIEWER", "OWNER"), false);
  assert.equal(canSetCoreProjectAccess("MEMBER", "VIEWER", null), false);
});

test("allows only the global owner to revoke project owners", () => {
  assert.equal(canRevokeCoreProjectAccess("OWNER", "OWNER"), true);
  assert.equal(canRevokeCoreProjectAccess("ADMIN", "EDITOR"), true);
  assert.equal(canRevokeCoreProjectAccess("ADMIN", "OWNER"), false);
  assert.equal(canRevokeCoreProjectAccess("MEMBER", "VIEWER"), false);
});

test("protects active project owners from last-owner removal", () => {
  assert.equal(requiresActiveOwnerRetentionCheck("OWNER", true), true);
  assert.equal(requiresActiveOwnerRetentionCheck("OWNER", false), false);
  assert.equal(requiresActiveOwnerRetentionCheck("EDITOR", true), false);
});
