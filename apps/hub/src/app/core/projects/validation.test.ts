import assert from "node:assert/strict";
import test from "node:test";
import {
  isValidCoreResourceId,
  validateCoreProjectInput,
  type CoreProjectFields
} from "./validation";

const validFields: CoreProjectFields = {
  name: "Core Workspace",
  slug: "core-workspace",
  description: "Private project workspace",
  visibility: "INTERNAL",
  status: "ACTIVE"
};

test("accepts and normalizes valid project fields", () => {
  assert.deepEqual(
    validateCoreProjectInput({
      ...validFields,
      name: "  Core Workspace  ",
      description: "   "
    }),
    {
      name: "Core Workspace",
      slug: "core-workspace",
      description: null,
      visibility: "INTERNAL",
      status: "ACTIVE"
    }
  );
});

test("rejects invalid names and descriptions", () => {
  assert.equal(validateCoreProjectInput({ ...validFields, name: "x" }), null);
  assert.equal(validateCoreProjectInput({ ...validFields, name: "x".repeat(81) }), null);
  assert.equal(
    validateCoreProjectInput({ ...validFields, description: "x".repeat(501) }),
    null
  );
});

test("rejects unsafe slug forms", () => {
  for (const slug of ["ab", "Core-project", "core--project", "-core", "core-", "core_project"]) {
    assert.equal(validateCoreProjectInput({ ...validFields, slug }), null);
  }
});

test("rejects crafted enum values and archived status", () => {
  assert.equal(validateCoreProjectInput({ ...validFields, visibility: "PRIVATE" }), null);
  assert.equal(validateCoreProjectInput({ ...validFields, status: "ARCHIVED" }), null);
});

test("bounds project and access resource identifiers", () => {
  assert.equal(isValidCoreResourceId("project-id"), true);
  assert.equal(isValidCoreResourceId(""), false);
  assert.equal(isValidCoreResourceId("x".repeat(129)), false);
});
