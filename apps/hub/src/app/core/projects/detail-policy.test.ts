import assert from "node:assert/strict";
import test from "node:test";

import {
  canShowCoreProjectMutationControls,
  CORE_PROJECT_DETAIL_COPY,
  getCoreProjectDetailPath
} from "./detail-policy";

test("project detail paths use validated durable identifiers", () => {
  assert.equal(getCoreProjectDetailPath("project-id"), "/core/projects/project-id");
  assert.equal(getCoreProjectDetailPath("project/id"), "/core/projects/project%2Fid");
  assert.equal(getCoreProjectDetailPath(""), null);
  assert.equal(getCoreProjectDetailPath("x".repeat(129)), null);
});

test("project mutation controls stay administrator-only and hidden for archives", () => {
  assert.equal(canShowCoreProjectMutationControls(true, "ACTIVE"), true);
  assert.equal(canShowCoreProjectMutationControls(true, "ARCHIVED"), false);
  assert.equal(canShowCoreProjectMutationControls(false, "ACTIVE"), false);
  assert.equal(canShowCoreProjectMutationControls(false, "ARCHIVED"), false);
});

test("project detail copy is complete in PT-BR and English", () => {
  const portugueseKeys = Object.keys(CORE_PROJECT_DETAIL_COPY["pt-BR"]).sort();
  const englishKeys = Object.keys(CORE_PROJECT_DETAIL_COPY.en).sort();

  assert.deepEqual(portugueseKeys, englishKeys);
  assert.equal(
    Object.values(CORE_PROJECT_DETAIL_COPY).every((copy) =>
      Object.values(copy).every((value) => value.trim().length > 0)
    ),
    true
  );
});
