import assert from "node:assert/strict";
import test from "node:test";
import { selectLatestWorkflowRun } from "./lib/production-run-selection.mjs";

const sha = "0123456789abcdef0123456789abcdef01234567";
const run = (patch = {}) => ({
  id: 100,
  name: "CI",
  head_sha: sha,
  head_branch: "main",
  event: "push",
  run_number: 12,
  run_attempt: 1,
  status: "completed",
  conclusion: "success",
  ...patch
});

test("selects a successful rerun even when the same SHA has multiple successful run records", () => {
  const selected = selectLatestWorkflowRun([
    run({ id: 100, run_number: 12, run_attempt: 1, conclusion: "failure" }),
    run({ id: 100, run_number: 12, run_attempt: 2, conclusion: "success" }),
    run({ id: 88, run_number: 11, run_attempt: 1, conclusion: "success" })
  ], "CI", sha);
  assert.deepEqual(selected, { state: "success", id: "100" });
});

test("ignores same-SHA runs from another branch or event", () => {
  const selected = selectLatestWorkflowRun([
    run({ id: 999, run_number: 99, head_branch: "feature/untrusted", conclusion: "success" }),
    run({ id: 998, run_number: 98, event: "pull_request", conclusion: "success" }),
    run({ id: 123, run_number: 13, conclusion: "success" })
  ], "CI", sha);
  assert.deepEqual(selected, { state: "success", id: "123" });
});

test("fails closed when the latest exact main-push run failed after an older success", () => {
  const selected = selectLatestWorkflowRun([
    run({ id: 100, name: "CodeQL", run_number: 12, conclusion: "success" }),
    run({ id: 101, name: "CodeQL", run_number: 13, conclusion: "failure" })
  ], "CodeQL", sha);
  assert.deepEqual(selected, { state: "failure", id: "101" });
});

test("waits on the newest in-progress exact run instead of accepting an older success", () => {
  const selected = selectLatestWorkflowRun([
    run({ id: 100, run_number: 12, conclusion: "success" }),
    run({ id: 101, run_number: 13, status: "in_progress", conclusion: null })
  ], "CI", sha);
  assert.deepEqual(selected, { state: "pending", id: "101" });
});

test("reports missing checks and rejects unsupported workflow names or malformed SHAs", () => {
  assert.deepEqual(selectLatestWorkflowRun([], "CI", sha), { state: "missing", id: null });
  assert.throws(() => selectLatestWorkflowRun([], "Other", sha), /Invalid exact-SHA/u);
  assert.throws(() => selectLatestWorkflowRun([], "CI", "bad"), /Invalid exact-SHA/u);
});
