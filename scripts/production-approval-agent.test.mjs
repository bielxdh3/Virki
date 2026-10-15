import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseApprovedProductionPointer, planApprovedProductionAttempt, withExclusiveAgentLock } from "./production-approval-agent.mjs";

const approved = {
  version: 1, source_commit: "a".repeat(40), approved_by: "bielxdh3",
  approved_at: "2026-10-15T00:00:00Z", ci_run: 123, codeql_run: 124, approval_run: 125,
  previous_approval: ""
};
test("the production approval pointer requires the exact schema and approving owner", () => {
  assert.equal(parseApprovedProductionPointer(JSON.stringify(approved)).source_commit, approved.source_commit);
  for (const patch of [
    { version: 2 }, { source_commit: "b" }, { approved_by: "attacker" },
    { ci_run: null }, { codeql_run: 0 }, { approval_run: 0 }, { approved_at: "yesterday" }
  ]) {
    assert.throws(() => parseApprovedProductionPointer({ ...approved, ...patch }));
  }
});
test("the agent never repeats or overwrites an unresolved production attempt", () => {
  assert.equal(planApprovedProductionAttempt(approved, null), "deploy");
  assert.equal(planApprovedProductionAttempt(approved, { sha: approved.source_commit, status: "success" }), "already-applied");
  for (const status of ["attempted", "failed"]) {
    assert.throws(() => planApprovedProductionAttempt(approved, { sha: approved.source_commit, status }));
    assert.throws(() => planApprovedProductionAttempt(approved, { sha: "b".repeat(40), status }));
  }
  assert.throws(() => planApprovedProductionAttempt(approved, { sha: "oops", status: "success" }));
  assert.equal(planApprovedProductionAttempt(approved, { sha: "b".repeat(40), status: "success" }), "deploy");
});

test("atomic lock refuses a concurrent deployment and releases on normal completion", { skip: process.platform !== "linux" }, async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-approval-agent-"));
  try {
    const stateFile = path.join(dir, "virki-approval-state.json");
    await withExclusiveAgentLock(stateFile, async () => {
      await assert.rejects(withExclusiveAgentLock(stateFile, async () => {}), { code: "EEXIST" });
    });
    await withExclusiveAgentLock(stateFile, async () => {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
