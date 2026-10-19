import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseApprovedProductionPointer, planApprovedProductionAttempt, withExclusiveAgentLock } from "./production-approval-agent.mjs";
import { verifyRemoteMainHead } from "./production-main-head-check.mjs";

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

test("a main advance during production preflight blocks the latch and deployment", () => {
  const source = readFileSync(new URL("./production-approval-agent.mjs", import.meta.url), "utf8");
  const preflightIndex = source.indexOf('exec("npm", ["run", "preflight:prod"])');
  const finalHeadCheck = source.indexOf("verifyRemoteMainHead(pointer.source_commit,");
  const attemptLatch = source.indexOf('writeState(stateFile, { sha: pointer.source_commit, status: "attempted" })');
  const deploy = source.indexOf('exec("npm", ["run", "deploy:prod"])');

  assert.ok(preflightIndex >= 0 && finalHeadCheck > preflightIndex && attemptLatch > finalHeadCheck && deploy > attemptLatch);
  assert.match(source.slice(finalHeadCheck, attemptLatch), /\(command, args\) => exec\(command, args\)/u);

  let remoteMain = approved.source_commit;
  let latched = false;
  let deployed = false;
  const advanceMainDuringPreflight = () => { remoteMain = "f".repeat(40); };
  const continueDeployment = () => {
    advanceMainDuringPreflight();
    verifyRemoteMainHead(approved.source_commit, () => `${remoteMain}\trefs/heads/main\n`);
    latched = true;
    deployed = true;
  };

  assert.equal(verifyRemoteMainHead(approved.source_commit, () => `${remoteMain}\trefs/heads/main\n`), approved.source_commit);
  assert.throws(
    continueDeployment,
    /main changed after approval preflight/u,
  );
  assert.equal(latched, false);
  assert.equal(deployed, false);
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
