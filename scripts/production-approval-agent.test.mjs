import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, fstatSync, fsyncSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
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
  const attemptLatch = source.indexOf('writeDurableApprovalState(stateFile, { sha: pointer.source_commit, status: "attempted" })');
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

test("approval lock persists on a failed deployment instead of enabling automatic retry", { skip: process.platform !== "linux" }, async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-approval-agent-failure-"));
  try {
    const stateFile = path.join(dir, "virki-approval-state.json");
    await assert.rejects(
      withExclusiveAgentLock(stateFile, async () => { throw new Error("interrupted deploy"); }),
      /interrupted deploy/u,
    );
    assert.equal(existsSync(stateFile + ".lock"), true, "an uncertain attempt requires manual reconciliation");
    await assert.rejects(withExclusiveAgentLock(stateFile, async () => {}), { code: "EEXIST" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("approval lock must persist file and directory before any action", { skip: process.platform !== "linux" }, async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-approval-agent-sync-"));
  try {
    const stateFile = path.join(dir, "virki-approval-state.json");
    let actionStarted = false;
    const barriers = [];
    await assert.rejects(
      withExclusiveAgentLock(stateFile, async () => { actionStarted = true; }, (fd) => {
        const kind = fstatSync(fd).isDirectory() ? "directory" : "file";
        barriers.push(kind);
        if (kind === "directory") throw new Error("simulated directory fsync failure");
        fsyncSync(fd);
      }),
      /simulated directory fsync failure/u,
    );
    assert.deepEqual(barriers, ["file", "directory"]);
    assert.equal(actionStarted, false, "no deploy action before a durable lock");
    assert.equal(existsSync(stateFile + ".lock"), true, "uncertain lock remains for manual reconciliation");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("attempt state fsyncs file then directory and fails closed on either barrier", { skip: process.platform !== "linux" }, async () => {
  const { writeDurableApprovalState } = await import("./production-approval-agent.mjs");
  assert.equal(typeof writeDurableApprovalState, "function");
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-approval-state-sync-"));
  try {
    const stateFile = path.join(dir, "virki-approval-state.json");
    const barriers = [];
    const first = { sha: approved.source_commit, status: "attempted" };
    writeDurableApprovalState(stateFile, first, (fd) => {
      barriers.push(fstatSync(fd).isDirectory() ? "directory" : "file");
      fsyncSync(fd);
    });
    assert.deepEqual(barriers, ["file", "directory"]);
    assert.deepEqual(JSON.parse(readFileSync(stateFile, "utf8")), first);

    assert.throws(() => writeDurableApprovalState(stateFile, { ...first, status: "success" }, (fd) => {
      if (fstatSync(fd).isDirectory()) throw new Error("simulated state directory fsync failure");
      fsyncSync(fd);
    }), /simulated state directory fsync failure/u);
    assert.throws(() => writeDurableApprovalState(stateFile, { ...first, status: "failed" }, () => {
      throw new Error("simulated state file fsync failure");
    }), /simulated state file fsync failure/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("failed attempt-state persistence blocks deployment and retains the recovery lock", { skip: process.platform !== "linux" }, async () => {
  const { writeDurableApprovalState } = await import("./production-approval-agent.mjs");
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-approval-state-recovery-"));
  try {
    const stateFile = path.join(dir, "virki-approval-state.json");
    let deployed = false;
    await assert.rejects(withExclusiveAgentLock(stateFile, async () => {
      writeDurableApprovalState(stateFile, { sha: approved.source_commit, status: "attempted" }, () => {
        throw new Error("simulated ENOSPC while persisting attempt");
      });
      deployed = true;
    }), /simulated ENOSPC while persisting attempt/u);
    assert.equal(deployed, false);
    assert.equal(existsSync(stateFile + ".lock"), true);
    await assert.rejects(withExclusiveAgentLock(stateFile, async () => { deployed = true; }), { code: "EEXIST" });
    assert.equal(deployed, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
