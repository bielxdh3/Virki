import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  unlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  inspectDisposableOfflineRecovery, rehearseDisposableOfflineRecovery,
} from "./disposable-recovery-coordinator.mjs";

const OLD = "a".repeat(40);
const NEW = "b".repeat(40);
process.env.VIRKI_DISPOSABLE_RECOVERY_TEST = "1";

function fixture(t, candidateHealth = "ok") {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-offline-recovery-fixture-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const folder of [
    "state", "database", "backups", "restores", "releases",
    `releases/${OLD}`, `releases/${NEW}`,
  ]) mkdirSync(path.join(root, folder), { recursive: true, mode: 0o700 });
  const put = (name, data) => writeFileSync(path.join(root, name), JSON.stringify(data), { mode: 0o600 });
  put(".virki-disposable-recovery.json",
    { version: 1, disposable: true, id: randomBytes(16).toString("hex") });
  put(`releases/${OLD}/release.json`, { revision: OLD, schemaVersion: 1, health: "ok" });
  put(`releases/${NEW}/release.json`, { revision: NEW, schemaVersion: 2, health: candidateHealth });
  put("database/database.json", { schemaVersion: 1, accounts: ["admin", "user"] });
  put("state/active.json", { revision: OLD });
  put("state/routing.json", { maintenance: false, runningSha: OLD });
  put("state/journal.json", { version: 1, events: [] });
  const read = (name) => JSON.parse(readFileSync(path.join(root, name), "utf8"));
  return {
    root, put, read, request: { fixtureRoot: root, expectedPreviousSha: OLD, candidateSha: NEW },
    run: (phaseHook = () => {}) => rehearseDisposableOfflineRecovery(
      { fixtureRoot: root, expectedPreviousSha: OLD, candidateSha: NEW },
      { onPhase: phaseHook },
    ),
  };
}
function assertRecovered(f) {
  assert.deepEqual(f.read("state/active.json"), { revision: OLD });
  assert.deepEqual(f.read("state/routing.json"), { maintenance: false, runningSha: OLD });
  assert.deepEqual(f.read("database/database.json"),
    { schemaVersion: 1, accounts: ["admin", "user"] });
  assert.equal(existsSync(path.join(f.root, ".recovery-attempt.lock")), false);
  assert.equal(f.read("state/journal.json").events.at(-1).phase, "rolled-back");
  assert.equal(inspectDisposableOfflineRecovery(f.root).deployAuthorized, false);
}
function subprocess(root, action) {
  const script = `
    import { rehearseDisposableOfflineRecovery } from ${JSON.stringify(
      new URL("./disposable-recovery-coordinator.mjs", import.meta.url).href
    )};
    try {
      const result = rehearseDisposableOfflineRecovery({
        fixtureRoot: process.argv[1],
        expectedPreviousSha: "${OLD}", candidateSha: "${NEW}",
      }, { onPhase(phase) {
        if (process.argv[2] === "crash" && phase === "maintenance") process.exit(89);
        if (process.argv[2] === "hold" && phase === "attempted") {
          const until = Date.now() + 250;
          while (Date.now() < until) {}
        }
      } });
      process.stdout.write(result.status);
    } catch (error) {
      process.stderr.write(String(error.message));
      process.exitCode = 2;
    }
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script, root, action], {
      env: { ...process.env, VIRKI_DISPOSABLE_RECOVERY_TEST: "1" },
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "", stdout = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr, stdout }));
  });
}

test("full offline rehearsal reserves attempt, validates restored clone, migrates, checks health, and retains backup plus predecessor", (t) => {
  const f = fixture(t);
  const phases = [];
  const result = f.run((phase) => phases.push(phase));
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.status, "DISPOSABLE_RECOVERY_REHEARSAL_PASSED");
  assert.deepEqual(phases, [
    "attempted", "maintenance", "backup-verified", "restore-verified",
    "restore-migrated", "live-migrated", "candidate-running", "health-passed",
  ]);
  assert.deepEqual(f.read("database/database.json"),
    { schemaVersion: 2, accounts: ["admin", "user"] });
  assert.deepEqual(f.read("state/active.json"), { revision: NEW });
  assert.deepEqual(f.read("state/routing.json"), { maintenance: false, runningSha: NEW });
  assert.equal(f.read("state/journal.json").events.at(-1).phase, "committed");
  assert.deepEqual(f.read(`releases/${OLD}/release.json`),
    { revision: OLD, schemaVersion: 1, health: "ok" });
  assert.deepEqual(f.read(`backups/${result.attemptId}.dump`),
    { schemaVersion: 1, accounts: ["admin", "user"] });
  assert.deepEqual(f.read(`restores/${result.attemptId}.dump`),
    { schemaVersion: 2, accounts: ["admin", "user"] });
  assert.equal(inspectDisposableOfflineRecovery(f.root).attemptedLock, false);
  assert.throws(() => f.run(), /predecessor is not active/u);
});

test("default hook-free API runs fixture successfully with no hidden external dependencies", (t) => {
  const f = fixture(t);
  const result = rehearseDisposableOfflineRecovery(f.request);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.status, "DISPOSABLE_RECOVERY_REHEARSAL_PASSED");
  assert.equal(f.read("state/active.json").revision, NEW);
});

test("every injected stage failure rolls back exact data and resumes prior healthy app", async (t) => {
  for (const phase of [
    "attempted", "maintenance", "backup-verified", "restore-verified",
    "restore-migrated", "live-migrated", "candidate-running", "health-passed",
  ]) {
    await t.test(phase, (subtest) => {
      const f = fixture(subtest);
      assert.throws(() => f.run((step) => {
        if (step === phase) throw new Error("injected " + phase);
      }), new RegExp("injected " + phase));
      assertRecovered(f);
      assert.equal(f.read("state/journal.json").events.some((event) => event.phase === "attempted"), true);
      if (["live-migrated", "candidate-running", "health-passed"].includes(phase)) {
        assert.equal(readdirSync(path.join(f.root, "backups")).length, 1);
      }
    });
  }
});

test("unhealthy candidate fails closed after migration and restores predecessor", (t) => {
  const f = fixture(t, "fail");
  assert.throws(() => f.run(), /health or database schema mismatch/u);
  assertRecovered(f);
});

test("tampering with account rows in restored clone rejects migration before live mutation", (t) => {
  const f = fixture(t);
  assert.throws(() => f.run((phase) => {
    if (phase === "restore-verified") {
      const name = readdirSync(path.join(f.root, "restores"))[0];
      f.put(path.join("restores", name), { schemaVersion: 1, accounts: ["intruder"] });
    }
  }), /migration changed account data on disposable restore/u);
  assertRecovered(f);
  assert.equal(f.read("state/journal.json").events.some((entry) => entry.phase === "live-migrated"), false);
});

test("app-side identity mutation after health fails closed and is reversed from backup", (t) => {
  const f = fixture(t);
  assert.throws(() => f.run((phase) => {
    if (phase === "health-passed") {
      f.put("database/database.json", { schemaVersion: 2, accounts: ["intruder", "user"] });
    }
  }), /live identity state differs from verified migrated restore/u);
  assertRecovered(f);
});

test("candidate descriptor swap after health blocks activation and restores old release", (t) => {
  const f = fixture(t);
  assert.throws(() => f.run((phase) => {
    if (phase === "health-passed") {
      f.put(`releases/${NEW}/release.json`,
        { revision: NEW, schemaVersion: 2, health: "fail" });
    }
  }), /health or database schema mismatch/u);
  assertRecovered(f);
});

test("corrupted verified backup prevents rollback and retains maintenance plus attempt lock", (t) => {
  const f = fixture(t);
  assert.throws(() => f.run((phase) => {
    if (phase === "live-migrated") {
      const name = readdirSync(path.join(f.root, "backups"))[0];
      writeFileSync(path.join(f.root, "backups", name), "tampered");
      throw new Error("failure after live migration");
    }
  }), /safe rollback is blocked/u);
  const state = inspectDisposableOfflineRecovery(f.root);
  assert.equal(state.maintenance, true);
  assert.equal(state.attemptedLock, true);
  assert.equal(state.lastPhase, "rollback-blocked");
  assert.equal(f.read("database/database.json").schemaVersion, 2);
  assert.throws(() => f.run(), /predecessor is not active and healthy|unresolved attempted operation/u);
});

test("child process crash retains maintenance, durable attempted journal, and blocks replay", async (t) => {
  const f = fixture(t);
  const exited = await subprocess(f.root, "crash");
  assert.equal(exited.code, 89, exited.stderr);
  const state = inspectDisposableOfflineRecovery(f.root);
  assert.equal(state.status, "DISPOSABLE_ATTEMPT_REQUIRES_MANUAL_RECONCILIATION");
  assert.equal(state.lastPhase, "maintenance");
  assert.equal(state.maintenance, true);
  assert.equal(state.activeSha, OLD);
  assert.equal(state.attemptedLock, true);
  assert.throws(() => f.run(), /predecessor is not active and healthy/u);
  assert.deepEqual(f.read("database/database.json"),
    { schemaVersion: 1, accounts: ["admin", "user"] });
});

test("parallel independent processes admit exactly one attempt", async (t) => {
  const f = fixture(t);
  const [one, two] = await Promise.all([
    subprocess(f.root, "hold"), subprocess(f.root, "hold"),
  ]);
  const results = [one, two];
  assert.deepEqual(results.map((entry) => entry.code).sort(), [0, 2], JSON.stringify(results));
  assert.equal(results.filter((entry) => entry.stdout.includes("REHEARSAL_PASSED")).length, 1);
  assert.equal(f.read("state/journal.json").events.filter((entry) => entry.phase === "attempted").length, 1);
  assert.equal(f.read("state/active.json").revision, NEW);
  assert.equal(existsSync(path.join(f.root, ".recovery-attempt.lock")), false);
});

test("invalid root and forged candidate descriptor are refused before attempted ledger reservation", (t) => {
  const f = fixture(t);
  const source = f.root;
  assert.throws(() => rehearseDisposableOfflineRecovery(
    { ...f.request, fixtureRoot: path.dirname(source) }, { onPhase() {} }),
  /root must be an OS-temp disposable fixture/u);
  f.put(`releases/${NEW}/release.json`,
    { revision: OLD, schemaVersion: 2, health: "ok" });
  assert.throws(() => f.run(), /release identity or health descriptor mismatch/u);
  assert.deepEqual(f.read("state/journal.json").events, []);
  assert.equal(existsSync(path.join(f.root, ".recovery-attempt.lock")), false);
});

test("unexpected fixture database file type is rejected before state change", (t) => {
  const f = fixture(t);
  unlinkSync(path.join(f.root, "database", "database.json"));
  mkdirSync(path.join(f.root, "database", "database.json"));
  assert.throws(() => f.run(), /unsafe fixture file/u);
  assert.deepEqual(f.read("state/journal.json").events, []);
  assert.equal(existsSync(path.join(f.root, ".recovery-attempt.lock")), false);
});
