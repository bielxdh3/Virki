import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { buildLocalStageReceipts, executeBoundedLocalCommand } from "./lib/offline-ci-local-runner.mjs";

// Synthetic *test-only* evidence. Never represent it as CI or scanner proof.
const revision = "a".repeat(40);
const branch = "cdx/disposable-offline-ci-fixture";
const stages = ["tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check"];
const emptyHash = createHash("sha256").update("").digest("hex");
const logs = { "unit-tests": "unit-tests.tap.log", "integration-tests": "integration-tests.tap.log",
  "production-operations-tests": "production-operations-tests.tap.log",
  "browser-e2e": "browser-e2e-output.log", "bootstrap-virgin-tests": "bootstrap-virgin-tests.tap.log" };

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-local-receipts-dev-"));
  for (const filename of Object.values(logs)) writeFileSync(path.join(root, filename), "DEV_ONLY_TEST_LOG\n");
  const start = Date.parse("2026-10-28T17:00:00.000Z");
  const manifest = {
    runId: "b".repeat(32), sourceBranch: branch, sourceHead: revision,
    startedUtc: new Date(start).toISOString(), finishedUtc: new Date(start + 220_000).toISOString(),
    nodeVersion: "v22.23.3", npmVersion: "10.9.9", dockerMutationJournal: "docker-mutations.jsonl",
    dockerMutationUncertain: false, dockerCleanupVerified: true,
    bootstrapVirginTestsLog: logs["bootstrap-virgin-tests"], bootstrapVirginTestsExitCode: 0,
    unitTestsLog: logs["unit-tests"], integrationTestsLog: logs["integration-tests"],
    productionOperationsLog: logs["production-operations-tests"], browserE2ELog: logs["browser-e2e"],
    stagedPatchSha256: emptyHash, workingTreePatchSha256: emptyHash, untrackedFiles: [],
    unitTestsFailureCount: 0, unitTestsFailures: [], integrationTestsFailureCount: 0,
    integrationTestsFailures: [], productionOperationsFailureCount: 0, productionOperationsFailures: [],
    exitCode: 0, failedStages: [],
    stages: stages.map((name, index) => ({
      name, startedUtc: new Date(start + index * 10_000 + 1000).toISOString(),
      finishedUtc: new Date(start + index * 10_000 + 2000).toISOString(), durationMs: 1000, exitCode: 0,
    })),
  };
  const ordered = [...stages];
  ordered.splice(ordered.indexOf("integration-tests"), 0, "bootstrap-virgin-tests");
  const stdout = Buffer.from(ordered.map((name) => `\n[${name}]\nDEV_ONLY_TEST_OUTPUT\n[RESULT] ${name} exit=0 durationMs=1000\n`).join(""));
  const input = () => ({ manifestBytes: Buffer.from(JSON.stringify(manifest)), stdout, revision, branch, stageLogDirectory: root });
  return { root, manifest, stdout, input, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("DEV fixture binds 19 real-observed stage envelopes, five local logs, extra virgin preflight and explicit absent authorities", () => {
  const f = fixture();
  try {
    const receipt = buildLocalStageReceipts(f.input());
    assert.equal(receipt.stages.length, 19);
    assert.equal(receipt.bootstrap.exitCode, 0);
    assert.match(receipt.bootstrap.rawLogSha256, /^[a-f0-9]{64}$/u);
    assert.equal(receipt.codeql, "NOT_RUN");
    assert.equal(receipt.deployAuthorized, false);
    assert.equal(receipt.stages[0].consoleExcerptComplete, false);
    assert.equal(receipt.stages[12].name, "browser-e2e");
    assert.notEqual(receipt.finalChainSha256, receipt.manifestSha256);
  } finally { f.cleanup(); }
});

test("receipts never serialize raw console secrets; hardlinked logs are rejected", () => {
  const f = fixture();
  try {
    const input = f.input();
    const credential = "DEV_SYNTHETIC_PRIVATE_OUTPUT_EXAMPLE_123456";
    input.stdout = Buffer.from(input.stdout.toString().replace(/DEV_ONLY_TEST_OUTPUT/gu, credential));
    const receipt = buildLocalStageReceipts(input);
    assert.equal(JSON.stringify(receipt).includes(credential), false);
    linkSync(path.join(f.root, logs["unit-tests"]), path.join(f.root, "hardlink-to-unit.log"));
    assert.throws(() => buildLocalStageReceipts(input), /Invalid bounded local evidence file/u);
  } finally { f.cleanup(); }
});

test("forged reports, wrong SHA, skipped stages, duplicated results, replay and failed bootstrap block", async (suite) => {
  const attacks = {
    "wrong SHA replay": (f, input) => { input.revision = "c".repeat(40); },
    "skipped manifest stage": (f) => { f.manifest.stages.splice(4, 1); },
    "stage reports nonzero": (f) => { f.manifest.stages[6].exitCode = 1; },
    "bootstrap fails": (f) => { f.manifest.bootstrapVirginTestsExitCode = 1; },
    "cleanup uncertain": (f) => { f.manifest.dockerMutationUncertain = true; },
    "truncated stdout": (f, input) => { input.stdout = f.stdout.subarray(0, f.stdout.length - 80); },
    "missing result": (f, input) => { input.stdout = Buffer.from(f.stdout.toString().replace(/\[RESULT\] lint exit=0 durationMs=1000/u, "")); },
    "duplicate result": (f, input) => { input.stdout = Buffer.from(f.stdout.toString().replace(/\[RESULT\] lint exit=0 durationMs=1000/u, "[RESULT] lint exit=0 durationMs=1000\n[RESULT] lint exit=0 durationMs=1000")); },
    "stage reordered": (f, input) => { input.stdout = Buffer.from(f.stdout.toString().replace(/\[tooling-policy-dependencies\]/u, "[lint]")); },
    "reported stage exit differs": (f, input) => { input.stdout = Buffer.from(f.stdout.toString().replace(/\[RESULT\] build exit=0/u, "[RESULT] build exit=1")); },
  };
  for (const [name, mutate] of Object.entries(attacks)) {
    await suite.test(name, () => {
      const f = fixture();
      try {
        const input = f.input();
        mutate(f, input);
        input.manifestBytes = Buffer.from(JSON.stringify(f.manifest));
        assert.throws(() => buildLocalStageReceipts(input));
      } finally { f.cleanup(); }
    });
  }
});

test("bounded child executes real code and blocks stdout overflow and timeout", async () => {
  const success = await executeBoundedLocalCommand(process.execPath, ["-e", "process.stdout.write('executed')"], { timeoutMs: 3000, maxOutputBytes: 100 });
  assert.equal(success.exitCode, 0);
  assert.equal(success.stdout.toString(), "executed");
  assert.equal(success.timedOut, false);
  const over = await executeBoundedLocalCommand(process.execPath, ["-e", "process.stdout.write('X'.repeat(4096))"], { timeoutMs: 3000, maxOutputBytes: 100 });
  assert.equal(over.truncated, true);
  const timed = await executeBoundedLocalCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { timeoutMs: 200, maxOutputBytes: 100 });
  assert.equal(timed.timedOut, true);
});

test("POSIX entrypoint alias cannot silently exit 0, with or without Node symlink preservation", { skip: process.platform === "win32" }, () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-offline-cli-alias-dev-"));
  try {
    const originalScripts = path.dirname(fileURLToPath(import.meta.url));
    const copiedScripts = path.join(root, "scripts");
    mkdirSync(path.join(copiedScripts, "lib"), { recursive: true });
    for (const filename of ["offline-ci-local-runner.mjs"]) {
      copyFileSync(path.join(originalScripts, filename), path.join(copiedScripts, filename));
    }
    for (const filename of ["offline-ci-local-runner.mjs", "offline-ci-evidence.mjs"]) {
      copyFileSync(path.join(originalScripts, "lib", filename), path.join(copiedScripts, "lib", filename));
    }
    symlinkSync("offline-ci-local-runner.mjs", path.join(copiedScripts, "alias.mjs"));
    symlinkSync(copiedScripts, path.join(root, "alias-scripts"), "dir");
    for (const [alias, flags] of [
      [path.join(copiedScripts, "alias.mjs"), []],
      [path.join(copiedScripts, "alias.mjs"), ["--preserve-symlinks-main"]],
      [path.join(root, "alias-scripts", "offline-ci-local-runner.mjs"), []],
      [path.join(root, "alias-scripts", "offline-ci-local-runner.mjs"), ["--preserve-symlinks", "--preserve-symlinks-main"]],
    ]) {
      const run = spawnSync(process.execPath, [...flags, alias], { encoding: "utf8", timeout: 5000 });
      assert.equal(run.status, 1, `symlink variant ${alias} flags=${flags.join(" ")} must BLOCK`);
      assert.match(run.stderr, /entrypoint alias is forbidden/iu);
      assert.equal(run.stdout, "");
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
