import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import test from "node:test";
import { buildLocalStageReceipts, executeBoundedLocalCommand, executePinnedPowerShellScriptBytes, assertCleanGitWorktreeWithoutFilters } from "./lib/offline-ci-local-runner.mjs";

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
    "noncanonical comma duration remains rejected": (f, input) => { input.stdout = Buffer.from(f.stdout.toString().replace(/durationMs=1000/u, "durationMs=1000,5")); },
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

test("Windows PowerShell 5.1 pt-BR real Invoke-Stage emits canonical invariant duration for strict receipts", { skip: process.platform !== "win32" }, () => {
  // Extract the actual committed fixture function via the PowerShell AST.
  // Its Docker dependency is a dummy: this regression never contacts a daemon.
  const source = path.join(path.dirname(fileURLToPath(import.meta.url)), "e2e", "run-isolated-linux-docker.ps1");
  const ps = `
$ErrorActionPreference = 'Stop'
$errors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('${source.replace(/'/gu, "''")}', [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Fixture did not parse' }
$fn = $ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Stage'}, $true)
if (-not $fn) { throw 'Real stage emitter missing' }
Invoke-Expression $fn.Extent.Text
function Invoke-PinnedDocker { $global:LASTEXITCODE = 0 }
$script:runnerName = 'SYNTHETIC_TEST_ONLY'
$script:results = [System.Collections.Generic.List[string]]::new()
$script:stageManifest = [System.Collections.Generic.List[object]]::new()
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('pt-BR')
Invoke-Stage -Name 'runtime' -Command @('true')
`;
  const result = spawnSync("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", ps], { encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 0, "isolated PowerShell stage stub must succeed");
  const lines = result.stdout.split(/\r?\n/u);
  const emitted = lines.find((line) => line.startsWith("[RESULT] runtime "));
  assert.match(emitted, /^\[RESULT\] runtime exit=0 durationMs=[0-9]+(?:\.[0-9]+)?$/u);
});

test("Windows attacker swaps the script after hash but cannot execute the new pathname bytes", { skip: process.platform !== "win32" }, async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-ci-toctou-dev-"));
  const scriptDirectory = path.join(root, "scripts", "e2e");
  mkdirSync(scriptDirectory, { recursive: true });
  const scriptPath = path.join(scriptDirectory, "fixture.ps1");
  const safeScript = "param([switch]$UnitOnly)\nWrite-Output ('SAFE_SCRIPT_ROOT=' + $PSScriptRoot)\n";
  const attackerScript = "param([switch]$UnitOnly)\nWrite-Output 'ATTACKER_BYTES_EXECUTED'\n";
  try {
    writeFileSync(scriptPath, safeScript);
    const verifiedBytes = readFileSync(scriptPath);
    const verifiedSha256 = createHash("sha256").update(verifiedBytes).digest("hex");
    assert.equal(verifiedSha256, createHash("sha256").update(safeScript).digest("hex"));
    // Deterministic stand-in for the gap between verified hash and PowerShell -File.
    writeFileSync(scriptPath, attackerScript);
    const result = await executePinnedPowerShellScriptBytes(verifiedBytes, scriptDirectory,
      { cwd: root, timeoutMs: 10_000, maxOutputBytes: 1024 });
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout.toString("utf8").trim(), `SAFE_SCRIPT_ROOT=${scriptDirectory}`);
    assert.equal(result.stdout.includes(Buffer.from("ATTACKER_BYTES_EXECUTED")), false);
    // A post-execution hash check can be satisfied after a transient swap.
    writeFileSync(scriptPath, safeScript);
    assert.equal(createHash("sha256").update(readFileSync(scriptPath)).digest("hex"), verifiedSha256);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("Windows concurrent rewrite and restore during process startup cannot affect attested script bytes", { skip: process.platform !== "win32" }, async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-ci-transient-dev-"));
  const scriptDirectory = path.join(root, "scripts", "e2e");
  mkdirSync(scriptDirectory, { recursive: true });
  const scriptPath = path.join(scriptDirectory, "fixture.ps1");
  const original = "param()\nStart-Sleep -Milliseconds 350\nWrite-Output ('VERIFIED:' + $PSScriptRoot)\n";
  const attacker = "param()\nWrite-Output 'ATTACKER_TRANSIENT_EXECUTED'\n";
  try {
    writeFileSync(scriptPath, original);
    const attested = readFileSync(scriptPath);
    const task = executePinnedPowerShellScriptBytes(attested, scriptDirectory,
      { cwd: root, timeoutMs: 10_000, maxOutputBytes: 1024 });
    writeFileSync(scriptPath, attacker);
    await new Promise((resolve) => setTimeout(resolve, 150));
    writeFileSync(scriptPath, original);
    const result = await task;
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout.toString("utf8").trim(), `VERIFIED:${scriptDirectory}`);
    assert.deepEqual(readFileSync(scriptPath), attested);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("Windows pinned streamed PowerShell preserves fixture failure semantics", { skip: process.platform !== "win32" }, async () => {
  const scriptDirectory = "C:\\synthetic\\scripts\\e2e";
  for (const [contents, exit] of [
    ["param()\nexit 7\n", 7],
    ["param()\nthrow 'SYNTHETIC_FAILURE'\n", 1],
  ]) {
    const result = await executePinnedPowerShellScriptBytes(Buffer.from(contents), scriptDirectory,
      { timeoutMs: 10_000, maxOutputBytes: 1024 });
    assert.equal(result.exitCode, exit);
  }
});

test("Windows exact 19-stage fixture reaches original Docker environment guard with its real PSScriptRoot", { skip: process.platform !== "win32" }, async () => {
  // Exercise the whole real fixture's parser and first 39 lines. This forces
  // its own guard to stop before any Docker CLI, daemon, or CI action is used.
  const scriptPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "e2e", "run-isolated-linux-docker.ps1");
  const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
    Path: process.env.Path, DOCKER_HOST: "synthetic-disallowed-test-only" };
  const result = await executePinnedPowerShellScriptBytes(readFileSync(scriptPath), path.dirname(scriptPath),
    { cwd: path.dirname(path.dirname(scriptPath)), env, timeoutMs: 10_000, maxOutputBytes: 4096 });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout.toString("utf8"), /Isolated E2E requires an unoverridden local Docker Desktop Linux context/u);
  assert.equal(result.stdout.includes(Buffer.from("Cannot find path")), false);
});

test("Windows clean source verification never launches repo-configured Git filter helpers", { skip: process.platform !== "win32" }, async () => {
  const sandbox = mkdtempSync(path.join(os.tmpdir(), "virki-ci-filter-exec-dev-"));
  const root = path.join(sandbox, "repo");
  const filter = path.join(sandbox, "filter.cjs");
  const marker = path.join(sandbox, "attacker-filter-executed.txt");
  mkdirSync(root);
  writeFileSync(filter, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'UNTRUSTED_GIT_FILTER_EXECUTED'); process.stdin.pipe(process.stdout);\n`);
  const gitBin = "C:\\Program Files\\Git\\cmd\\git.exe";
  const git = (...args) => {
    const done = spawnSync(gitBin, ["-C", root, ...args], { encoding: "utf8", timeout: 10_000 });
    assert.equal(done.status, 0, `disposable Git fixture failed: ${args[0]}`);
    return done.stdout.trim();
  };
  try {
    git("init", "-q");
    writeFileSync(path.join(root, ".gitattributes"), "*.txt filter=attack\n");
    writeFileSync(path.join(root, "fixture.txt"), "safe-original\n");
    git("add", ".gitattributes", "fixture.txt");
    git("-c", "user.name=Disposable", "-c", "user.email=disposable@invalid.local", "commit", "-qm", "fixture");
    const revision = git("rev-parse", "HEAD");
    git("config", "filter.attack.clean", `"${process.execPath}" "${filter}"`);
    await assertCleanGitWorktreeWithoutFilters(root, revision, process.env);
    writeFileSync(path.join(root, "fixture.txt"), "safe-changed!\n");
    // The original `git status` preflight invoked the configured executable
    // merely because this tracked path changed. The new inventory must reject
    // changed bytes while NEVER asking Git to run the clean filter.
    await assert.rejects(assertCleanGitWorktreeWithoutFilters(root, revision, process.env), /Tracked source differs from HEAD/u);
    assert.equal(existsSync(marker), false, "untrusted clean filter MUST NOT execute");
    assert.match(revision, /^[a-f0-9]{40}$/u);
  } finally { rmSync(sandbox, { recursive: true, force: true }); }
});

test("Windows local Git replacement refs cannot substitute an attacker tree at a trusted full SHA", { skip: process.platform !== "win32" }, async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-ci-replace-ref-dev-"));
  const gitBin = "C:\\Program Files\\Git\\cmd\\git.exe";
  const git = (...args) => {
    const run = spawnSync(gitBin, ["-C", root, ...args], { encoding: "utf8", timeout: 10_000 });
    assert.equal(run.status, 0, `disposable Git fixture failure: ${args[0]}`);
    return run.stdout.trim();
  };
  try {
    git("init", "-q");
    writeFileSync(path.join(root, "fixture.txt"), "TRUSTED_BYTES\n");
    git("add", "fixture.txt");
    git("-c", "user.name=Disposable", "-c", "user.email=disposable@invalid.local", "commit", "-qm", "trusted");
    const trusted = git("rev-parse", "HEAD");
    const trustedBlob = git("rev-parse", `${trusted}:fixture.txt`);
    writeFileSync(path.join(root, "fixture.txt"), "ATTACKER_BYTES\n");
    git("add", "fixture.txt");
    git("-c", "user.name=Disposable", "-c", "user.email=disposable@invalid.local", "commit", "-qm", "attacker");
    const attackerCommit = git("rev-parse", "HEAD");
    git("replace", trusted, attackerCommit);
    git("reset", "--hard", trusted);
    assert.equal(git("rev-parse", "HEAD"), trusted);
    assert.notEqual(git("rev-parse", `${trusted}:fixture.txt`), trustedBlob,
      "RED: replacement forged a trusted SHA into an attacker blob");
    await assert.rejects(assertCleanGitWorktreeWithoutFilters(root, trusted, process.env), /Git index differs from HEAD|Tracked source differs from HEAD/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("Windows corrupted loose Git commit object cannot forge the trusted source tree", { skip: process.platform !== "win32" }, async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-ci-git-object-corruption-dev-"));
  const gitBin = "C:\\Program Files\\Git\\cmd\\git.exe";
  const git = (...args) => {
    const run = spawnSync(gitBin, ["-C", root, ...args], { encoding: "utf8", timeout: 10_000 });
    assert.equal(run.status, 0, `disposable Git fixture failure: ${args[0]}`);
    return run.stdout.trim();
  };
  try {
    git("init", "-q");
    writeFileSync(path.join(root, "fixture.txt"), "TRUSTED_BYTES\n");
    git("add", "fixture.txt");
    git("-c", "user.name=Disposable", "-c", "user.email=disposable@invalid.local", "commit", "-qm", "trusted");
    const trusted = git("rev-parse", "HEAD");
    const trustedCommitRaw = spawnSync(gitBin, ["-C", root, "cat-file", "commit", trusted], { encoding: "utf8" }).stdout;
    writeFileSync(path.join(root, "fixture.txt"), "ATTACKER_BYTES\n");
    git("add", "fixture.txt");
    git("-c", "user.name=Disposable", "-c", "user.email=disposable@invalid.local", "commit", "-qm", "attacker");
    const attackerTree = git("rev-parse", "HEAD^{tree}");
    const corrupted = Buffer.from(trustedCommitRaw.replace(/^tree [a-f0-9]{40}/u, `tree ${attackerTree}`));
    const forged = deflateSync(Buffer.concat([Buffer.from(`commit ${corrupted.length}\0`), corrupted]));
    const objectFile = path.join(root, ".git", "objects", trusted.slice(0, 2), trusted.slice(2));
    rmSync(objectFile, { force: true });
    writeFileSync(objectFile, forged);
    git("reset", "--hard", trusted);
    assert.equal(git("rev-parse", "HEAD"), trusted);
    assert.equal(git("rev-parse", `${trusted}:fixture.txt`), git("hash-object", "fixture.txt"));
    await assert.rejects(assertCleanGitWorktreeWithoutFilters(root, trusted, process.env), /Git commit object hash differs from trusted revision/u);
  } finally { try { rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }); } catch { /* Windows file permissions of disposable git objects may require ACL cleanup. */ } }
});

test("Windows corrupted loose Git tree object cannot forge source bytes under the trusted commit", { skip: process.platform !== "win32" }, async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-ci-git-tree-corruption-dev-"));
  const gitBin = "C:\\Program Files\\Git\\cmd\\git.exe";
  const git = (...args) => {
    const done = spawnSync(gitBin, ["-C", root, ...args], { encoding: "utf8", timeout: 10_000 });
    assert.equal(done.status, 0, `disposable Git fixture failure: ${args[0]} ${done.stderr}`);
    return done.stdout.trim();
  };
  try {
    git("init", "-q");
    writeFileSync(path.join(root, "fixture.txt"), "TRUSTED_CONTENT\n");
    git("add", "fixture.txt");
    git("-c", "user.name=Disposable", "-c", "user.email=disposable@invalid.local", "commit", "-qm", "trusted");
    const trusted = git("rev-parse", "HEAD");
    const treeId = git("rev-parse", "HEAD^{tree}");
    writeFileSync(path.join(root, "fixture.txt"), "ATTACKER_CONTENT\n");
    const forgedBlob = git("hash-object", "-w", "fixture.txt");
    const tree = spawnSync(gitBin, ["-C", root, "cat-file", "tree", treeId], { timeout: 10_000 }).stdout;
    const oidPosition = tree.indexOf(0) + 1;
    assert.ok(oidPosition > 0 && oidPosition + 20 === tree.length);
    const forgedTree = Buffer.from(tree);
    Buffer.from(forgedBlob, "hex").copy(forgedTree, oidPosition);
    const framed = Buffer.concat([Buffer.from(`tree ${forgedTree.length}\0`), forgedTree]);
    const objectFile = path.join(root, ".git", "objects", treeId.slice(0, 2), treeId.slice(2));
    rmSync(objectFile, { force: true });
    writeFileSync(objectFile, deflateSync(framed));
    const gitDecode = spawnSync(gitBin, ["-C", root, "cat-file", "tree", treeId], { timeout: 10_000 });
    assert.equal(gitDecode.status, 0, "Git cat-file alone accepts forged tree bytes under trusted SHA");
    assert.deepEqual(gitDecode.stdout, forgedTree);
    assert.equal(git("rev-parse", "HEAD"), trusted);
    await assert.rejects(assertCleanGitWorktreeWithoutFilters(root, trusted, process.env), /Git tree object hash differs from trusted revision/u);
  } finally { try { rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }); } catch { /* disposable Git object permissions on Windows */ } }
});

test("Windows real 19-stage PowerShell snapshot executes no repo fsmonitor or filter command and preserves bundle plus diff", { skip: process.platform !== "win32" }, () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-snapshot-git-safety-dev-"));
  const repo = path.join(root, "repo");
  const staged = path.join(root, "snapshot with spaces");
  const bundle = path.join(staged, "source.bundle");
  const workingPatch = path.join(staged, "working.patch");
  const stagedPatch = path.join(staged, "staged.patch");
  const marker = path.join(repo, "ATTACKER_FS_MONITOR_MARKER");
  const filterMarker = path.join(repo, "ATTACKER_CLEAN_FILTER_MARKER");
  const hookMarker = path.join(repo, "ATTACKER_HOOK_MARKER");
  const diffMarker = path.join(repo, "ATTACKER_EXTERNAL_DIFF_MARKER");
  const pinnedGit = "C:\\Program Files\\Git\\cmd\\git.exe";
  const runGit = (...args) => {
    const result = spawnSync(pinnedGit, ["-C", repo, ...args], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.status, 0, `Git fixture failed: ${args[0]} ${result.stderr}`);
    return result.stdout.trim();
  };
  try {
    mkdirSync(repo);
    mkdirSync(staged);
    runGit("init", "-q");
    writeFileSync(path.join(repo, ".gitattributes"), "*.txt filter=attack\n");
    writeFileSync(path.join(repo, "fixture.txt"), "GOOD_SOURCE\n");
    writeFileSync(path.join(repo, "staged.txt"), "STAGED_ORIGINAL\n");
    runGit("add", ".gitattributes", "fixture.txt", "staged.txt");
    runGit("-c", "user.name=Disposable", "-c", "user.email=test@invalid.local", "commit", "-qm", "initial");
    const branch = runGit("branch", "--show-current");
    const head = runGit("rev-parse", "HEAD");
    runGit("tag", "snapshot-keep-tag");
    runGit("update-ref", `refs/replace/${head}`, head);
    // Stage trusted test data before installing adversarial .git/config,
    // otherwise the attack filter deliberately changes the Git index bytes.
    writeFileSync(path.join(repo, "staged.txt"), "STAGED_NEW\n");
    runGit("add", "staged.txt");
    runGit("config", "core.fsmonitor", `echo ATTACKER_BYTES_EXECUTED > ${marker.replace(/\\/gu, "/")}`);
    runGit("config", "filter.attack.clean", `echo ATTACKER_BYTES_EXECUTED > ${filterMarker.replace(/\\/gu, "/")}`);
    runGit("config", "diff.external", `echo ATTACKER_BYTES_EXECUTED > ${diffMarker.replace(/\\/gu, "/")}`);
    const hooks = path.join(repo, "adversarial-hooks");
    mkdirSync(hooks);
    writeFileSync(path.join(hooks, "pre-commit"), `#!/bin/sh\necho ATTACKER_BYTES_EXECUTED > '${hookMarker.replace(/\\/gu, "/")}'\n`);
    runGit("config", "core.hooksPath", hooks);
    writeFileSync(path.join(repo, "fixture.txt"), "MODIFIED_SOURCE\n");
    // RED: the old raw host Git diff touches candidate-controlled config.
    spawnSync(pinnedGit, ["-C", repo, "diff", "--binary"], { timeout: 10_000 });
    assert.ok(existsSync(marker) || existsSync(filterMarker), "RED host Git invocation must demonstrate executable configuration");
    rmSync(marker, { force: true });
    rmSync(filterMarker, { force: true });
    rmSync(diffMarker, { force: true });

    const psFile = path.join(path.dirname(fileURLToPath(import.meta.url)), "e2e", "run-isolated-linux-docker.ps1");
    const quote = (value) => `'${value.replace(/'/gu, "''")}'`;
    const driver = `
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(${quote(psFile)},[ref]$tokens,[ref]$errors)
if($errors.Count -gt 0){throw 'PowerShell fixture failed to parse'}
$fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-IsolatedGitSnapshot'},$true)
if(-not $fn){throw 'Real isolated Git snapshot function is absent'}
$gitFn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-PinnedGit'},$true)
if(-not $gitFn){throw 'Real pinned Git helper is absent'}
$script:pinnedGit=${quote(pinnedGit)}
$env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL='NUL';$env:GIT_NO_REPLACE_OBJECTS='1'
Invoke-Expression $gitFn.Extent.Text
Invoke-Expression $fn.Extent.Text
New-IsolatedGitSnapshot -SourceRoot ${quote(repo)} -SourceBranch ${quote(branch)} -ExpectedHead ${quote(head)} -SnapshotRoot ${quote(staged)} -BundleFile ${quote(bundle)} -StagedPatchFile ${quote(stagedPatch)} -WorkingPatchFile ${quote(workingPatch)} | Out-Null
if($LASTEXITCODE -ne 0){throw 'Sanitized snapshot native command failure'}
Write-Output 'SANITIZED_GIT_SNAPSHOT_PASS'
`;
    const invoked = spawnSync("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", driver], { encoding: "utf8", timeout: 30_000 });
    assert.equal(invoked.status, 0, `${invoked.stdout}\n${invoked.stderr}`);
    assert.match(invoked.stdout, /SANITIZED_GIT_SNAPSHOT_PASS/u);
    assert.equal(existsSync(marker), false, "new snapshot must never run fsmonitor");
    assert.equal(existsSync(filterMarker), false, "new snapshot must never run a clean filter");
    assert.equal(existsSync(hookMarker), false, "new snapshot must never run checkout-local hooks");
    assert.equal(existsSync(diffMarker), false, "new snapshot must never run configured diff executables");
    assert.match(readFileSync(stagedPatch, "utf8"), /STAGED_NEW/u);
    assert.match(readFileSync(workingPatch, "utf8"), /MODIFIED_SOURCE/u);
    const clone = path.join(root, "clone");
    const cloned = spawnSync(pinnedGit, ["clone", "-q", "--branch", branch, bundle, clone], { encoding: "utf8", timeout: 30_000 });
    assert.equal(cloned.status, 0, cloned.stderr);
    assert.equal(spawnSync(pinnedGit, ["-C", clone, "tag", "--list", "snapshot-keep-tag"],
      { encoding: "utf8", timeout: 10_000 }).stdout.trim(), "snapshot-keep-tag", "--all tag semantics must survive");
    assert.equal(spawnSync(pinnedGit, ["-C", clone, "show-ref", `refs/replace/${head}`],
      { encoding: "utf8", timeout: 10_000 }).status, 1, "refs/replace must never be carried into the disposable clone");
    const appliedStaged = spawnSync(pinnedGit, ["-C", clone, "apply", "--binary", stagedPatch], { encoding: "utf8", timeout: 15_000 });
    assert.equal(appliedStaged.status, 0, appliedStaged.stderr);
    const applied = spawnSync(pinnedGit, ["-C", clone, "apply", "--binary", workingPatch], { encoding: "utf8", timeout: 15_000 });
    assert.equal(applied.status, 0, applied.stderr);
    assert.equal(readFileSync(path.join(clone, "fixture.txt"), "utf8").replace(/\r\n/gu, "\n"), "MODIFIED_SOURCE\n");
    assert.equal(readFileSync(path.join(clone, "staged.txt"), "utf8").replace(/\r\n/gu, "\n"), "STAGED_NEW\n");
  } finally { rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }); }
});

test("Windows same-account attacker cannot rearm filter.clean by swapping the writable safe-git config mid-snapshot", { skip: process.platform !== "win32" }, async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-safe-git-race-dev-"));
  const repo = path.join(root, "repo");
  const staged = path.join(root, "snapshot");
  const marker = path.join(root, "ATTACKER_FROM_SAFE_GIT_CONFIG");
  const attempted = path.join(root, "ATTACKER_ATTEMPTED_SAFE_GIT_CONFIG_REWRITE");
  const injectedConfig = path.join(staged, "safe-git", "config");
  const pinnedGit = "C:\\Program Files\\Git\\cmd\\git.exe";
  const runGit = (...args) => {
    const result = spawnSync(pinnedGit, ["-C", repo, ...args], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.status, 0, `${result.stderr}`);
    return result.stdout.trim();
  };
  let watcher;
  try {
    mkdirSync(repo);
    mkdirSync(staged);
    runGit("init", "-q");
    writeFileSync(path.join(repo, ".gitattributes"), "*.txt filter=attack\n");
    writeFileSync(path.join(repo, "fixture.txt"), "ORIGINAL\n");
    runGit("add", ".gitattributes", "fixture.txt");
    runGit("-c", "user.name=Disposable", "-c", "user.email=test@invalid.local", "commit", "-qm", "initial");
    const branchName = runGit("branch", "--show-current");
    const head = runGit("rev-parse", "HEAD");
    writeFileSync(path.join(repo, "fixture.txt"), "MUTATED_SOURCE_WITH_DIFFERENT_SIZE\n");
    const hostileConfig = `[core]\nrepositoryformatversion = 0\nbare = false\nfsmonitor = false\n[filter "attack"]\nclean = sh -c 'echo ATTACKER_BYTES_EXECUTED > ${marker.replace(/\\/gu, "/")} && cat'\n`;
    const watcherSource = `const fs=require('node:fs'); const config=${JSON.stringify(injectedConfig)}; const content=${JSON.stringify(hostileConfig)}; const attempted=${JSON.stringify(attempted)};
const started=Date.now(); const poll=setInterval(()=>{if(fs.existsSync(config)){fs.writeFileSync(attempted,'attempted');try{fs.writeFileSync(config,content)}catch{ /* Windows kernel sharing lock denied the attacker */ }clearInterval(poll);process.exit(0)}else if(Date.now()-started>12000){clearInterval(poll);process.exit(2)}},1);`;
    watcher = spawn(process.execPath, ["-e", watcherSource], { stdio: "ignore", windowsHide: true });
    await new Promise((resolve) => setTimeout(resolve, 200));
    const source = path.join(path.dirname(fileURLToPath(import.meta.url)), "e2e", "run-isolated-linux-docker.ps1");
    const quote = (s) => `'${s.replace(/'/gu, "''")}'`;
    const driver = `
$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(${quote(source)},[ref]$tokens,[ref]$errors)
if($errors.Count -gt 0){throw 'Invalid PowerShell fixture'}
$gitFn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-PinnedGit'},$true)
$fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-IsolatedGitSnapshot'},$true)
$script:pinnedGit=${quote(pinnedGit)}
$env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL='NUL';$env:GIT_NO_REPLACE_OBJECTS='1'
Invoke-Expression $gitFn.Extent.Text; Invoke-Expression $fn.Extent.Text
New-IsolatedGitSnapshot -SourceRoot ${quote(repo)} -SourceBranch ${quote(branchName)} -ExpectedHead ${quote(head)} -SnapshotRoot ${quote(staged)} -BundleFile ${quote(path.join(staged, "source.bundle"))} -StagedPatchFile ${quote(path.join(staged, "staged.patch"))} -WorkingPatchFile ${quote(path.join(staged, "worktree.patch"))} | Out-Null
`;
    const invoked = spawnSync("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", driver], { timeout: 30_000, encoding: "utf8" });
    assert.equal(existsSync(attempted), true, "same-account adversary must attempt the temp config rewrite");
    assert.equal(existsSync(marker), false, `same-account filter.clean code executed: ${invoked.stdout} ${invoked.stderr}`);
    if (invoked.status === 0) {
      assert.doesNotMatch(readFileSync(injectedConfig, "utf8"), /ATTACKER_BYTES_EXECUTED/u,
        "successful snapshot must retain the original pinned config");
    } else {
      assert.match(invoked.stderr, /Isolated Git config changed before its kernel pin was established/u,
        "a pre-lock concurrent write must fail the snapshot closed");
    }
    // Control: a Git porcelain status with the same poisoned private config
    // must be capable of invoking the hostile filter. The snapshot itself
    // deliberately invokes only bundle, --no-ext-diff and ls-files.
    // Lock scope has ended: an identical malicious config is demonstrably
    // executable by native Git outside the protected critical section.
    writeFileSync(injectedConfig, hostileConfig);
    writeFileSync(path.join(repo, "fixture.txt"), "AFTER_SNAPSHOT_FORCE_FRESH_FILTER_CONVERSION_WITH_NEW_SIZE\n");
    const control = spawnSync(pinnedGit, [(`--git-dir=${path.join(staged, "safe-git")}`),
      (`--work-tree=${repo}`), "-c", "core.fsmonitor=false", "diff", "--no-ext-diff", "--no-textconv", "--binary"],
    { timeout: 10_000, encoding: "utf8" });
    assert.equal(control.status, 0, control.stderr);
    assert.equal(existsSync(marker), true, `control poisoned filter.clean must demonstrate real Git execution; status=${control.stdout}; stderr=${control.stderr}`);
  } finally {
    if (watcher) watcher.kill();
    rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
});

test("Windows W52 cross-boundary transient checkout poison: dirty snapshot RED, prebound clean snapshot GREEN and final Git object verified", { skip: process.platform !== "win32" }, async () => {
  const sandbox = mkdtempSync(path.join(os.tmpdir(), "virki-w52-transient-worktree-dev-"));
  const root = path.join(sandbox, "repo");
  const trustedContent = "SAFE_SOURCE_ONLY\n";
  const attackerContent = "ATTACKER_BYTES_EXECUTED\n";
  const script = path.join(root, "payload.txt");
  const git = "C:\\Program Files\\Git\\cmd\\git.exe";
  const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const commandGit = (cwd, ...args) => {
    const result = spawnSync(git, ["-C", cwd, ...args], { encoding: "utf8", timeout: 20_000 });
    assert.equal(result.status, 0, `disposable Git: ${args.join(" ")} ${result.stderr}`);
    return result.stdout.trim();
  };
  try {
    mkdirSync(root);
    commandGit(root, "init", "-q");
    writeFileSync(script, trustedContent);
    commandGit(root, "add", "payload.txt");
    commandGit(root, "-c", "user.name=Disposable", "-c", "user.email=test@invalid.local", "commit", "-qm", "trusted");
    const revision = commandGit(root, "rev-parse", "HEAD");
    const branchName = commandGit(root, "branch", "--show-current");
    const fixture = path.join(path.dirname(fileURLToPath(import.meta.url)), "e2e", "run-isolated-linux-docker.ps1");
    const quote = (value) => `'${value.replace(/'/gu, "''")}'`;
    for (const [mode, isClean] of [["legacy-dirty-snapshot", false], ["pinned-clean-snapshot", true]]) {
      const destination = path.join(sandbox, mode);
      mkdirSync(destination);
      const bundle = path.join(destination, "verified.bundle");
      const staged = path.join(destination, "staged.patch");
      const working = path.join(destination, "working.patch");
      // Same clean preflight as the real Node entrypoint. Attacker now races
      // only the gap AFTER this gate, never the verified original Git graph.
      await assertCleanGitWorktreeWithoutFilters(root, revision, process.env);
      writeFileSync(script, attackerContent);
      const driver = `
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(${quote(fixture)},[ref]$tokens,[ref]$errors)
if($errors.Count -gt 0){throw 'Fixture syntax error'}
$gitFn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-PinnedGit'},$true)
$fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-IsolatedGitSnapshot'},$true)
$blobFn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-VerifiedCommittedGitBlob'},$true)
$objectFn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Read-VerifiedGitObjectBytes'},$true)
$treeFn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Find-VerifiedGitTreeEntry'},$true)
$shaFn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-FileSha256'},$true)
$script:pinnedGit=${quote(git)}
$env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL='NUL';$env:GIT_NO_REPLACE_OBJECTS='1'
Invoke-Expression $gitFn.Extent.Text;Invoke-Expression $fn.Extent.Text
Invoke-Expression $objectFn.Extent.Text;Invoke-Expression $treeFn.Extent.Text
Invoke-Expression $blobFn.Extent.Text;Invoke-Expression $shaFn.Extent.Text
New-IsolatedGitSnapshot -SourceRoot ${quote(root)} -SourceBranch ${quote(branchName)} -ExpectedHead ${quote(revision)} -SnapshotRoot ${quote(destination)} -BundleFile ${quote(bundle)} -StagedPatchFile ${quote(staged)} -WorkingPatchFile ${quote(working)} -PinnedCleanRunner:$${isClean ? "true" : "false"} | Out-Null
${isClean ? `New-VerifiedCommittedGitBlob -SourceRoot ${quote(root)} -ExpectedHead ${quote(revision)} -RelativePath 'payload.txt' -Destination ${quote(path.join(destination, "committed-payload.txt"))} | Out-Null` : ""}
`;
      const output = spawnSync(ps, ["-NoProfile", "-NonInteractive", "-Command", driver], { encoding: "utf8", timeout: 30_000 });
      // Attacker restores the source before the exact Node POSTCHECK.
      writeFileSync(script, trustedContent);
      assert.equal(output.status, 0, `${mode}: ${output.stdout}\n${output.stderr}`);
      await assertCleanGitWorktreeWithoutFilters(root, revision, process.env);
      const patchContents = readFileSync(working, "utf8");
      if (!isClean) assert.match(patchContents, /ATTACKER_BYTES_EXECUTED/u, "RED old snapshot exports transient attacker bytes despite two clean Node probes");
      else {
        assert.equal(readFileSync(working).length, 0, "GREEN never exports worktree bytes");
        assert.equal(readFileSync(staged).length, 0, "GREEN never exports index bytes");
        assert.equal(readFileSync(path.join(destination, "committed-payload.txt"), "utf8"), trustedContent,
          "GREEN PostgreSQL-style initialization files also originate from independently verified committed Git blob bytes");
      }
      const clone = path.join(sandbox, `${mode}-clone`);
      commandGit(sandbox, "clone", "-q", "--branch", branchName, bundle, clone);
      if (!isClean) commandGit(clone, "apply", "--binary", working);
      assert.equal(readFileSync(path.join(clone, "payload.txt"), "utf8").replace(/\r\n/gu, "\n"),
        isClean ? trustedContent : attackerContent);
      if (isClean) {
        commandGit(clone, "fsck", "--full", "--strict", "--no-reflogs");
        assert.equal(commandGit(clone, "status", "--porcelain", "--untracked-files=all"), "");
        assert.equal(commandGit(clone, "rev-parse", "HEAD"), revision);
      }
    }
  } finally {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
});

test("Windows attacker-forged loose commit after clean bundle cannot supply executable PostgreSQL init bytes", { skip: process.platform !== "win32" }, async () => {
  const sandbox = mkdtempSync(path.join(os.tmpdir(), "virki-pg-init-commit-object-race-dev-"));
  const repo = path.join(sandbox, "repo");
  const relative = "infra/postgres-init/10-virki-database-roles.sh";
  const trusted = "#!/bin/sh\nprintf SAFE_SOURCE_ONLY\\n\n";
  const attacker = "#!/bin/sh\necho ATTACKER_BYTES_EXECUTED\n";
  const git = "C:\\Program Files\\Git\\cmd\\git.exe";
  const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const quote = (value) => `'${value.replace(/'/gu, "''")}'`;
  const gitRun = (...args) => {
    const result = spawnSync(git, ["-C", repo, ...args], { encoding: "utf8", timeout: 20_000 });
    assert.equal(result.status, 0, `${args.join(" ")}: ${result.stderr}`);
    return result.stdout.trim();
  };
  const runPowerShell = (body) => spawnSync(ps, ["-NoProfile", "-NonInteractive", "-Command", `
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(${quote(path.join(path.dirname(fileURLToPath(import.meta.url)), "e2e", "run-isolated-linux-docker.ps1"))},[ref]$tokens,[ref]$errors)
if($errors.Count -gt 0){throw 'Source PowerShell AST invalid'}
foreach($name in @('Invoke-PinnedGit','New-IsolatedGitSnapshot','Read-VerifiedGitObjectBytes','Find-VerifiedGitTreeEntry','New-VerifiedCommittedGitBlob')) {
  $fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
  # Optional helpers were added with the fix. The old vulnerable implementation
  # has no such helpers and must fail this exact attacker test semantically,
  # not merely because the test harness cannot import its functions.
  if(-not $fn -and $name -in @('Invoke-PinnedGit','New-IsolatedGitSnapshot','New-VerifiedCommittedGitBlob')) {
    throw ('Missing required fixture function: '+$name)
  }
  if($fn){Invoke-Expression $fn.Extent.Text}
}
$script:pinnedGit=${quote(git)}
$env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL='NUL';$env:GIT_NO_REPLACE_OBJECTS='1'
${body}
`], { encoding: "utf8", timeout: 30_000 });
  try {
    mkdirSync(repo);
    gitRun("init", "-q");
    const script = path.join(repo, "infra", "postgres-init", "10-virki-database-roles.sh");
    mkdirSync(path.dirname(script), { recursive: true });
    writeFileSync(script, trusted);
    gitRun("add", relative);
    gitRun("-c", "user.name=Disposable", "-c", "user.email=dev@invalid.local", "commit", "-qm", "source-pinned");
    const head = gitRun("rev-parse", "HEAD");
    const branch = gitRun("branch", "--show-current");
    const originalCommit = spawnSync(git, ["-C", repo, "cat-file", "commit", head], { timeout: 10_000 });
    assert.equal(originalCommit.status, 0);
    const originalTree = gitRun("rev-parse", `${head}^{tree}`);
    // Create the adversarial referenced tree/blob in Git without committing
    // them. Both object payloads are valid and independently self-hashed.
    writeFileSync(script, attacker);
    gitRun("add", relative);
    const attackerTree = gitRun("write-tree");
    assert.notEqual(attackerTree, originalTree);
    gitRun("reset", "-q", "HEAD");
    writeFileSync(script, trusted);
    await assertCleanGitWorktreeWithoutFilters(repo, head, process.env);

    // Generate the pinned clean bundle BEFORE the attacker swaps the loose
    // commit. This bundle must remain clean, regardless of later source store
    // mutation; a separate init-script extraction must share its provenance.
    const bundle = path.join(sandbox, "verified.bundle");
    const snapshot = runPowerShell(`New-IsolatedGitSnapshot -SourceRoot ${quote(repo)} -SourceBranch ${quote(branch)} -ExpectedHead ${quote(head)} -SnapshotRoot ${quote(sandbox)} -BundleFile ${quote(bundle)} -StagedPatchFile ${quote(path.join(sandbox, "staged.patch"))} -WorkingPatchFile ${quote(path.join(sandbox, "working.patch"))} -PinnedCleanRunner | Out-Null`);
    assert.equal(snapshot.status, 0, `${snapshot.stdout}\n${snapshot.stderr}`);
    const looseCommitPath = path.join(repo, ".git", "objects", head.slice(0, 2), head.slice(2));
    const originalLooseBytes = readFileSync(looseCommitPath);
    const originalLooseMode = statSync(looseCommitPath).mode & 0o777;
    const forgedCommit = Buffer.from(originalCommit.stdout.toString("utf8").replace(
      `tree ${originalTree}\n`, `tree ${attackerTree}\n`));
    assert.notDeepEqual(forgedCommit, originalCommit.stdout);
    const framed = Buffer.concat([Buffer.from(`commit ${forgedCommit.length}\0`), forgedCommit]);
    const forgedSha = createHash("sha1").update(framed).digest("hex");
    assert.notEqual(forgedSha, head, "attack MUST violate trusted commit SHA while retaining its pathname");
    try {
      chmodSync(looseCommitPath, 0o600);
      writeFileSync(looseCommitPath, deflateSync(framed));
      const denied = runPowerShell(`
try {
  New-VerifiedCommittedGitBlob -SourceRoot ${quote(repo)} -ExpectedHead ${quote(head)} -RelativePath ${quote(relative)} -Destination ${quote(path.join(sandbox, "poisoned-init.sh"))} | Out-Null
  throw 'UNEXPECTED_FORGED_COMMIT_ACCEPTED'
} catch {
  if($_.Exception.Message -cnotmatch 'independently computed framed SHA-1') { throw }
  Write-Output 'FORGED_COMMIT_BLOCKED_BY_PARENT_HASH'
}`);
      assert.equal(denied.status, 0, `${denied.stdout}\n${denied.stderr}`);
      assert.match(denied.stdout, /FORGED_COMMIT_BLOCKED_BY_PARENT_HASH/u);
      assert.equal(existsSync(path.join(sandbox, "poisoned-init.sh")), false);
    } finally {
      writeFileSync(looseCommitPath, originalLooseBytes);
      chmodSync(looseCommitPath, originalLooseMode);
    }
    await assertCleanGitWorktreeWithoutFilters(repo, head, process.env);
    const accepted = runPowerShell(`New-VerifiedCommittedGitBlob -SourceRoot ${quote(repo)} -ExpectedHead ${quote(head)} -RelativePath ${quote(relative)} -Destination ${quote(path.join(sandbox, "verified-init.sh"))} | Out-Null`);
    assert.equal(accepted.status, 0, `${accepted.stdout}\n${accepted.stderr}`);
    assert.equal(readFileSync(path.join(sandbox, "verified-init.sh"), "utf8"), trusted);
    const clone = path.join(sandbox, "bundle-clone");
    const cloneResult = spawnSync(git, ["clone", "-q", "--branch", branch, bundle, clone], { encoding: "utf8", timeout: 20_000 });
    assert.equal(cloneResult.status, 0, cloneResult.stderr);
    // Windows Git may check out CRLF even though the canonical blob is LF.
    assert.equal(readFileSync(path.join(clone, relative), "utf8").replace(/\r\n/gu, "\n"), trusted);
  } finally {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
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
