import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { executeBoundedLocalCommand, buildLocalStageReceipts, readStableLocalEvidenceFile } from "./lib/offline-ci-local-runner.mjs";

const SHA = /^[a-f0-9]{40}$/u;
const BRANCH = /^(?!\/)(?!.*(?:\/\/|\.\.))[A-Za-z0-9._/-]{1,200}$/u;
const SCRIPT = "scripts/e2e/run-isolated-linux-docker.ps1";
const MAX_RUN_MS = 3 * 60 * 60 * 1000;
const PINNED_GIT = "C:\\Program Files\\Git\\cmd\\git.exe";
const PINNED_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

function blocked(reason) { throw new Error(`Offline 19-stage local validation BLOCKED: ${reason}`); }

function isolatedWindowsEnvironment() {
  // Do not inherit GIT_DIR, GIT_INDEX_FILE, GIT_CONFIG_* or deployment secrets.
  const environmentNames = ["PATHEXT", "SystemRoot", "WINDIR", "TEMP", "TMP", "APPDATA",
    "LOCALAPPDATA", "USERPROFILE", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "COMSPEC",
    "PSModulePath", "HOMEDRIVE", "HOMEPATH", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"];
  const env = Object.fromEntries(environmentNames.filter((key) => typeof process.env[key] === "string")
    .map((key) => [key, process.env[key]]));
  env.Path = [path.dirname(PINNED_GIT), "C:\\Windows\\System32", "C:\\Windows"].join(path.delimiter);
  return env;
}

async function git(root, ...args) {
  const output = await executeBoundedLocalCommand(PINNED_GIT, ["-C", root, "-c", "core.fsmonitor=false", ...args], {
    cwd: root, env: isolatedWindowsEnvironment(), timeoutMs: 30_000, maxOutputBytes: 128 * 1024,
  });
  if (output.exitCode !== 0 || output.truncated || output.timedOut || output.spawnError) blocked("Git state verification failed");
  return output.stdout.toString("utf8").trim();
}

async function verifyGitExecutable() {
  const expected = PINNED_GIT.toLowerCase();
  if (!existsSync(PINNED_GIT) || realpathSync.native(PINNED_GIT).toLowerCase() !== expected ||
      !lstatSync(PINNED_GIT).isFile() || lstatSync(PINNED_GIT).isSymbolicLink()) {
    blocked("pinned Git for Windows executable is unavailable or aliased");
  }
  const signature = await executeBoundedLocalCommand(PINNED_POWERSHELL, [
    "-NoProfile", "-NonInteractive", "-Command",
    "$s = Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath 'C:\\Program Files\\Git\\cmd\\git.exe'; if ($s.Status -eq 'Valid' -and $s.SignerCertificate -and $s.SignerCertificate.Subject.StartsWith('CN=Johannes Schindelin,', [System.StringComparison]::OrdinalIgnoreCase)) { [Console]::Out.Write('SIGNED_GIT_OK') } else { exit 1 }",
  ], { env: isolatedWindowsEnvironment(), timeoutMs: 15_000, maxOutputBytes: 2048 });
  if (signature.exitCode !== 0 || signature.stdout.toString("utf8").trim() !== "SIGNED_GIT_OK" ||
      signature.timedOut || signature.truncated || signature.spawnError) {
    blocked("pinned Git for Windows Authenticode identity is unverified");
  }
  return createHash("sha256").update(readFileSync(PINNED_GIT)).digest("hex");
}

async function assertCleanRevision(root, revision, branch) {
  const [head, observedBranch, status, trackedScript, committedBlob, workingBlob] = await Promise.all([
    git(root, "rev-parse", "HEAD"), git(root, "branch", "--show-current"),
    git(root, "status", "--porcelain=v1", "--untracked-files=all"),
    git(root, "ls-files", "--error-unmatch", "--", SCRIPT),
    git(root, "rev-parse", `${revision}:${SCRIPT}`),
    git(root, "hash-object", "--", SCRIPT),
  ]);
  if (head !== revision || observedBranch !== branch || status !== "" || trackedScript !== SCRIPT) {
    blocked("expected clean exact source SHA, branch and tracked pinned launcher are required");
  }
  const scriptPath = path.join(root, SCRIPT);
  if (lstatSync(scriptPath).isSymbolicLink() || !lstatSync(scriptPath).isFile()) {
    blocked("runner script is not a regular tracked file");
  }
  // Compare the Git-filtered blob identity to handle Windows CRLF checkouts.
  // Also bind raw bytes before/after execution against a transient replacement.
  if (workingBlob !== committedBlob) {
    blocked("pinned launcher bytes differ from the committed revision");
  }
  return createHash("sha256").update(readFileSync(scriptPath)).digest("hex");
}

/** Explicit opt-in. The CLI never accepts an executable, command map or test result. */
export async function runOfflineCiLocally({ repositoryRoot, revision, branch, offline }) {
  if (offline !== true || !SHA.test(revision ?? "") || !BRANCH.test(branch ?? "")) {
    blocked("explicit --offline, full revision and branch are mandatory");
  }
  if (process.platform !== "win32") blocked("pinned Docker Desktop fixture requires Windows host");
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) blocked("absolute repository root required");
  const root = realpathSync(repositoryRoot);
  if (root !== path.resolve(repositoryRoot) || !existsSync(path.join(root, ".git"))) blocked("repository root is not canonical");
  const gitInitialSha256 = await verifyGitExecutable();
  const launcherInitialSha256 = await assertCleanRevision(root, revision, branch);

  const evidenceParent = path.join(root, ".virki-mission-tmp", "isolated-runs");
  if (await git(root, "check-ignore", ".virki-mission-tmp/isolated-runs") !== ".virki-mission-tmp/isolated-runs") {
    blocked("evidence root is not Git ignored");
  }
  const evidenceTop = path.dirname(evidenceParent);
  if (existsSync(evidenceTop) && realpathSync(evidenceTop) !== evidenceTop) blocked("evidence parent alias is forbidden");
  mkdirSync(evidenceParent, { recursive: true, mode: 0o700 });
  if (realpathSync(evidenceParent) !== evidenceParent || lstatSync(evidenceParent).isSymbolicLink()) {
    blocked("evidence directory alias is forbidden");
  }

  // The PowerShell fixture resolves Git only from the pinned signed location.
  const env = isolatedWindowsEnvironment();
  env.VIRKI_E2E_HUB_MODE = "production";
  const startedUtc = new Date().toISOString();
  const run = await executeBoundedLocalCommand(PINNED_POWERSHELL,
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path.join(root, SCRIPT)],
    { cwd: root, env, timeoutMs: MAX_RUN_MS });
  if (run.exitCode !== 0 || run.timedOut || run.truncated || run.spawnError) {
    blocked(`isolated launcher failed (exit=${String(run.exitCode)}, timeout=${run.timedOut}, oversized=${run.truncated})`);
  }
  const consoleText = new TextDecoder("utf-8", { fatal: true }).decode(run.stdout);
  const directoryMatches = [...consoleText.matchAll(/^RUN_EVIDENCE_DIRECTORY=(.+)$/gmu)];
  if (directoryMatches.length !== 1) blocked("run evidence directory was absent or ambiguous");
  const evidenceDir = path.resolve(directoryMatches[0][1].trim());
  if (path.dirname(evidenceDir).toLowerCase() !== evidenceParent.toLowerCase() ||
      !/^[a-f0-9]{32}$/u.test(path.basename(evidenceDir)) ||
      lstatSync(evidenceDir).isSymbolicLink() || !lstatSync(evidenceDir).isDirectory()) {
    blocked("runner returned a noncanonical evidence path");
  }
  const manifestPath = path.join(evidenceDir, "run-manifest.json");
  const rawManifest = readStableLocalEvidenceFile(manifestPath, 64 * 1024);
  const receipt = buildLocalStageReceipts({ manifestBytes: rawManifest, stdout: run.stdout,
    revision, branch, stageLogDirectory: evidenceDir });
  if (receipt.runId !== path.basename(evidenceDir)) blocked("manifest run ID differs from isolated directory");
  if (launcherInitialSha256 !== await assertCleanRevision(root, revision, branch)) {
    blocked("runner script changed while the isolated suite was executing");
  }
  if (gitInitialSha256 !== await verifyGitExecutable()) blocked("Git executable changed during validation");
  const final = {
    ...receipt, launcherSha256: launcherInitialSha256, gitExecutableSha256: gitInitialSha256,
    startedUtc, finishedUtc: new Date().toISOString(),
  };
  const receiptPath = path.join(evidenceDir, "offline-local-stage-receipts.json");
  writeFileSync(receiptPath, `${JSON.stringify(final, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  return Object.freeze({
    status: "LOCAL_PASS_19_UNTRUSTED", revision, branch, receiptPath,
    receiptsSha256: createHash("sha256").update(readFileSync(receiptPath)).digest("hex"),
    codeql: "NOT_RUN", hostedCi: "NOT_RUN", deployAuthorized: false,
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
const modulePath = fileURLToPath(import.meta.url);
const canonicalInvoked = invokedPath ? realpathSync.native(invokedPath) : null;
const canonicalModule = realpathSync.native(modulePath);
const sameEntry = canonicalInvoked !== null && (process.platform === "win32"
  ? canonicalInvoked.toLowerCase() === canonicalModule.toLowerCase()
  : canonicalInvoked === canonicalModule);
const hasAlias = sameEntry && (process.platform === "win32"
  ? invokedPath.toLowerCase() !== canonicalInvoked.toLowerCase() || modulePath.toLowerCase() !== canonicalModule.toLowerCase()
  : invokedPath !== canonicalInvoked || modulePath !== canonicalModule);

if (hasAlias) {
  process.stderr.write("Offline 19-stage local validation BLOCKED: entrypoint alias is forbidden\n");
  process.exitCode = 1;
} else if (sameEntry) {
  const argv = process.argv.slice(2);
  const keys = ["--offline", "--repository-root", "--expected-sha", "--expected-branch"];
  const valid = argv.length === 7 && argv[0] === keys[0] && argv[1] === keys[1] &&
    argv[3] === keys[2] && argv[5] === keys[3];
  if (!valid) {
    process.stderr.write("Usage: node scripts/offline-ci-local-runner.mjs --offline --repository-root <absolute-path> --expected-sha <40-hex> --expected-branch <branch>\n");
    process.exitCode = 1;
  } else {
    runOfflineCiLocally({ repositoryRoot: argv[2], revision: argv[4], branch: argv[6], offline: true })
      .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
      .catch((error) => {
        // Only fixed safe error messages reach the console; no child output,
        // credential-bearing errors or arbitrary paths are reflected.
        process.stderr.write(`${error instanceof Error && error.message.startsWith("Offline 19-stage local validation BLOCKED:") ? error.message : "Offline 19-stage local validation BLOCKED: evidence verification failed"}\n`);
        process.exitCode = 1;
      });
  }
}
