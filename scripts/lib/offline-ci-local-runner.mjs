import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { constants, closeSync, fstatSync, openSync, readFileSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { validateOfflineCiEvidence } from "./offline-ci-evidence.mjs";

const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_STAGE_LOG_BYTES = 32 * 1024 * 1024;
const MAX_PINNED_POWERSHELL_SCRIPT_BYTES = 1024 * 1024;
const PINNED_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const PINNED_GIT = "C:\\Program Files\\Git\\cmd\\git.exe";
const MAX_GIT_INVENTORY_BYTES = 8 * 1024 * 1024;
const MAX_GIT_TRACKED_FILE_BYTES = 32 * 1024 * 1024;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const safeLine = (line) => /^(?:[a-z][a-z0-9-]{1,80})$/u.test(line);

// This command never opens the mutable fixture pathname. The script arrives on
// a private stdin pipe after the caller verifies those exact bytes against Git.
// PowerShell dynamic scriptblocks have no $PSScriptRoot; restore its value
// inside the verified fixture immediately after its top-level param block.
const executeVerifiedScriptCommand = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$payload = [Console]::In.ReadToEnd()
$tokens = $null
$parseErrors = $null
$parsed = [System.Management.Automation.Language.Parser]::ParseInput($payload, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0 -or $null -eq $parsed.ParamBlock) { throw 'Pinned fixture syntax is invalid' }
if ([string]::IsNullOrEmpty($env:VIRKI_OFFLINE_VERIFIED_SCRIPT_DIRECTORY)) { throw 'Pinned fixture directory is missing' }
$payload = $payload.Insert($parsed.ParamBlock.Extent.EndOffset, ([Environment]::NewLine + '$PSScriptRoot = $env:VIRKI_OFFLINE_VERIFIED_SCRIPT_DIRECTORY' + [Environment]::NewLine))
& ([scriptblock]::Create($payload))
if (-not $?) { exit 1 }
`;

const sameFile = (a, b) => ["dev", "ino", "mode", "size", "nlink", "mtimeNs", "ctimeNs"]
  .every((key) => a[key] === b[key]);

/** Read evidence from one checked regular file descriptor, including mutation checks. */
export function readStableLocalEvidenceFile(filepath, maxBytes) {
  const before = lstatSync(filepath, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
      before.size < 1n || before.size > BigInt(maxBytes)) {
    throw new Error("Invalid bounded local evidence file");
  }
  const fd = openSync(filepath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!sameFile(before, fstatSync(fd, { bigint: true }))) throw new Error("Evidence file changed before read");
    const contents = readFileSync(fd);
    if (contents.length > maxBytes || !sameFile(before, fstatSync(fd, { bigint: true })) ||
        !sameFile(before, lstatSync(filepath, { bigint: true }))) {
      throw new Error("Evidence file changed during read");
    }
    return contents;
  } finally { closeSync(fd); }
}

/** Executes a real child with a bounded output and elapsed time. No shell. */
export async function executeBoundedLocalCommand(file, args, { cwd, env, input, timeoutMs = 120_000, maxOutputBytes = MAX_OUTPUT_BYTES } = {}) {
  if (typeof file !== "string" || !Array.isArray(args) || !args.every((arg) => typeof arg === "string") ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 4 * 60 * 60 * 1000 ||
      !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > MAX_OUTPUT_BYTES ||
      (input !== undefined && (!Buffer.isBuffer(input) || input.length > MAX_PINNED_POWERSHELL_SCRIPT_BYTES))) {
    throw new Error("Invalid bounded child execution configuration");
  }
  return await new Promise((resolve) => {
    let outputSize = 0;
    let truncated = false;
    let timedOut = false;
    let spawnError = false;
    let settled = false;
    const chunks = [];
    const child = spawn(file, args, { cwd, env, shell: false, windowsHide: true, stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"], detached: process.platform !== "win32" });
    const stop = () => {
      if (!child.pid) return;
      if (process.platform === "win32") {
        // Force the PowerShell/Docker CLI process tree to stop; never use PATH.
        const killer = spawn("C:\\Windows\\System32\\taskkill.exe", ["/PID", String(child.pid), "/T", "/F"],
          { stdio: "ignore", windowsHide: true });
        killer.on("error", () => {});
      } else {
        try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
      }
    };
    const finish = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killDeadline);
      resolve(Object.freeze({
        exitCode: Number.isInteger(code) ? code : null, timedOut, truncated, spawnError,
        stdout: Buffer.concat(chunks), capturedBytes: outputSize,
      }));
    };
    const accept = (bytes) => {
      if (truncated) return;
      if (outputSize + bytes.length > maxOutputBytes) {
        truncated = true;
        stop();
        return;
      }
      outputSize += bytes.length;
      chunks.push(bytes);
    };
    child.stdout.on("data", accept);
    child.stderr.on("data", accept);
    child.on("error", () => { spawnError = true; finish(null); });
    child.on("close", (code) => finish(code));
    if (input !== undefined) {
      child.stdin.on("error", () => { spawnError = true; stop(); });
      child.stdin.end(input);
    }
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    // A descendant retaining a pipe must never keep the supervisor hanging.
    const killDeadline = setTimeout(() => { timedOut = true; stop(); finish(null); }, timeoutMs + 15_000);
    timer.unref();
    killDeadline.unref();
  });
}

/** Execute exact pre-attested fixture bytes, never resolving the script path again. */
export async function executePinnedPowerShellScriptBytes(scriptBytes, scriptDirectory, options = {}) {
  if (process.platform !== "win32" || !Buffer.isBuffer(scriptBytes) ||
      scriptBytes.length === 0 || scriptBytes.length > MAX_PINNED_POWERSHELL_SCRIPT_BYTES ||
      typeof scriptDirectory !== "string" || !path.win32.isAbsolute(scriptDirectory) ||
      scriptDirectory !== path.win32.normalize(scriptDirectory)) {
    throw new Error("Invalid pinned PowerShell fixture inputs");
  }
  // Reject malformed UTF-8 before PowerShell reads the exact same byte stream.
  new TextDecoder("utf-8", { fatal: true }).decode(scriptBytes);
  const env = { ...(options.env ?? process.env), VIRKI_OFFLINE_VERIFIED_SCRIPT_DIRECTORY: scriptDirectory };
  return executeBoundedLocalCommand(PINNED_POWERSHELL,
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", executeVerifiedScriptCommand],
    { ...options, env, input: scriptBytes });
}

/**
 * Inspect HEAD, index and every tracked worktree file without asking Git to
 * convert worktree content. `git status`, `git diff` and filtered `hash-object`
 * can invoke repo-local filter.<name>.clean shell commands from .git/config.
 */
export async function assertCleanGitWorktreeWithoutFilters(root, revision, environment) {
  if (process.platform !== "win32" || typeof root !== "string" || !path.win32.isAbsolute(root) ||
      !/^[a-f0-9]{40}$/u.test(revision) || typeof environment !== "object" || !environment) {
    throw new Error("Invalid no-filter working-tree verification inputs");
  }
  async function plumbing(...args) {
    const result = await executeBoundedLocalCommand(PINNED_GIT,
      ["-C", root, "-c", "core.fsmonitor=false", ...args],
      { cwd: root, env: { ...environment, GIT_NO_REPLACE_OBJECTS: "1" },
        timeoutMs: 30_000, maxOutputBytes: MAX_GIT_INVENTORY_BYTES });
    if (result.exitCode !== 0 || result.spawnError || result.timedOut || result.truncated) {
      throw new Error("Git no-filter source inventory failed");
    }
    return result.stdout;
  }
  const [commitBytes, index, untracked] = await Promise.all([
    plumbing("cat-file", "commit", revision),
    plumbing("ls-files", "--stage", "-z"),
    plumbing("ls-files", "--others", "--exclude-standard", "-z"),
  ]);
  if (untracked.length !== 0) throw new Error("Untracked source file present");

  const decoder = new TextDecoder("utf-8", { fatal: true });
  const gitObjectSha = (type, bytes) => createHash("sha1")
    .update(`${type} ${bytes.length}\0`).update(bytes).digest("hex");
  // Git cat-file may return a loose object stored at a forged object filename
  // without verifying the original Git SHA. Recheck the bytes of the commit
  // and every recursively referenced tree ourselves before using any paths.
  if (gitObjectSha("commit", commitBytes) !== revision) {
    throw new Error("Git commit object hash differs from trusted revision");
  }
  const head = /^tree ([a-f0-9]{40})\n/u.exec(decoder.decode(commitBytes));
  if (!head) throw new Error("Git commit tree identity is missing");
  const committedFiles = new Map();
  const seenTrees = new Set();
  async function walkTree(objectId, prefix = "") {
    if (seenTrees.has(`${prefix}${objectId}`)) throw new Error("Repeated Git tree entry");
    seenTrees.add(`${prefix}${objectId}`);
    const raw = await plumbing("cat-file", "tree", objectId);
    if (gitObjectSha("tree", raw) !== objectId) {
      throw new Error("Git tree object hash differs from trusted revision");
    }
    for (let offset = 0; offset < raw.length;) {
      const space = raw.indexOf(32, offset);
      const nul = space < 0 ? -1 : raw.indexOf(0, space + 1);
      if (space <= offset || nul <= space + 1 || nul + 21 > raw.length) {
        throw new Error("Invalid committed Git tree data");
      }
      const mode = raw.subarray(offset, space).toString("ascii");
      const filename = decoder.decode(raw.subarray(space + 1, nul));
      if (filename === "." || filename === ".." || filename.includes("/") ||
          filename.includes("\\") || filename.includes(":") ||
          Array.from(filename).some((character) => character.codePointAt(0) < 32)) {
        throw new Error("Unsafe committed Git tree pathname");
      }
      const object = raw.subarray(nul + 1, nul + 21).toString("hex");
      const relativePath = `${prefix}${filename}`;
      if (mode === "40000" || mode === "040000") {
        await walkTree(object, `${relativePath}/`);
      } else if (mode === "100644" || mode === "100755") {
        if (committedFiles.has(relativePath)) throw new Error("Repeated Git tree pathname");
        committedFiles.set(relativePath, { mode, object });
      } else {
        throw new Error("Unsupported Git source tree file type");
      }
      offset = nul + 21;
    }
  }
  await walkTree(head[1]);
  function entries(data, expression) {
    if (data.length === 0 || data[data.length - 1] !== 0) throw new Error("Invalid Git NUL inventory");
    const records = decoder.decode(data).slice(0, -1).split("\0");
    const entriesByPath = new Map();
    for (const record of records) {
      const match = expression.exec(record);
      if (!match || entriesByPath.has(match[3]) || !match[3] ||
          match[3].includes("\\") || path.win32.isAbsolute(match[3]) ||
          match[3].split("/").some((part) => !part || part === "." || part === "..")) {
        throw new Error("Invalid Git source inventory entry");
      }
      entriesByPath.set(match[3], { mode: match[1], object: match[2] });
    }
    return entriesByPath;
  }
  const indexFiles = entries(index, /^(100644|100755) ([a-f0-9]{40}) 0\t(.+)$/u);
  if (committedFiles.size !== indexFiles.size) throw new Error("Git index differs from HEAD");
  const checkedDirectories = new Set([root.toLowerCase()]);
  for (const [relativePath, entry] of committedFiles) {
    const staged = indexFiles.get(relativePath);
    if (!staged || staged.mode !== entry.mode || staged.object !== entry.object) {
      throw new Error("Git index differs from HEAD");
    }
    const filepath = path.resolve(root, ...relativePath.split("/"));
    if (!filepath.toLowerCase().startsWith(`${root.toLowerCase()}${path.sep}`)) {
      throw new Error("Tracked source path is aliased");
    }
    // Resolve each distinct ancestor just once. A junction/reparse point can
    // redirect a perfectly regular child file outside the verified tree.
    let ancestor = root;
    for (const component of relativePath.split("/").slice(0, -1)) {
      ancestor = path.join(ancestor, component);
      const identity = ancestor.toLowerCase();
      if (checkedDirectories.has(identity)) continue;
      const directory = lstatSync(ancestor);
      if (!directory.isDirectory() || directory.isSymbolicLink() ||
          realpathSync.native(ancestor).toLowerCase() !== identity) {
        throw new Error("Tracked source directory is aliased");
      }
      checkedDirectories.add(identity);
    }
    const before = lstatSync(filepath, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
        before.size > BigInt(MAX_GIT_TRACKED_FILE_BYTES)) {
      throw new Error("Unsafe tracked source file");
    }
    const bytes = readFileSync(filepath);
    const after = lstatSync(filepath, { bigint: true });
    if (!sameFile(before, after) || BigInt(bytes.length) !== before.size) {
      throw new Error("Tracked source mutated during inventory");
    }
    if (gitObjectSha("blob", bytes) !== entry.object) {
      // Windows Git checkouts may use CRLF for text, but binary or non-UTF8
      // data must match its Git object byte-for-byte.
      if (bytes.includes(0)) throw new Error("Tracked source differs from HEAD");
      let lf;
      try { lf = Buffer.from(decoder.decode(bytes).replace(/\r\n/gu, "\n"), "utf8"); }
      catch { throw new Error("Tracked source differs from HEAD"); }
      if (lf.equals(bytes) || gitObjectSha("blob", lf) !== entry.object) {
        throw new Error("Tracked source differs from HEAD");
      }
    }
  }
}

/**
 * Locally observed evidence ONLY. Caller must independently check that a
 * bounded, non-overridden pinned runner produced these exact bytes. Console
 * sections are excerpts, since the Docker fixture tails some stage logs.
 * No statement of hosted CI, CodeQL, Semgrep or deployment authority.
 */
export function buildLocalStageReceipts({ manifestBytes, stdout, revision, branch, stageLogDirectory }) {
  const validated = validateOfflineCiEvidence(manifestBytes, revision, branch);
  const manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes));
  if (manifest.dockerCleanupVerified !== true || manifest.dockerMutationUncertain !== false ||
      manifest.bootstrapVirginTestsExitCode !== 0 ||
      manifest.bootstrapVirginTestsLog !== "bootstrap-virgin-tests.tap.log") {
    throw new Error("Local stage receipts require verified Docker cleanup and virgin bootstrap");
  }
  if (!Buffer.isBuffer(stdout) || stdout.byteLength === 0 || stdout.byteLength > MAX_OUTPUT_BYTES) {
    throw new Error("Bounded runner console output is required");
  }
  const observed = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  const sections = new Map();
  const orderedStages = manifest.stages.map((stage) => stage.name);
  orderedStages.splice(orderedStages.indexOf("integration-tests"), 0, "bootstrap-virgin-tests");
  let current = null;
  let outputSection = [];
  for (const line of observed.split(/\r?\n/u)) {
    const header = /^\[([a-z][a-z0-9-]+)\]$/u.exec(line);
    if (header && (manifest.stages.some((stage) => stage.name === header[1]) || header[1] === "bootstrap-virgin-tests")) {
      if (current !== null) throw new Error("Runner console omitted a result or repeated a stage header");
      if (sections.has(header[1])) throw new Error("Duplicate console stage");
      if (orderedStages[sections.size] !== header[1]) {
        throw new Error("Runner console stages were observed out of expected order");
      }
      current = header[1];
      outputSection = [];
      continue;
    }
    const result = /^\[RESULT\] ([a-z][a-z0-9-]+) exit=(-?\d+) durationMs=([0-9.]+)$/u.exec(line);
    if (result) {
      if (current !== result[1] || !Number.isFinite(Number(result[3])) || sections.has(current)) {
        throw new Error("Runner stage console evidence is out of order or contradictory");
      }
      sections.set(current, {
        exitCode: Number(result[2]),
        consoleExcerptSha256: sha(Buffer.from(outputSection.join("\n"))),
        consoleExcerptBytes: Buffer.byteLength(outputSection.join("\n")),
      });
      current = null;
      continue;
    }
    if (current !== null) outputSection.push(line);
  }
  if (current !== null || sections.size !== 20 || sections.get("bootstrap-virgin-tests")?.exitCode !== 0) {
    throw new Error("All 19 stages and the virgin bootstrap need real console results");
  }

  const logNames = new Map([
    ["unit-tests", "unitTestsLog"], ["integration-tests", "integrationTestsLog"],
    ["production-operations-tests", "productionOperationsLog"],
    ["browser-e2e", "browserE2ELog"], ["bootstrap-virgin-tests", "bootstrapVirginTestsLog"],
  ]);
  const completeLogs = new Map();
  for (const [name, key] of logNames) {
    const filename = manifest[key];
    if (typeof filename !== "string" || filename !== {
      "unit-tests": "unit-tests.tap.log", "integration-tests": "integration-tests.tap.log",
      "production-operations-tests": "production-operations-tests.tap.log",
      "browser-e2e": "browser-e2e-output.log", "bootstrap-virgin-tests": "bootstrap-virgin-tests.tap.log",
    }[name]) throw new Error(`Missing exact ${name} log`);
    const filepath = path.join(stageLogDirectory, filename);
    completeLogs.set(name, sha(readStableLocalEvidenceFile(filepath, MAX_STAGE_LOG_BYTES)));
  }
  const bootstrap = Object.freeze({
    status: "PASS", exitCode: 0,
    ...sections.get("bootstrap-virgin-tests"),
    rawLogSha256: completeLogs.get("bootstrap-virgin-tests"),
  });
  let previous = sha(manifestBytes);
  const stages = manifest.stages.map((stage) => {
    if (!safeLine(stage.name)) throw new Error("Unsafe stage name");
    const record = sections.get(stage.name);
    if (!record || record.exitCode !== stage.exitCode || stage.exitCode !== 0) {
      throw new Error(`Stage ${stage.name} has no matching successful observed result`);
    }
    const receipt = {
      name: stage.name, status: "PASS", startedUtc: stage.startedUtc,
      finishedUtc: stage.finishedUtc, exitCode: stage.exitCode,
      consoleExcerptSha256: record.consoleExcerptSha256,
      consoleExcerptBytes: record.consoleExcerptBytes,
      consoleExcerptComplete: false,
      ...(completeLogs.has(stage.name) ? { rawLogSha256: completeLogs.get(stage.name) } : {}),
    };
    previous = sha(Buffer.from(JSON.stringify([previous, revision, branch, manifest.runId, receipt])));
    return Object.freeze({ ...receipt, chainSha256: previous });
  });
  return Object.freeze({
    version: 1, kind: "UNTRUSTED_LOCAL_19_STAGE_EXECUTION_RECEIPTS", revision, branch,
    runId: manifest.runId, manifestSha256: validated.manifestSha256,
    consoleSha256: sha(stdout), bootstrap, stages,
    finalChainSha256: previous, codeql: "NOT_RUN", hostedCi: "NOT_RUN", ghcr: "NOT_RUN",
    deployAuthorized: false,
    limitation: "Local runner metadata and hash-linked console excerpts are not independent attestation or proof of hosted CI/scanner execution; some console output is tailed.",
  });
}
