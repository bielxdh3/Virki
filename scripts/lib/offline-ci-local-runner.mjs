import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { constants, closeSync, fstatSync, openSync, readFileSync, lstatSync } from "node:fs";
import path from "node:path";
import { validateOfflineCiEvidence } from "./offline-ci-evidence.mjs";

const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_STAGE_LOG_BYTES = 32 * 1024 * 1024;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const safeLine = (line) => /^(?:[a-z][a-z0-9-]{1,80})$/u.test(line);

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
export async function executeBoundedLocalCommand(file, args, { cwd, env, timeoutMs = 120_000, maxOutputBytes = MAX_OUTPUT_BYTES } = {}) {
  if (typeof file !== "string" || !Array.isArray(args) || !args.every((arg) => typeof arg === "string") ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 4 * 60 * 60 * 1000 ||
      !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > MAX_OUTPUT_BYTES) {
    throw new Error("Invalid bounded child execution configuration");
  }
  return await new Promise((resolve) => {
    let outputSize = 0;
    let truncated = false;
    let timedOut = false;
    let spawnError = false;
    let settled = false;
    const chunks = [];
    const child = spawn(file, args, { cwd, env, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32" });
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
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    // A descendant retaining a pipe must never keep the supervisor hanging.
    const killDeadline = setTimeout(() => { timedOut = true; stop(); finish(null); }, timeoutMs + 15_000);
    timer.unref();
    killDeadline.unref();
  });
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
