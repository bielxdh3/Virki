// Production pull agent. Install on a dedicated native-Linux operator checkout
// only after Virki's first installation, ingress cutover and GHCR credentials
// have been verified. Invoked by a non-overlapping, owner-only systemd timer.
import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readProductionConfig, isValidProductionConfig } from "./lib/production-config.mjs";
import { SSH_OPTIONS } from "./production-preflight.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const remote = "https://github.com/bielxdh3/Virki.git";
const pointerApi = "repos/bielxdh3/Virki/contents/production.json?ref=production";

export function parseApprovedProductionPointer(value) {
  const v = typeof value === "string" ? JSON.parse(value) : value;
  if (!v || typeof v !== "object" || Array.isArray(v) ||
    v.version !== 1 || !/^[0-9a-f]{40}$/u.test(v.source_commit ?? "") ||
    v.approved_by !== "bielxdh3" ||
    !Number.isSafeInteger(v.ci_run) || v.ci_run <= 0 ||
    !Number.isSafeInteger(v.codeql_run) || v.codeql_run <= 0 ||
    !Number.isSafeInteger(v.approval_run) || v.approval_run <= 0 ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(v.approved_at ?? "")) {
    throw new Error("Production approval pointer has invalid or untrusted fields.");
  }
  return v;
}

export function planApprovedProductionAttempt(pointer, state) {
  if (state) {
    if (!/^[0-9a-f]{40}$/u.test(state.sha ?? "") ||
      !["attempted", "failed", "success"].includes(state.status)) {
      throw new Error("Stored production agent state is invalid.");
    }
    if (state.status !== "success") {
      throw new Error("Previous production attempt is unresolved; manual inspection is required.");
    }
    if (state.sha === pointer.source_commit) return "already-applied";
  }
  return "deploy";
}

function exec(command, args, input) {
  const r = spawnSync(command, args, {
    cwd: root, shell: false, encoding: "utf8", input,
    windowsHide: true, maxBuffer: 8 * 1024 * 1024
  });
  if (r.error || r.status !== 0) {
    // Do not propagate stderr: it can contain secrets or sensitive host details.
    throw new Error("Required command failed: " + command);
  }
  return (r.stdout ?? "").trim();
}

function readState(file) {
  // Open the checked inode itself, not a pathname re-resolved after stat:
  // this removes the file-system race flagged by CodeQL (TOCTOU).
  const fd = (() => {
    try {
      return openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if (error && typeof error === "object" && error.code === "ENOENT") return null;
      throw error;
    }
  })();
  if (fd === null) return null;
  try {
    const meta = fstatSync(fd);
    if (!meta.isFile() || (meta.mode & 0o077) !== 0 ||
      meta.uid !== process.getuid()) {
      throw new Error("Production state file has unsafe permissions.");
    }
    return JSON.parse(readFileSync(fd, "utf8"));
  } finally {
    closeSync(fd);
  }
}

function writeState(file, state) {
  const temporary = file + ".tmp-" + process.pid;
  writeFileSync(temporary, JSON.stringify(state) + "\n", { mode: 0o600, flag: "wx" });
  renameSync(temporary, file);
}

function validateStateLocation(file) {
  if (typeof file !== "string" || !path.isAbsolute(file) ||
    path.basename(file) !== "virki-approval-state.json") {
    throw new Error("Absolute VIRKI_APPROVAL_STATE_FILE is required.");
  }
  const dir = lstatSync(path.dirname(file));
  if (!dir.isDirectory() || dir.isSymbolicLink() || (dir.mode & 0o077) !== 0 || dir.uid !== process.getuid()) {
    throw new Error("Production agent state directory is not owner-only.");
  }
}

function readRemote(config, script) {
  return exec("ssh", [...SSH_OPTIONS, config.sshAlias, "bash -s -- " + config.root], script);
}

function assertInitialized(config) {
  // A partial first-install is NOT a candidate for unattended upgrades.
  readRemote(config, "set -eu\nroot=$1\ntest -f \"$root/.virki-first-install\"\ntest -L \"$root/current\"\ntest -f \"$root/.ghcr-read-token\"\ntest -f \"$root/.virki-production-host\"\n");
}

function demanageContainers(config) {
  const names = readRemote(config, "set -eu\ndocker ps --format '{{.Names}}'\n")
    .split(/\r?\n/u).map(x => x.trim()).filter(Boolean)
    .filter(name => /demanage/iu.test(name)).sort();
  if (names.length < 3) throw new Error("deManage services are not all running.");
  return names.join("\n");
}

async function run() {
  if (os.platform() !== "linux" || /microsoft/iu.test(os.release())) throw new Error("This agent runs only on native Linux.");
  if (process.env.VIRKI_AUTOMATED_DEPLOY_ENABLED !== "true") {
    throw new Error("Approval agent is disabled until first-install and ingress cutover are verified.");
  }
  if (!process.env.GH_TOKEN) throw new Error("GitHub read credential is missing.");
  const stateFile = process.env.VIRKI_APPROVAL_STATE_FILE;
  validateStateLocation(stateFile);
  const config = readProductionConfig();
  if (!isValidProductionConfig(config)) throw new Error("Pinned production operator configuration is invalid.");

  const encoded = exec("gh", ["api", pointerApi, "--jq", ".content"]);
  const pointer = parseApprovedProductionPointer(
    Buffer.from(encoded.replace(/\s/gu, ""), "base64").toString("utf8")
  );
  // Prove that the pointer was written by a completed owner-triggered
  // workflow_dispatch on the exact commit, not by editing production.json.
  const approvalRun = JSON.parse(exec("gh", [
    "api", "repos/bielxdh3/Virki/actions/runs/" + pointer.approval_run
  ]));
  if (approvalRun.id !== pointer.approval_run ||
      approvalRun.name !== "Authorize Virki production release" ||
      approvalRun.event !== "workflow_dispatch" ||
      approvalRun.status !== "completed" ||
      approvalRun.conclusion !== "success" ||
      approvalRun.head_branch !== "main" ||
      approvalRun.head_sha !== pointer.source_commit ||
      approvalRun.actor?.login !== "bielxdh3") {
    throw new Error("GitHub owner approval workflow provenance is unverified.");
  }
  const state = readState(stateFile);
  if (planApprovedProductionAttempt(pointer, state) === "already-applied") {
    process.stdout.write("Approved Virki SHA was already deployed and recorded.\n");
    return;
  }

  if (exec("git", ["remote", "get-url", "origin"]) !== remote ||
    exec("git", ["branch", "--show-current"]) !== "main" ||
    exec("git", ["status", "--porcelain"]) !== "") {
    throw new Error("Operator checkout must be clean main with canonical remote.");
  }
  exec("git", ["fetch", "--no-tags", "origin", "main"]);
  if (exec("git", ["rev-parse", "origin/main"]) !== pointer.source_commit) {
    throw new Error("Approval does not match current remote main.");
  }
  exec("git", ["merge", "--ff-only", "origin/main"]);
  if (exec("git", ["rev-parse", "HEAD"]) !== pointer.source_commit ||
    exec("git", ["status", "--porcelain"]) !== "") {
    throw new Error("Operator source is not the exact approved revision.");
  }

  // The official preflight verifies exact-SHA CI, CodeQL SARIF digest evidence,
  // pinned SSH identity, Docker, Compose, free space and protected host files.
  exec("npm", ["run", "preflight:prod"]);
  assertInitialized(config);
  const before = demanageContainers(config);

  // Write before any mutation. A failed or interrupted attempt is latched and
  // cannot rerun automatically; recovery requires owner/operator review.
  writeState(stateFile, { sha: pointer.source_commit, status: "attempted" });
  try {
    exec("npm", ["run", "deploy:prod"]);
    exec("npm", ["run", "health:prod", "--", "--expected", pointer.source_commit]);
    if (demanageContainers(config) !== before) {
      throw new Error("deManage container continuity check failed.");
    }
    writeState(stateFile, { sha: pointer.source_commit, status: "success" });
    process.stdout.write("Virki deployment and local health checks succeeded at " + pointer.source_commit + ".\n");
  } catch {
    writeState(stateFile, { sha: pointer.source_commit, status: "failed" });
    throw new Error("Production deploy or health check failed. Agent latched; manual recovery required.");
  }
}

export async function withExclusiveAgentLock(stateFile, action) {
  validateStateLocation(stateFile);
  // 'wx' is an atomic O_EXCL create. A crash leaves the lock as a deliberate
  // fail-closed manual-recovery sentinel, rather than allowing a second deploy.
  const lockFile = stateFile + ".lock";
  const fd = openSync(lockFile, "wx", 0o600);
  try {
    return await action();
  } finally {
    closeSync(fd);
    unlinkSync(lockFile);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // An additional nonblocking systemd flock is recommended as defense in depth.
  withExclusiveAgentLock(process.env.VIRKI_APPROVAL_STATE_FILE, run)
    .catch(error => { console.error(error.message); process.exitCode = 1; });
}
