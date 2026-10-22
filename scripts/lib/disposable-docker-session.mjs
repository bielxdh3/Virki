import { spawnSync } from "node:child_process";
import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdtempSync, openSync,
  writeSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { cleanupOwnedDockerResources } from "./disposable-docker-cleanup.mjs";
import { requireOwnedDisposableDockerMutation } from "./disposable-docker-mutation-policy.mjs";

// Test-only engine selection. Windows must use the local Docker Desktop Linux
// named pipe directly. Linux requires the trusted GitHub-hosted CI runner
// assumption; runner environment variables are NOT cryptographic proof.
const WINDOWS_DOCKER = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const WINDOWS_ENGINE = "npipe:////./pipe/dockerDesktopLinuxEngine";
const LINUX_DOCKER = "/usr/bin/docker";
const LINUX_ENGINE = "unix:///var/run/docker.sock";
const SAFE_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,180}$/u;

function refuse(message) {
  throw new Error(`Disposable Docker session refused: ${message}`);
}

function selectEngine(platform, env, nativeArch) {
  const arch = nativeArch === "x64" ? "amd64" : nativeArch === "arm64" ? "arm64" : "unsupported";
  if (platform === "win32") {
    if (env.VIRKI_BUILD_ARCH && env.VIRKI_BUILD_ARCH !== "amd64") {
      refuse("Windows Docker Desktop validation requires amd64");
    }
    return { cli: WINDOWS_DOCKER, host: WINDOWS_ENGINE, arch: "amd64" };
  }
  if (platform === "linux" && env.GITHUB_ACTIONS === "true" &&
      env.CI === "true" && env.RUNNER_OS === "Linux" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      /^[a-f0-9]{40}$/u.test(env.VIRKI_BUILD_REVISION ?? "") &&
      env.VIRKI_BUILD_ARCH === arch && ["amd64", "arm64"].includes(arch) &&
      env.RUNNER_ARCH === (arch === "amd64" ? "X64" : "ARM64")) {
    return { cli: LINUX_DOCKER, host: LINUX_ENGINE, arch };
  }
  refuse("a local Windows Docker Desktop Linux engine or trusted runner architecture and revision assumption is required");
}

function scrubDockerEnvironment(env) {
  return Object.fromEntries(Object.entries(env).filter(([key]) => !/^DOCKER_/iu.test(key)));
}

function directoryIdentity(root, requireOwnerPrivate = true) {
  for (let cursor = root;; cursor = path.dirname(cursor)) {
    const entry = lstatSync(cursor, { bigint: true });
    if (!entry.isDirectory() || entry.isSymbolicLink()) refuse("receipt root has an unsafe path alias");
    if (path.dirname(cursor) === cursor) break;
  }
  const stat = lstatSync(root, { bigint: true });
  if (process.platform !== "win32" && requireOwnerPrivate && (stat.mode & 0o077n) !== 0n) {
    refuse("receipt root must be owner-private (0700)");
  }
  if (process.platform !== "win32" && !requireOwnerPrivate &&
      (stat.mode & 0o022n) !== 0n && (stat.mode & 0o1000n) === 0n) {
    refuse("receipt parent is writable without the sticky bit");
  }
  return stat;
}

function sameIdentity(left, right) {
  return ["dev", "ino", "mode", "nlink"].every((field) => left[field] === right[field]);
}

function syncPinnedDirectory(directory, expectedIdentity, fsyncDirectory, label) {
  const fd = openSync(directory, "r");
  try {
    if (!sameIdentity(expectedIdentity, fstatSync(fd, { bigint: true })) ||
        !sameIdentity(expectedIdentity, directoryIdentity(directory, label !== "parent"))) {
      refuse("receipt directory identity changed before durability barrier");
    }
    fsyncDirectory(fd, label);
    if (!sameIdentity(expectedIdentity, fstatSync(fd, { bigint: true })) ||
        !sameIdentity(expectedIdentity, directoryIdentity(directory, label !== "parent"))) {
      refuse("receipt directory identity changed after durability barrier");
    }
  } finally {
    closeSync(fd);
  }
}

export function createDisposableDockerSession({
  kind, owner, containers, network, env = process.env, platform = process.platform,
  spawn = spawnSync, nativeArch = process.arch, receiptDirectory, fsyncDirectory = fsyncSync,
} = {}) {
  if (!["runtime", "migrator"].includes(kind) || !SAFE_NAME.test(owner ?? "") ||
      !Array.isArray(containers) || containers.some((name) => !SAFE_NAME.test(name)) ||
      new Set(containers).size !== containers.length || !SAFE_NAME.test(network ?? "") ||
      containers.includes(network) || typeof spawn !== "function") refuse("invalid resource ownership");

  const { cli, host, arch } = selectEngine(platform, env, nativeArch);
  if (spawn === spawnSync && !existsSync(cli)) refuse("pinned Docker CLI is unavailable");
  // Live validation always owns a fresh OS-generated directory. Test fixtures
  // may inject a root only with a fake Docker process; no environment path
  // may steer writes to arbitrary filesystem locations.
  if (spawn === spawnSync && (receiptDirectory !== undefined || fsyncDirectory !== fsyncSync)) {
    refuse("receipt root and durability operation overrides are test-only");
  }
  const evidenceDirectory = receiptDirectory ??
    mkdtempSync(path.join(os.tmpdir(), "virki-disposable-docker-"), { mode: 0o700 });
  if (!path.isAbsolute(evidenceDirectory) || path.normalize(evidenceDirectory) !== evidenceDirectory) {
    refuse("evidence root must be an absolute canonical path");
  }
  const rootStat = directoryIdentity(evidenceDirectory);
  const parentDirectory = path.dirname(evidenceDirectory);
  const parentStat = process.platform === "win32" ? null : directoryIdentity(parentDirectory, false);
  const receiptPath = path.join(evidenceDirectory, `${kind}-${owner}.jsonl`);
  // O_EXCL creates an independent inode and never replaces an existing receipt.
  const receiptFd = openSync(receiptPath, "wx", 0o600);
  const receiptStat = fstatSync(receiptFd, { bigint: true });
  let receiptClosed = false;

  function verifyPinnedReceipt() {
    const rootNow = directoryIdentity(evidenceDirectory);
    const leafNow = lstatSync(receiptPath, { bigint: true });
    const openedNow = fstatSync(receiptFd, { bigint: true });
    if (!sameIdentity(rootStat, rootNow) || !leafNow.isFile() || leafNow.isSymbolicLink() ||
        leafNow.nlink !== 1n || !sameIdentity(receiptStat, leafNow) ||
        !sameIdentity(receiptStat, openedNow)) {
      refuse("receipt directory or pinned file identity changed");
    }
  }

  const receipt = {
    version: 1, kind, owner, resources: { containers: [...containers], network },
    status: "PREPARED", stage: "before-preflight", uncertainOperations: [],
  };
  let sequence = 0;

  function appendReceipt() {
    verifyPinnedReceipt();
    const bytes = Buffer.from(JSON.stringify({ ...receipt, sequence: ++sequence }) + "\n");
    let offset = 0;
    while (offset < bytes.length) {
      const count = writeSync(receiptFd, bytes, offset, bytes.length - offset);
      if (count <= 0) refuse("receipt append was incomplete");
      offset += count;
    }
    fsyncSync(receiptFd);
    verifyPinnedReceipt();
  }

  try {
    appendReceipt();
    if (process.platform !== "win32") {
      // fsync(file) persists the JSONL contents; it does not persist the new
      // directory entry. The receipt root and its mkdtemp parent also need
      // fsync before any Docker operation can execute. A failed barrier
      // aborts this session rather than creating untracked resources.
      verifyPinnedReceipt();
      syncPinnedDirectory(evidenceDirectory, rootStat, fsyncDirectory, "root");
      syncPinnedDirectory(parentDirectory, parentStat, fsyncDirectory, "parent");
      verifyPinnedReceipt();
    }
  } catch (error) {
    closeSync(receiptFd);
    throw error;
  }

  function persist(status, stage) {
    receipt.status = status;
    receipt.stage = stage;
    appendReceipt();
  }

  function invokeRaw(args, options = {}) {
    const output = spawn(cli, ["--host", host, ...args], {
      encoding: "utf8", windowsHide: true,
      timeout: options.timeout ?? 120_000,
      maxBuffer: 10 * 1024 * 1024,
      env: scrubDockerEnvironment(options.env ?? env),
    });
    return output;
  }

  const check = invokeRaw(["version", "--format", "{{.Server.Os}}|{{.Server.Arch}}"], { timeout: 15_000 });
  if (check?.error || check?.status !== 0 || check?.stdout?.trim() !== `linux|${arch}`) {
    persist("PREFLIGHT_FAILED", "Docker Desktop Linux / trusted hosted architecture check");
    refuse(`explicit Linux/${arch} Docker endpoint was not verified`);
  }
  persist("READY", "preflight-verified");

  let cleanupStarted = false;
  let cleanupComplete = false;
  // A public generic Docker CLI bypasses the mutation journal. Only expose
  // the exact, owner-scoped read observations used by smoke fixtures.
  function invoke(args, options = {}) {
    if (cleanupStarted || !Array.isArray(args)) refuse("unreviewed public Docker read after cleanup or invalid arguments");
    const portRead = kind === "runtime" && args.length === 3 && args[0] === "port" &&
      containers.includes(args[1]) && ["3000/tcp", "3001/tcp"].includes(args[2]);
    const readyArgs = ["exec", containers[0], "pg_isready", "-h", "127.0.0.1",
      "-U", "virki_bootstrap", "-d", "virki_validation"];
    const readyRead = kind === "migrator" && args.length === readyArgs.length &&
      args.every((value, index) => value === readyArgs[index]);
    if (!portRead && !readyRead) refuse("unreviewed public Docker read operation");
    return invokeRaw(args, options);
  }

  function performMutation(stage, args, options, cleanupOperation = false) {
    if (cleanupStarted && !cleanupOperation) refuse("Docker mutation after cleanup was requested");
    if (!SAFE_NAME.test(stage)) refuse("invalid Docker mutation stage");
    if (!cleanupOperation) requireOwnedDisposableDockerMutation({ kind, owner, containers, network, stage, args });
    // Persist intent before invoking Docker; a lost ACK must never become PASS.
    persist("MUTATION_PENDING", stage);
    let result;
    try { result = invokeRaw(args, options); } catch { /* unknown Docker effect */ }
    if (result?.error || result?.status !== 0) {
      receipt.uncertainOperations.push(stage);
      persist("RECONCILIATION_REQUIRED", stage);
      refuse(`uncertain Docker mutation ${stage}; reconcile using receipt ${receiptPath}`);
    }
    persist("MUTATION_ACKNOWLEDGED", stage);
    return result;
  }

  function mutate(stage, args, options) {
    return performMutation(stage, args, options);
  }

  function cleanup() {
    if (cleanupStarted) refuse("Docker cleanup already started; reconcile prior attempt");
    cleanupStarted = true;
    try {
      cleanupOwnedDockerResources({
        invoke: (args) => args[1] === "rm"
          ? performMutation(`remove-${args[0]}`, args, undefined, true)
          : invokeRaw(args, { timeout: 60_000 }),
        owner, containers, network,
      });
      cleanupComplete = true;
      persist(receipt.uncertainOperations.length ? "RECONCILIATION_REQUIRED" : "CLEANUP_CONFIRMED",
        "cleanup-verified");
    } catch (error) {
      persist("RECONCILIATION_REQUIRED", "cleanup-unconfirmed");
      throw error;
    }
  }

  function finish(smokePassed) {
    try {
      if (!cleanupComplete || receipt.uncertainOperations.length !== 0) {
        persist("RECONCILIATION_REQUIRED", "final-reconciliation");
        refuse(`manual reconciliation required; a delayed Docker resource may still appear; receipt ${receiptPath}`);
      }
      persist(smokePassed ? "PASS" : "SMOKE_FAILED_CLEANED", "complete");
    } finally {
      if (!receiptClosed) { closeSync(receiptFd); receiptClosed = true; }
    }
  }

  return Object.freeze({ invoke, mutate, cleanup, finish, receiptPath });
}
