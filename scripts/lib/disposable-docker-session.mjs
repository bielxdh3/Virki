import { spawnSync } from "node:child_process";
import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdtempSync, openSync,
  writeSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { cleanupOwnedDockerResources } from "./disposable-docker-cleanup.mjs";
import { requireOwnedDisposableDockerMutation, verifyTrustedRoleSetup } from "./disposable-docker-mutation-policy.mjs";

// Test-only engine selection. Windows must use the local Docker Desktop Linux
// named pipe directly. Linux requires the trusted GitHub-hosted CI runner
// assumption; runner environment variables are NOT cryptographic proof.
const WINDOWS_DOCKER = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const WINDOWS_ENGINE = "npipe:////./pipe/dockerDesktopLinuxEngine";
const LINUX_DOCKER = "/usr/bin/docker";
const LINUX_ENGINE = "unix:///var/run/docker.sock";
const SAFE_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,180}$/u;
const UUID_V4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const RESERVED_NETWORK = /^(?:host|bridge|none|default)$/iu;

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

function sameIdentity(left, right, requireLinkCount = true) {
  // The public shared /tmp parent legitimately changes nlink when another
  // process creates/removes an unrelated child directory. Its dev/ino/mode,
  // path components and sticky-bit protection remain mandatory. Keep nlink
  // strict for our private receipt root and the receipt file itself.
  const fields = requireLinkCount ? ["dev", "ino", "mode", "nlink"] : ["dev", "ino", "mode"];
  return fields.every((field) => left[field] === right[field]);
}

function syncPinnedDirectory(directory, expectedIdentity, fsyncDirectory, label) {
  const fd = openSync(directory, "r");
  const matches = (actual) => sameIdentity(expectedIdentity, actual, label !== "parent");
  try {
    if (!matches(fstatSync(fd, { bigint: true })) ||
        !matches(directoryIdentity(directory, label !== "parent"))) {
      refuse("receipt directory identity changed before durability barrier");
    }
    fsyncDirectory(fd, label);
    if (!matches(fstatSync(fd, { bigint: true })) ||
        !matches(directoryIdentity(directory, label !== "parent"))) {
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
      RESERVED_NETWORK.test(network) ||
      containers.includes(network) || typeof spawn !== "function") refuse("invalid resource ownership");

  if (spawn === spawnSync) {
    // Live calls originate only from the three reviewed disposable fixtures;
    // a caller cannot borrow ambient Docker networks or foreign resource names.
    const runtime = kind === "runtime" && containers.length === 3 &&
      network === `virki-runtime-${owner}` &&
      containers[0] === `virki-runtime-public-${owner}` &&
      containers[1] === `virki-runtime-hub-${owner}` &&
      containers[2] === `virki-runtime-issuer-${owner}`;
    const assertion = kind === "runtime" && containers.length === 1 &&
      network === `virki-image-assertion-unused-${owner}` &&
      containers[0] === `virki-image-assertion-${owner}`;
    const migration = kind === "migrator" && containers.length === 3 &&
      network === `virki-migrator-smoke-${owner}` &&
      containers[0] === `virki-migrator-db-${owner}` &&
      containers[1] === `virki-migrator-deploy-${owner}` &&
      containers[2] === `virki-migrator-status-${owner}`;
    if (!UUID_V4.test(owner) || !(runtime || assertion || migration)) {
      refuse("real Docker resource names must bind exactly to one disposable fixture owner");
    }
  }

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
  const acknowledgedStages = [];
  function verifyEnvironmentOverride(stage, options = {}) {
    if (options.env === undefined) {
      if (["create-database", "run-deploy", "run-status"].includes(stage)) {
        refuse("missing scoped disposable database environment");
      }
      return;
    }
    const supplied = options.env;
    if (!supplied || typeof supplied !== "object" || Array.isArray(supplied)) {
      refuse("invalid Docker subprocess environment override");
    }
    const passwordKeys = ["POSTGRES_PASSWORD", "VIRKI_RUNTIME_DB_PASSWORD",
      "VIRKI_MIGRATOR_DB_PASSWORD", "VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD"];
    const allowed = stage === "create-database"
      ? new Set(["POSTGRES_USER", "POSTGRES_DB", ...passwordKeys])
      : ["run-deploy", "run-status"].includes(stage)
        ? new Set(["MIGRATION_DATABASE_URL"])
        : new Set();
    for (const key of new Set([...Object.keys(env), ...Object.keys(supplied)])) {
      if (!allowed.has(key) && supplied[key] !== env[key]) {
        refuse("unreviewed Docker subprocess environment override");
      }
    }
    if (stage === "create-database") {
      if (supplied.POSTGRES_USER !== "virki_bootstrap" || supplied.POSTGRES_DB !== "virki_validation" ||
          passwordKeys.some((key) => !/^[a-f0-9]{64}$/u.test(supplied[key] ?? ""))) {
        refuse("disposable PostgreSQL environment does not match the fixture");
      }
    } else if (["run-deploy", "run-status"].includes(stage)) {
      let url;
      try { url = new URL(supplied.MIGRATION_DATABASE_URL); } catch { /* fail closed */ }
      if (url?.protocol !== "postgresql:" || url.username !== "virki_migrator" ||
          !/^[a-f0-9]{64}$/u.test(url.password) || url.hostname !== `database-${owner}` ||
          url.port !== "5432" || url.pathname !== "/virki_validation" ||
          url.search !== "?schema=public" || url.hash) {
        refuse("disposable migration database URL is not owner-local");
      }
    }
  }
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
    verifyEnvironmentOverride("read", options);
    return invokeRaw(args, options);
  }

  function performMutation(stage, args, options, cleanupOperation = false) {
    if (cleanupStarted && !cleanupOperation) refuse("Docker mutation after cleanup was requested");
    if (!SAFE_NAME.test(stage)) refuse("invalid Docker mutation stage");
    if (!cleanupOperation) {
      const order = kind === "migrator"
        ? ["create-network", "create-database", "run-deploy", "run-status"]
        : containers.length === 3
          ? ["create-network", "create-public", "create-issuer", "create-hub"]
          : ["create-network", "run-assertion"];
      // A one-container assertion fixture runs without a network; an isolated
      // one-container mock may instead create one disposable network.
      const allowedStage = containers.length === 1
        ? acknowledgedStages.length === 0 && (spawn === spawnSync
          ? stage === "run-assertion" : ["create-network", "run-assertion"].includes(stage))
        : stage === order[acknowledgedStages.length];
      if (!allowedStage || receipt.uncertainOperations.length > 0) {
        refuse("out-of-order, repeated or uncertain Docker mutation");
      }
    }
    if (!cleanupOperation) requireOwnedDisposableDockerMutation({ kind, owner, containers, network, stage, args });
    if (!cleanupOperation) verifyEnvironmentOverride(stage, options);
    const initializerIdentity = !cleanupOperation && stage === "create-database"
      ? verifyTrustedRoleSetup() : null;
    // Persist intent before invoking Docker; a lost ACK must never become PASS.
    persist("MUTATION_PENDING", stage);
    let result;
    try { result = invokeRaw(args, options); } catch { /* unknown Docker effect */ }
    if (initializerIdentity !== null) {
      try { verifyTrustedRoleSetup({ previous: initializerIdentity }); } catch {
        receipt.uncertainOperations.push(stage);
        persist("RECONCILIATION_REQUIRED", stage);
        refuse(`disposable initializer identity changed during Docker operation; reconcile using ${receiptPath}`);
      }
    }
    if (result?.error || result?.status !== 0) {
      receipt.uncertainOperations.push(stage);
      persist("RECONCILIATION_REQUIRED", stage);
      refuse(`uncertain Docker mutation ${stage}; reconcile using receipt ${receiptPath}`);
    }
    persist("MUTATION_ACKNOWLEDGED", stage);
    if (!cleanupOperation) acknowledgedStages.push(stage);
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
