import os from "node:os";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync,
  readdirSync, rmSync, statfsSync, unlinkSync, writeSync,
} from "node:fs";
import { receiveOfflineWireToQuarantine, publishVerifiedOfflineQuarantine } from "./lib/offline-ssh-stage-protocol.mjs";
import { OFFLINE_SSH_LOGIN, verifyRemoteOfflineTransferPermit } from "./lib/offline-ssh-transfer-permit.mjs";

// Must be installed independently from an audited root-owned verifier build.
// The non-root forced SSH gate invokes the fixed root receiver through
// independently approved sudoers. Neither is executed out of a release TAR.
const HOST_STAGE_ROOT = "/var/lib/virki/offline-staging";
const INSTALL_ROOT = "/usr/local/lib/virki/offline-transfer";
const ACCEPTED_COMMAND = "offline-receive-v1";
const LOCK = HOST_STAGE_ROOT + "/.receiver-lock";
const RECEIVER_PATH = INSTALL_ROOT + "/offline-host-transfer-receiver.mjs";
const NODE_PATH = "/usr/bin/node";
const SUDO_PATH = "/usr/bin/sudo";
const EXPECTED_SUDO_COMMAND = NODE_PATH + " " + RECEIVER_PATH;
const PRODUCTION_ROOT = "/srv/virki";
const HOST_APPROVAL_ROOT = "/etc/virki/offline-transfer-host";
const NONCE_JOURNAL = "/var/lib/virki/offline-transfer-nonces";
const PROBE_COMMANDS = Object.freeze({
  "offline-probe-v1": "--read-probe",
  "offline-docker-v1": "--read-docker",
  "offline-identity-v1": "--read-identity",
});
const READONLY_PROBES = new Set(Object.values(PROBE_COMMANDS));
export function restrictedOfflineSshGateSelector(originalCommand) {
  if (originalCommand === ACCEPTED_COMMAND) return null;
  if (Object.hasOwn(PROBE_COMMANDS, originalCommand)) return PROBE_COMMANDS[originalCommand];
  throw new Error("Unapproved SSH original command");
}
export function buildExactRestrictedOfflineSudoArgs(originalCommand) {
  const selector = restrictedOfflineSshGateSelector(originalCommand);
  return Object.freeze(["-n", "-u", "root", "--", NODE_PATH, RECEIVER_PATH,
    ...(selector === null ? [] : [selector])]);
}

function installedExecutable() {
  const own = fileURLToPath(import.meta.url);
  if (own !== RECEIVER_PATH || realpathSync.native(own) !== own) return false;
  const file = lstatSync(own);
  const root = lstatSync(INSTALL_ROOT);
  return file.isFile() && file.uid === 0 && (file.mode & 0o022) === 0 &&
    root.isDirectory() && root.uid === 0 && (root.mode & 0o022) === 0 &&
    realpathSync.native(INSTALL_ROOT) === INSTALL_ROOT;
}

/**
 * Unprivileged sshd forced-command gate. The only elevation is an exact
 * owner-installed sudoers permission for root to execute this fixed receiver,
 * with no shell, user-controlled args, arbitrary destination or environment.
 */
export function runInstalledOfflineSshGate() {
  if (process.platform !== "linux" || process.arch !== "x64" ||
      /microsoft|wsl/iu.test(os.release()) || !installedExecutable() ||
      process.getuid?.() === 0 || os.userInfo().username !== OFFLINE_SSH_LOGIN) {
    throw new Error("Fixed non-root SSH gate refused");
  }
  const args = buildExactRestrictedOfflineSudoArgs(process.env.SSH_ORIGINAL_COMMAND);
  const sudo = lstatSync(SUDO_PATH);
  if (!sudo.isFile() || sudo.uid !== 0 || (sudo.mode & 0o022) !== 0) {
    throw new Error("Protected sudo binary unavailable");
  }
  const result = spawnSync(SUDO_PATH, args, {
      shell: false, stdio: "inherit", windowsHide: true,
    });
  return result.error || result.signal ? 2 : result.status;
}

function requireNativeProbeContext(selector) {
  if (!READONLY_PROBES.has(selector) || process.platform !== "linux" ||
      process.arch !== "x64" || /microsoft|wsl/iu.test(os.release()) ||
      process.getuid?.() !== 0 || !installedExecutable() ||
      process.env.SUDO_USER !== OFFLINE_SSH_LOGIN ||
      !/^[1-9][0-9]*$/u.test(process.env.SUDO_UID ?? "") ||
      process.env.SUDO_COMMAND !== EXPECTED_SUDO_COMMAND + " " + selector ||
      ["NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"].some(
        (name) => Object.hasOwn(process.env, name))) {
    throw new Error("Untrusted native read-only SSH probe context");
  }
}

function protectedFile(location, mode) {
  if (realpathSync.native(location) !== location) throw new Error("Aliased native host path");
  const meta = lstatSync(location);
  const allowed = Array.isArray(mode) ? mode : [mode];
  if (!meta.isFile() || meta.uid !== 0 || meta.nlink !== 1 ||
      !allowed.includes(meta.mode & 0o7777)) {
    throw new Error("Native host file ownership or mode invalid");
  }
  return meta;
}

function protectedDirectory(location) {
  if (realpathSync.native(location) !== location) throw new Error("Aliased native host directory");
  const meta = lstatSync(location);
  if (!meta.isDirectory() || meta.uid !== 0 || (meta.mode & 0o7777) !== 0o700) {
    throw new Error("Native host directory ownership or mode invalid");
  }
}

function loadIndependentlyInstalledHostTransferPolicy() {
  protectedDirectory(HOST_APPROVAL_ROOT);
  const entries = readdirSync(HOST_APPROVAL_ROOT);
  if (entries.length !== 1 || entries[0] !== "host-policy.json") {
    throw new Error("Independent remote host approval policy missing or ambiguous");
  }
  const file = path.join(HOST_APPROVAL_ROOT, "host-policy.json");
  const before = lstatSync(file, { bigint: true });
  if (!before.isFile() || before.uid !== 0n || before.nlink !== 1n ||
      (before.mode & 0o7777n) !== 0o600n || before.size < 1n || before.size > 4096n) {
    throw new Error("Unsafe independent remote transfer policy inode");
  }
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const same = (st) => st.dev === before.dev && st.ino === before.ino &&
      st.size === before.size && st.mode === before.mode && st.uid === before.uid &&
      st.mtimeNs === before.mtimeNs && st.ctimeNs === before.ctimeNs;
    if (!same(lstatSync(file, { bigint: true })) ||
        !same(fstatSync(fd, { bigint: true }))) {
      throw new Error("Independent remote approval changed on open");
    }
    const bytes = readFileSync(fd);
    if (!same(lstatSync(file, { bigint: true }))) {
      throw new Error("Independent remote approval changed during read");
    }
    const obj = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    const fields = ["version", "mode", "expectedSourceSha", "host", "port",
      "sshAlias", "sshUser", "knownHostsSha256", "clientSshKeyPinSha256",
      "ownerPublicKeyPem"];
    if (Object.keys(obj).length !== fields.length ||
        fields.some((name, i) => Object.keys(obj)[i] !== name) ||
        JSON.stringify(obj) !== bytes.toString("utf8")) {
      throw new Error("Remote approval JSON not canonical");
    }
    return obj;
  } finally { closeSync(fd); }
}

/** Persist the nonce BEFORE any archive data; a crash permanently consumes it. */
export function consumeOfflineSignedTransferNonce(journalDirectory, nonce, manifestSha256) {
  protectedDirectory(journalDirectory);
  if (!/^[a-f0-9]{32}$/u.test(nonce) || !/^[a-f0-9]{64}$/u.test(manifestSha256)) {
    throw new Error("Invalid remote transfer nonce or signed manifest");
  }
  const file = path.join(journalDirectory, nonce);
  const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT |
    constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const bytes = Buffer.from("VIRKI_SIGNED_TRANSFER_NONCE_V1 " + manifestSha256 + "\n");
    if (writeSync(fd, bytes) !== bytes.length) throw new Error("Nonce journal write incomplete");
    fsyncSync(fd);
  } finally { closeSync(fd); }
  const dirfd = openSync(journalDirectory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(dirfd); } finally { closeSync(dirfd); }
}

function authorizeRemoteTransfer({ permitBytes, signatureBytes, manifestSha256, envelopeSha256 }) {
  const policy = loadIndependentlyInstalledHostTransferPolicy();
  const verified = verifyRemoteOfflineTransferPermit({
    permitBytes, signatureBytes, hostPolicy: policy, manifestSha256, envelopeSha256,
  });
  consumeOfflineSignedTransferNonce(NONCE_JOURNAL, verified.nonce, verified.manifestSha256);
}

function readNativeHostProbe() {
  protectedDirectory(PRODUCTION_ROOT);
  for (const name of [".deploy-tmp", "releases", "backups"]) {
    protectedDirectory(path.join(PRODUCTION_ROOT, name));
  }
  for (const name of [".env", ".env.oidc", ".env.oidc-data"]) {
    protectedFile(path.join(PRODUCTION_ROOT, name), 0o600);
  }
  const marker = path.join(PRODUCTION_ROOT, ".virki-production-host");
  protectedFile(marker, 0o600);
  const host = spawnSync("/usr/bin/hostname", ["-s"], {
    encoding: "utf8", timeout: 5000, maxBuffer: 1024,
  });
  if (host.status !== 0 || !/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\n?$/u.test(host.stdout)) {
    throw new Error("Native short hostname untrusted");
  }
  const name = host.stdout.trim();
  const lines = readFileSync(marker, "utf8").trimEnd().split("\n");
  if (lines.length !== 4 || !["role=production", "protocol=2",
    "hostname=" + name, "path=" + PRODUCTION_ROOT].every((line) => lines.includes(line))) {
    throw new Error("Native production host marker invalid");
  }
  return ["VIRKI_PROBE_ID=" + name, "VIRKI_PROBE_WD=" + PRODUCTION_ROOT,
    "VIRKI_PROBE_PLATFORM=linux-native", "VIRKI_PROBE_MARKER=valid"].join("\n") + "\n";
}

function readNativeDockerProbe() {
  const docker = "/usr/bin/docker";
  const lock = "/usr/bin/flock";
  for (const binary of [docker, lock]) {
    const st = lstatSync(binary);
    if (!st.isFile() || st.uid !== 0 || (st.mode & 0o022) !== 0) {
      throw new Error("Native Docker/flock executable not owner-protected");
    }
  }
  protectedDirectory(PRODUCTION_ROOT);
  const run = (args, allowEmpty = false) => {
    const r = spawnSync(docker, args, {
      encoding: "utf8", timeout: 10000, maxBuffer: 16384, stdio: ["ignore", "pipe", "ignore"],
    });
    if (r.status !== 0 || (!allowEmpty && !r.stdout) || r.error || r.signal) {
      throw new Error("Docker read-only probe failed");
    }
    return r.stdout.trim();
  };
  const version = run(["version", "--format", "{{.Server.Version}}"]);
  const info = run(["info", "--format", "{{.ServerVersion}}"]);
  const compose = run(["compose", "version", "--short"]);
  const type = run(["info", "--format", "{{.OSType}}"]);
  const rawArch = run(["info", "--format", "{{.Architecture}}"]);
  const arch = ["x86_64", "amd64"].includes(rawArch) ? "amd64" :
    ["aarch64", "arm64"].includes(rawArch) ? "arm64" : "";
  const names = run(["ps", "--format", "{{.Names}}"], true).split("\n");
  const count = names.filter((name) => /demanage/iu.test(name)).length;
  const release = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,126}$/u;
  if (type !== "linux" || !arch || ![version, info, compose].every((x) => release.test(x))) {
    throw new Error("Unsupported Docker platform or version output");
  }
  const fs = statfsSync(PRODUCTION_ROOT, { bigint: true });
  const freeGiB = Number(fs.bavail * fs.bsize) / (1024 ** 3);
  if (!Number.isFinite(freeGiB) || freeGiB < 0) throw new Error("Native capacity invalid");
  return ["VIRKI_DOCKER_VERSION=" + version, "VIRKI_DOCKER_INFO=" + info,
    "VIRKI_COMPOSE_VERSION=" + compose, "VIRKI_PLATFORM=linux/" + arch,
    "VIRKI_FLOCK=available", "VIRKI_DISK_FREE_GB=" + freeGiB.toFixed(1),
    "VIRKI_DEMANAGE_COUNT=" + count].join("\n") + "\n";
}

function readNativeIdentityProbe() {
  const location = "/etc/machine-id";
  protectedFile(location, [0o644, 0o444]);
  const id = readFileSync(location, "utf8").trim();
  if (!/^[a-f0-9]{32}$/u.test(id) || /^0+$/u.test(id)) {
    throw new Error("Native host identity malformed");
  }
  const hash = createHash("sha256").update(Buffer.concat([
    Buffer.from("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0"), Buffer.from(id),
  ])).digest("hex");
  return "VIRKI_OFFLINE_HOST_ID_SHA256=" + hash + "\n";
}

export function runInstalledOfflineReadOnlyProbe(selector) {
  requireNativeProbeContext(selector);
  if (selector === "--read-probe") return readNativeHostProbe();
  if (selector === "--read-docker") return readNativeDockerProbe();
  return readNativeIdentityProbe();
}

function syncParent() {
  const fd = openSync(HOST_STAGE_ROOT,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function acquireNativeReceiverLock() {
  if (realpathSync.native(HOST_STAGE_ROOT) !== HOST_STAGE_ROOT) {
    throw new Error("Native receiver root has symlinked ancestor");
  }
  const stat = lstatSync(HOST_STAGE_ROOT);
  if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o7777) !== 0o700 ||
      readdirSync(HOST_STAGE_ROOT).length !== 0) {
    throw new Error("Native stage root is not empty owner-private 0700");
  }
  // O_EXCL is atomic across concurrent incoming SSH sessions. A crashed
  // receiver leaves its lock behind, so the owner must reconcile instead
  // of retrying a potentially partly admitted transfer.
  const fd = openSync(LOCK, constants.O_WRONLY | constants.O_CREAT |
    constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { fsyncSync(fd); } finally { closeSync(fd); }
  syncParent();
}

export async function runInstalledOfflineSshReceiver() {
  if (process.platform !== "linux" || process.arch !== "x64" ||
      process.getuid?.() !== 0 || /microsoft|wsl/iu.test(os.release()) ||
      !installedExecutable() ||
      process.env.SUDO_USER !== OFFLINE_SSH_LOGIN ||
      !/^[1-9][0-9]*$/u.test(process.env.SUDO_UID ?? "") ||
      process.env.SUDO_COMMAND !== EXPECTED_SUDO_COMMAND ||
      (process.env.SSH_ORIGINAL_COMMAND !== undefined &&
        process.env.SSH_ORIGINAL_COMMAND !== ACCEPTED_COMMAND) ||
      ["NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"].some(
        (name) => Object.hasOwn(process.env, name))) {
    throw new Error("Native owner-installed forced SSH receiver required");
  }
  acquireNativeReceiverLock();
  let retainLock = false;
  try {
    const stage = await receiveOfflineWireToQuarantine({
      readable: process.stdin, stagingParent: HOST_STAGE_ROOT, requireRoot: true,
      authorizeTransfer: authorizeRemoteTransfer,
    });
    try {
    const completed = await publishVerifiedOfflineQuarantine({
      pendingDirectory: stage.pendingDirectory,
      stagingParent: HOST_STAGE_ROOT,
      manifestSha256: stage.manifestSha256,
    });
    return Object.freeze({
      status: "HOST_OWNER_SIGNED_PRIVATE_STAGE_VERIFIED",
      stageName: path.basename(completed),
      fileCount: 11,
      manifestSha256: stage.manifestSha256,
      transferAuthorized: false,
      deployAuthorized: false,
    });
    } catch (error) {
      if (error.code !== "OFFLINE_REMOTE_STAGE_SYNC_UNCERTAIN") {
        rmSync(stage.pendingDirectory, { recursive: true, force: true });
      } else {
        retainLock = true;
      }
      throw error;
    }
  } finally {
    if (!retainLock) {
      // If cleanup was interrupted, preserve the lock and fail closed.
      const files = readdirSync(HOST_STAGE_ROOT);
      if (files.every((entry) => entry === ".receiver-lock" ||
        /^candidate-[a-f0-9]{32}$/u.test(entry))) {
        unlinkSync(LOCK);
        syncParent();
      }
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length === 3 && process.argv[2] === "--gate") {
    try { process.exitCode = runInstalledOfflineSshGate(); }
    catch {
      process.stderr.write("Offline restricted SSH gate refused.\n");
      process.exitCode = 2;
    }
  } else if (process.argv.length === 3 && READONLY_PROBES.has(process.argv[2])) {
    try { process.stdout.write(runInstalledOfflineReadOnlyProbe(process.argv[2])); }
    catch {
      process.stderr.write("Offline installed read-only probe refused.\n");
      process.exitCode = 2;
    }
  } else if (process.argv.length !== 2) process.exitCode = 2;
  else {
    try {
      const receipt = await runInstalledOfflineSshReceiver();
      process.stdout.write(JSON.stringify(receipt) + "\n");
    } catch {
      process.stderr.write("Offline SSH receiver refused; stage not admitted.\n");
      process.exitCode = 2;
    }
  }
}
