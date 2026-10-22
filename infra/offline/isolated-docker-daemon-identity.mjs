import { createHash } from "node:crypto";
import {
  constants, closeSync, fstatSync, lstatSync, openSync, readFileSync,
  readlinkSync, readdirSync, realpathSync, statfsSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

// READ-ONLY diagnostic. It cannot mint admission, launch Docker, grant an
// image import, or change a release ledger. A socket pathname and Docker
// info output cannot establish a Unix peer's kernel credentials.
const POLICY_DIR = "/etc/virki/offline-import-daemon";
const POLICY_FILE = POLICY_DIR + "/daemon-policy.json";
const IMPORT_CLI_PIN = "/etc/virki/offline-import-cli.sha256";
const SOCKET_DIR = "/run/virki-offline-import";
const SOCKET = SOCKET_DIR + "/docker.sock";
const CLI = SOCKET_DIR + "/docker";
const DAEMON = SOCKET_DIR + "/dockerd";
const DATA_ROOT = "/var/lib/virki/offline-import-daemon-data";
const EXEC_ROOT = SOCKET_DIR + "/exec";
const MODE = "virki-isolated-daemon-owner-pin-v1";
const PROC_MAGIC = 0x9fa0;
const SHA = /^[a-f0-9]{64}$/u;
const INODE = /^[1-9][0-9]{0,19}$/u;
const NS = /^(?:mnt|net|pid):\[[1-9][0-9]{0,19}\]$/u;
const POLICY_FIELDS = Object.freeze([
  "version", "mode", "cliSha256", "daemonSha256", "daemonPid",
  "daemonStartTicks", "socketKernelInode", "daemonCgroup",
  "mountNamespace", "netNamespace", "pidNamespace",
]);
const DENY = Object.freeze({
  status: "BLOCKED_DAEMON_PROVENANCE_UNVERIFIED",
  dockerLoadAuthorized: false, deployAuthorized: false,
  peerVerified: false, lifecycleVerified: false,
});

function requireIt(condition, reason) {
  if (!condition) throw new Error("Isolated Docker daemon identity refused: " + reason);
}
function same(a, b) {
  return ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function exact(value, keys, label) {
  requireIt(value !== null && typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key, index) => Object.keys(value)[index] === key),
  label + " missing, reordered or unexpected fields");
}
function readOwnerFile(filename, max, mode) {
  const before = lstatSync(filename, { bigint: true });
  requireIt(before.isFile() && !before.isSymbolicLink() && before.uid === 0n &&
    before.gid === 0n && before.nlink === 1n &&
    (before.mode & 0o7777n) === BigInt(mode) &&
    before.size > 0n && before.size <= BigInt(max),
  "owner-controlled file is unsafe");
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    requireIt(same(before, fstatSync(fd, { bigint: true })), "owner file replaced on open");
    const bytes = readFileSync(fd);
    requireIt(bytes.length === Number(before.size) &&
      same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(filename, { bigint: true })),
    "owner file modified during read");
    return bytes;
  } finally {
    closeSync(fd);
  }
}
function ownerDirectory(directory, mode) {
  requireIt(realpathSync.native(directory) === directory, "directory resolves via alias");
  let current = directory;
  while (true) {
    const stat = lstatSync(current, { bigint: true });
    requireIt(stat.isDirectory() && !stat.isSymbolicLink() &&
      stat.uid === 0n && stat.gid === 0n &&
      (stat.mode & 0o022n) === 0n &&
      (current !== directory || (stat.mode & 0o7777n) === BigInt(mode)),
    "directory or ancestor is not root-protected");
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}
function parsePolicy(bytes) {
  requireIt(Buffer.isBuffer(bytes) && bytes.length <= 4096 && bytes.length > 0,
    "owner policy size invalid");
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const policy = JSON.parse(decoded);
  exact(policy, POLICY_FIELDS, "owner policy");
  requireIt(JSON.stringify(policy) === decoded &&
    policy.version === 1 && policy.mode === MODE &&
    SHA.test(policy.cliSha256) && SHA.test(policy.daemonSha256) &&
    Number.isSafeInteger(policy.daemonPid) && policy.daemonPid > 1 &&
    policy.daemonPid <= 4194304 &&
    INODE.test(policy.daemonStartTicks) &&
    INODE.test(policy.socketKernelInode) &&
    /^0::\/virki-offline-import(?:\.[a-z0-9-]+)?\.slice$/u.test(policy.daemonCgroup) &&
    NS.test(policy.mountNamespace) && policy.mountNamespace.startsWith("mnt:") &&
    NS.test(policy.netNamespace) && policy.netNamespace.startsWith("net:") &&
    NS.test(policy.pidNamespace) && policy.pidNamespace.startsWith("pid:"),
  "independent policy is malformed or not scoped to an isolated daemon");
  return Object.freeze(policy);
}
function expectedCmdline() {
  return Object.freeze([
    DAEMON,
    "--host=unix://" + SOCKET,
    "--data-root=" + DATA_ROOT,
    "--exec-root=" + EXEC_ROOT,
    "--config-file=/dev/null",
    "--iptables=false",
    "--ip6tables=false",
    "--bridge=none",
    "--userland-proxy=false",
  ]);
}
function parseStartTicks(raw) {
  requireIt(typeof raw === "string" && raw.length <= 8192, "proc stat is oversized");
  const end = raw.lastIndexOf(")");
  requireIt(end > 0 && raw[end + 1] === " ", "proc stat has invalid comm");
  const fields = raw.slice(end + 2).trim().split(/\s+/u);
  const start = fields[19];
  requireIt(INODE.test(start ?? ""), "proc start ticks missing");
  return start;
}
function parseUnixSocketInode(raw, pathname) {
  requireIt(typeof raw === "string" && raw.length <= 4 * 1024 * 1024,
    "kernel Unix sockets listing oversized");
  const lines = raw.trim().split(/\n/u).slice(1);
  const matches = [];
  for (const line of lines) {
    const columns = line.trim().split(/\s+/u);
    if (columns.length === 8 && columns[7] === pathname) {
      // Listening stream socket only; abstract and unnamed sockets forbidden.
      requireIt(columns[3] === "00010000" &&
        columns[4] === "0001" && INODE.test(columns[6]),
      "socket is not a listening Unix stream");
      matches.push(columns[6]);
    }
  }
  requireIt(matches.length === 1, "socket endpoint is missing or ambiguous");
  return matches[0];
}
function checkStatus(raw) {
  requireIt(typeof raw === "string" && raw.length <= 65536, "proc status invalid");
  for (const field of ["Uid", "Gid"]) {
    const match = raw.match(new RegExp("^" + field + ":\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)$", "mu"));
    requireIt(match && match.slice(1).every((number) => number === "0"),
      "daemon real/effective/saved/filesystem credentials not root");
  }
}
function parseArgs(raw) {
  requireIt(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= 4096 &&
    raw[raw.length - 1] === 0,
  "daemon commandline invalid");
  const args = raw.subarray(0, -1).toString("utf8").split("\0");
  requireIt(args.every((arg) => arg.length > 0 && !arg.includes("\ufffd")) &&
    JSON.stringify(args) === JSON.stringify(expectedCmdline()),
  "daemon commandline does not pin its socket and separate data/exec roots");
  return args;
}
function inspectEvidence(policy, evidence) {
  exact(evidence, [
    "cliSha256", "daemonSha256", "daemonPid", "daemonStartTicks",
    "socketKernelInode", "socketOwnedByDaemon", "daemonCgroup",
    "mountNamespace", "netNamespace", "pidNamespace", "procRootOwned",
    "socketFileRootPrivate", "dataRootPrivate", "execRootPrivate",
    "namespacesDifferFromInspector",
    "daemonUidRoot", "daemonCmdlineExact", "kernelPeerCredentials",
    "independentlyAttestedLifecycle",
  ], "kernel evidence");
  for (const key of [
    "cliSha256", "daemonSha256", "daemonPid", "daemonStartTicks",
    "socketKernelInode", "daemonCgroup", "mountNamespace",
    "netNamespace", "pidNamespace",
  ]) requireIt(evidence[key] === policy[key], "daemon kernel identity differs from owner pin");
  for (const field of [
    "socketOwnedByDaemon", "procRootOwned", "socketFileRootPrivate",
    "dataRootPrivate", "execRootPrivate", "daemonUidRoot",
    "daemonCmdlineExact", "namespacesDifferFromInspector",
  ]) requireIt(evidence[field] === true, "daemon kernel isolation evidence missing");
  // A process holding the LISTENING FD is not necessarily the peer accepting
  // our connection. Node does not expose Linux SO_PEERCRED. Nor does a PID
  // and starttime prove that an operator supervised its entire lifecycle.
  // These values are deliberately never inferred or trusted from Docker info.
  requireIt(evidence.kernelPeerCredentials === false &&
    evidence.independentlyAttestedLifecycle === false,
  "unsupported caller-supplied peer or lifecycle attestation");
  return Object.freeze({
    status: "KERNEL_IDENTITY_MATCHES_PINS_PEER_AND_LIFECYCLE_UNPROVEN",
    daemonPid: policy.daemonPid,
    socketKernelInode: policy.socketKernelInode,
    dockerLoadAuthorized: false,
    deployAuthorized: false,
    peerVerified: false,
    lifecycleVerified: false,
    missingProofs: Object.freeze([
      "Kernel SO_PEERCRED for the live connection, cryptographically bound to this import",
      "Independently provisioned isolation supervisor with a pinned, continuously held daemon lifecycle",
    ]),
  });
}

/** Pure diagnostic on supplied TEST evidence; no authorization or host access. */
export function previewIsolatedDaemonEvidenceForTests({ policyBytes, evidence } = {}) {
  try {
    return inspectEvidence(parsePolicy(policyBytes), evidence);
  } catch {
    return DENY;
  }
}

/**
 * Docker info is self-reported by the queried endpoint and is NOT kernel
 * provenance. This bounded, pure comparison cannot authorize a Docker call
 * even if every value matches the expected isolated engine configuration.
 */
export function compareUntrustedDockerInfoForPreview(info = {}) {
  try {
    exact(info, ["DockerRootDir", "Driver", "CgroupVersion", "CgroupDriver"],
      "untrusted Docker info");
    requireIt(info.DockerRootDir === DATA_ROOT &&
      info.Driver === "vfs" && info.CgroupVersion === "2" &&
      info.CgroupDriver === "systemd",
    "self-reported Docker info does not match independent isolated-root design");
    return Object.freeze({
      status: "DOCKER_INFO_CORRELATES_ONLY_NOT_DAEMON_PROVENANCE",
      dockerLoadAuthorized: false, deployAuthorized: false,
      peerVerified: false, lifecycleVerified: false,
    });
  } catch {
    return DENY;
  }
}

/** Pure synthetic Linux /proc fixture. NEVER reads host files or grants authority. */
export function previewSyntheticProcDaemonForTests({ policyBytes, snapshot } = {}) {
  try {
    const policy = parsePolicy(policyBytes);
    exact(snapshot, [
      "cliSha256", "daemonSha256", "daemonPid", "statBefore", "statAfter",
      "unixBefore", "unixAfter", "fdLinksBefore", "fdLinksAfter",
      "status", "cmdline", "cgroup", "mountNamespace", "netNamespace",
      "pidNamespace", "procRootOwned", "socketFileRootPrivate",
      "dataRootPrivate", "execRootPrivate", "namespacesDifferFromInspector",
    ], "synthetic proc fixture");
    requireIt(Array.isArray(snapshot.fdLinksBefore) &&
      Array.isArray(snapshot.fdLinksAfter) &&
      snapshot.fdLinksBefore.length <= 4096 &&
      snapshot.fdLinksAfter.length <= 4096,
    "synthetic proc FD inventory invalid");
    checkStatus(snapshot.status);
    parseArgs(Buffer.from(snapshot.cmdline));
    const start = parseStartTicks(snapshot.statBefore);
    const inode = parseUnixSocketInode(snapshot.unixBefore, SOCKET);
    requireIt(start === parseStartTicks(snapshot.statAfter) &&
      inode === parseUnixSocketInode(snapshot.unixAfter, SOCKET) &&
      snapshot.fdLinksBefore.includes("socket:[" + inode + "]") &&
      snapshot.fdLinksAfter.includes("socket:[" + inode + "]"),
    "synthetic PID lifecycle or socket FD identity changed");
    return inspectEvidence(policy, {
      cliSha256: snapshot.cliSha256, daemonSha256: snapshot.daemonSha256,
      daemonPid: snapshot.daemonPid, daemonStartTicks: start,
      socketKernelInode: inode, socketOwnedByDaemon: true,
      daemonCgroup: snapshot.cgroup,
      mountNamespace: snapshot.mountNamespace, netNamespace: snapshot.netNamespace,
      pidNamespace: snapshot.pidNamespace, procRootOwned: snapshot.procRootOwned,
      socketFileRootPrivate: snapshot.socketFileRootPrivate,
      dataRootPrivate: snapshot.dataRootPrivate,
      execRootPrivate: snapshot.execRootPrivate,
      namespacesDifferFromInspector: snapshot.namespacesDifferFromInspector,
      daemonUidRoot: true, daemonCmdlineExact: true,
      kernelPeerCredentials: false, independentlyAttestedLifecycle: false,
    });
  } catch {
    return DENY;
  }
}

function nativeRoot() {
  requireIt(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && !/microsoft|wsl/iu.test(os.release()) &&
    statfsSync("/proc").type === PROC_MAGIC &&
    constants.O_NOFOLLOW && constants.O_DIRECTORY,
  "genuine native Linux root and kernel procfs required");
}
function hashRunningExecutable(filename, expectedTarget, expectedSha) {
  // /proc/<pid>/exe is deliberately a kernel-created magic symlink. A plain
  // pathname regular-file lstat check rejects it; pin its target descriptor
  // and read it only after enforcing the exact expected link destination.
  const target = readlinkSync(filename);
  requireIt(target === expectedTarget, "running executable path not pinned");
  const fd = openSync(filename, constants.O_RDONLY);
  try {
    const before = fstatSync(fd, { bigint: true });
    requireIt(before.isFile() && before.uid === 0n &&
      before.size > 0n && before.size <= 64n * 1024n * 1024n &&
      before.nlink === 1n, "running executable is not a private regular inode");
    const bytes = readFileSync(fd);
    requireIt(bytes.length === Number(before.size) &&
      digest(bytes) === expectedSha &&
      same(before, fstatSync(fd, { bigint: true })) &&
      readlinkSync(filename) === target,
    "running executable inode or hash differs from independently pinned bytes");
  } finally {
    closeSync(fd);
  }
}
function checkPrivateRoot(directory) {
  ownerDirectory(directory, 0o700);
  return true;
}
function collect(policy) {
  const pid = policy.daemonPid;
  const proc = "/proc/" + pid;
  const firstTicks = parseStartTicks(readFileSync(proc + "/stat", "utf8"));
  const unix = parseUnixSocketInode(readFileSync(proc + "/net/unix", "utf8"), SOCKET);
  const socket = lstatSync(SOCKET, { bigint: true });
  requireIt(socket.isSocket() && !socket.isSymbolicLink() &&
    socket.uid === 0n && socket.gid === 0n &&
    (socket.mode & 0o7777n) === 0o600n,
  "daemon socket is not a private root-owned Unix socket");
  const fdLinks = readdirSync(proc + "/fd").map((name) => readlinkSync(proc + "/fd/" + name));
  const ownsFd = fdLinks.includes("socket:[" + unix + "]");
  ownerDirectory("/etc/virki", 0o755);
  const cliPin = readOwnerFile(IMPORT_CLI_PIN, 65, 0o600).toString("ascii");
  requireIt(cliPin === policy.cliSha256 + "\n",
    "independent daemon CLI pin differs from the importer's owner-provisioned pin");
  const cli = readOwnerFile(CLI, 64 * 1024 * 1024, 0o700);
  hashRunningExecutable(proc + "/exe", DAEMON, policy.daemonSha256);
  checkStatus(readFileSync(proc + "/status", "utf8"));
  parseArgs(readFileSync(proc + "/cmdline"));
  const cgroup = readFileSync(proc + "/cgroup", "utf8").trim();
  const namespaces = ["mnt", "net", "pid"].map((name) => readlinkSync(proc + "/ns/" + name));
  const isolated = ["mnt", "net", "pid"].every((name, index) =>
    readlinkSync("/proc/self/ns/" + name) !== namespaces[index]);
  const result = {
    cliSha256: digest(cli), daemonSha256: policy.daemonSha256,
    daemonPid: pid, daemonStartTicks: firstTicks,
    socketKernelInode: unix, socketOwnedByDaemon: ownsFd,
    daemonCgroup: cgroup,
    mountNamespace: namespaces[0], netNamespace: namespaces[1],
    pidNamespace: namespaces[2],
    procRootOwned: statfsSync(proc).type === PROC_MAGIC,
    socketFileRootPrivate: true,
    dataRootPrivate: checkPrivateRoot(DATA_ROOT),
    execRootPrivate: checkPrivateRoot(EXEC_ROOT),
    namespacesDifferFromInspector: isolated,
    daemonUidRoot: true, daemonCmdlineExact: true,
    kernelPeerCredentials: false, independentlyAttestedLifecycle: false,
  };
  requireIt(parseStartTicks(readFileSync(proc + "/stat", "utf8")) === firstTicks &&
    readlinkSync(proc + "/exe") === DAEMON &&
    readlinkSync(proc + "/ns/mnt") === namespaces[0] &&
    readlinkSync(proc + "/ns/net") === namespaces[1] &&
    readlinkSync(proc + "/ns/pid") === namespaces[2] &&
    parseUnixSocketInode(readFileSync(proc + "/net/unix", "utf8"), SOCKET) === unix &&
    readdirSync(proc + "/fd").some((name) =>
      readlinkSync(proc + "/fd/" + name) === "socket:[" + unix + "]"),
  "daemon identity, socket owner or namespace changed during measurement");
  return result;
}

/**
 * Native READ-ONLY owner-controlled diagnostic. The caller cannot inject
 * policy, paths, evidence or Docker output. No production socket is opened,
 * no daemon command is run, and no Docker API operation is performed.
 */
export function inspectNativeIsolatedDockerDaemon(request = {}) {
  try {
    exact(request, [], "native inspection request");
    nativeRoot();
    ownerDirectory(POLICY_DIR, 0o700);
    ownerDirectory(SOCKET_DIR, 0o700);
    const policy = parsePolicy(readOwnerFile(POLICY_FILE, 4096, 0o600));
    requireIt(realpathSync.native(SOCKET) === SOCKET, "socket path aliases another daemon");
    return inspectEvidence(policy, collect(policy));
  } catch {
    return DENY;
  }
}
