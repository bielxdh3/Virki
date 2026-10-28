import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectUntrustedOfflineCandidate } from "../infra/offline/trusted-host-entry.mjs";
import { validateOfflineCiEvidence } from "./lib/offline-ci-evidence.mjs";
import { verifyOfflineReleaseAttestation } from "./lib/offline-release-attestation.mjs";
import { prepareOfflineTrustedReleasePolicy } from "./lib/offline-trusted-release-policy.mjs";
import { inspectOfflineProductionSource } from "./lib/production-revision.mjs";
import { isValidProductionConfig } from "./lib/production-config.mjs";
import { runProductionPreflight, SSH_OPTIONS } from "./production-preflight.mjs";

// Read-only local operator inspector only. No transfer, deployment, docker
// load, source execution, owner signing, anti-replay write, or GHCR fallback.
const TRUST_FILES = ["ledger.json", "ssh-known-hosts", "transport-policy.json", "trust-policy.json"];
const POLICY_FIELDS = [
  "version", "mode", "enabled", "expectedRevision", "sshAlias", "host", "port", "root",
  "knownHostsSha256", "runtimeExpandedBytes", "migratorExpandedBytes", "databaseBytes",
];
const SHA = /^[a-f0-9]{40}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const SSH_PATH = "/usr/bin/ssh";
const MAX_CAPACITY = 8 * 1024 ** 4;
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
function refuse(reason) { throw new Error("Offline production transport refused: " + reason); }
function requireIt(ok, reason) { if (!ok) refuse(reason); }
function exact(value, names, reason) {
  requireIt(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every((key) => Object.hasOwn(value, key)), reason);
}
function identical(a, b) {
  return ["dev", "ino", "nlink", "mode", "size", "mtimeNs", "ctimeNs"].every((key) => a[key] === b[key]);
}
function safeAbsolute(raw, label) {
  requireIt(typeof raw === "string" && raw.length > 1 && raw.length <= 4096 &&
    path.isAbsolute(raw) && path.normalize(raw) === raw &&
    raw !== path.parse(raw).root && !raw.includes("\0"), label + " path unsafe");
  requireIt(realpathSync.native(raw) === raw, label + " symlink or aliased ancestor");
  return raw;
}
function disjoint(a, b) {
  return a !== b && !a.startsWith(b + path.sep) && !b.startsWith(a + path.sep);
}
function parseStrict(raw, fields, name) {
  requireIt(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= 16384, name + " size invalid");
  let decoded, parsed;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    parsed = JSON.parse(decoded);
  } catch { refuse(name + " is not JSON UTF-8"); }
  exact(parsed, fields, name + " fields invalid");
  requireIt(JSON.stringify(parsed) === decoded, name + " JSON not canonical");
  return parsed;
}
function readProtectedInputs(dir) {
  safeAbsolute(dir, "private operator directory");
  requireIt(process.platform === "linux" && process.getuid?.() === 0 &&
    constants.O_NOFOLLOW && constants.O_DIRECTORY && constants.O_NONBLOCK,
  "privately provisioned root-owned Linux trust directory required");
  const rootBefore = lstatSync(dir, { bigint: true });
  requireIt(rootBefore.isDirectory() && rootBefore.uid === 0n &&
    (rootBefore.mode & 0o7777n) === 0o700n, "trusted root must be 0700 root-owned");
  const rootFd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const rootStat = fstatSync(rootFd, { bigint: true });
    requireIt(identical(rootStat, rootBefore), "trusted root changed during open");
    const pinnedRoot = "/proc/self/fd/" + rootFd;
    requireIt(JSON.stringify(readdirSync(pinnedRoot).sort()) === JSON.stringify([...TRUST_FILES].sort()),
      "trust root missing or contains foreign files");
    const output = {};
    for (const filename of TRUST_FILES) {
      const full = path.join(pinnedRoot, filename);
      const fd = openSync(full, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const before = fstatSync(fd, { bigint: true });
        const pathStat = lstatSync(full, { bigint: true });
        requireIt(before.isFile() && before.uid === 0n && before.nlink === 1n &&
          (before.mode & 0o7777n) === 0o600n && before.size > 0n &&
          before.size <= 1024n * 1024n && before.dev === pathStat.dev && before.ino === pathStat.ino &&
          !pathStat.isSymbolicLink(), "untrusted protected file: " + filename);
        const bytes = readFileSync(fd);
        requireIt(bytes.length === Number(before.size) &&
          identical(before, fstatSync(fd, { bigint: true })) &&
          identical(before, lstatSync(full, { bigint: true })),
        "trusted file changed while reading: " + filename);
        output[filename] = bytes;
      } finally { closeSync(fd); }
    }
    requireIt(identical(rootStat, fstatSync(rootFd, { bigint: true })) &&
      identical(rootStat, lstatSync(dir, { bigint: true })),
    "trusted directory changed during read");
    return output;
  } finally { closeSync(rootFd); }
}
function recheckSignedCi(candidateDirectory, expected) {
  const filename = path.join(candidateDirectory, "ci-report.json");
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    requireIt(before.isFile() && before.nlink === 1n && before.uid === BigInt(process.getuid()) &&
      (before.mode & 0o7777n) === 0o600n &&
      before.size > 0n && before.size <= 65536n, "unsafe local CI report inode");
    const bytes = readFileSync(fd);
    requireIt(bytes.length === Number(before.size) &&
      identical(before, fstatSync(fd, { bigint: true })) &&
      identical(before, lstatSync(filename, { bigint: true })) &&
      sha256(bytes) === expected.ciReportSha256,
    "signed CI bytes changed during structural validation");
    return validateOfflineCiEvidence(bytes, expected.sourceSha, "main");
  } finally { closeSync(fd); }
}

function readOperatorPolicy(raw, pinnedKnownHosts) {
  const p = parseStrict(raw, POLICY_FIELDS, "offline transport policy");
  requireIt(p.version === 1 && p.mode === "offline-signed-v1" && p.enabled === true &&
    SHA.test(p.expectedRevision) && HASH.test(p.knownHostsSha256) &&
    p.knownHostsSha256 === sha256(pinnedKnownHosts) &&
    [p.runtimeExpandedBytes, p.migratorExpandedBytes, p.databaseBytes].every(
      (n) => Number.isSafeInteger(n) && n > 0 && n <= MAX_CAPACITY),
  "operator has not independently accepted this SHA/SSH fingerprint/capacity budget");
  const config = { sshAlias: p.sshAlias, host: p.host, port: p.port, root: p.root };
  requireIt(isValidProductionConfig(config), "invalid pinned SSH endpoint");
  const hostLine = Number(p.port) === 22 ? p.host : "[" + p.host + "]:" + p.port;
  const known = new TextDecoder("utf-8", { fatal: true }).decode(pinnedKnownHosts);
  const lines = known.trimEnd().split("\n");
  const parts = lines[0]?.split(" ");
  requireIt(lines.length === 1 && parts.length === 3 &&
    parts[0] === hostLine && parts[1] === "ssh-ed25519" &&
    /^[A-Za-z0-9+/]+={0,2}$/u.test(parts[2]),
  "owner pinned SSH known_hosts must contain precisely the target Ed25519 key");
  return { policy: p, config };
}

// Checks effective OpenSSH settings. Actual peer identity is authenticated by
// a separate pinned known_hosts supplied to the real ssh process below.
export function validateOfflineSshConfiguration(output, config) {
  requireIt(typeof output === "string" && output.length > 0 &&
    output.length < 128 * 1024 && isValidProductionConfig(config),
  "SSH configuration output missing or expected endpoint unsafe");
  const map = new Map();
  for (const line of output.split(/\r?\n/u)) {
    const match = /^(hostname|port|user|stricthostkeychecking|proxycommand|proxyjump)\s+(.+)$/iu.exec(line.trim());
    if (match) {
      const field = match[1].toLowerCase();
      requireIt(!map.has(field), "duplicate SSH config field");
      map.set(field, match[2].trim());
    }
  }
  requireIt(map.get("hostname")?.toLowerCase() === config.host.toLowerCase() &&
    map.get("port") === String(config.port) &&
    /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/u.test(map.get("user") ?? "") &&
    map.get("stricthostkeychecking") === "yes" &&
    map.get("proxycommand") === "none" && map.get("proxyjump") === "none",
  "SSH resolved peer differs from pinned host or does not strictly check keys");
  return Object.freeze({ hostname: map.get("hostname"), port: map.get("port"), user: map.get("user") });
}

const IDENTITY_SCRIPT = [
  "set -euo pipefail",
  "idfile=/etc/machine-id",
  '[[ -f "$idfile" && ! -L "$idfile" && "$(stat -c %u -- "$idfile")" == 0 ]] || exit 1',
  'id=$(cat "$idfile")',
  '[[ "$id" =~ ^[a-f0-9]{32}$ && ! "$id" =~ ^0+$ ]] || exit 1',
  'hash=$(printf "VIRKI_OFFLINE_HOST_MACHINE_ID_V1\\\\0%s" "$id" | sha256sum | cut -d " " -f1)',
  'printf "VIRKI_OFFLINE_HOST_ID_SHA256=%s\\n" "$hash"',
  "",
].join("\n");

function approvedSshExecutor(trustedDirectory, config) {
  const binary = lstatSync(SSH_PATH);
  requireIt(binary.isFile() && binary.uid === 0 && (binary.mode & 0o022) === 0,
    "root-owned protected OpenSSH executable unavailable");
  const options = [
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=" + path.join(trustedDirectory, "ssh-known-hosts"),
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", "UpdateHostKeys=no", "-o", "ProxyCommand=none",
    "-o", "ProxyJump=none", "-o", "ControlMaster=no",
    "-o", "ControlPath=none", "-o", "BatchMode=yes",
  ];
  return (command, args, extras = {}) => {
    requireIt(command === "ssh" && Array.isArray(args) &&
      (args[0] === "-G" || args.includes(config.sshAlias)),
    "remote command outside approved SSH host");
    const result = spawnSync(SSH_PATH, [...options, ...args], {
      input: extras.input, encoding: "utf8", timeout: 25_000, maxBuffer: 1024 * 1024,
      shell: false,
      stdio: extras.input === undefined ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"],
    });
    return {
      status: result.error ? 1 : (Number.isInteger(result.status) ? result.status : 1),
      stdout: result.error ? "" : (result.stdout ?? ""),
      stderr: "",
    };
  };
}

/**
 * Inspects an owner-signed candidate BEFORE transfer, with a distinct
 * locally root-provisioned policy/ledger and pinned SSH host public key.
 * Inputs are only paths, never caller-provided identities, key bytes or
 * preflight success claims. A result NEVER authorizes transfer or deploy.
 */
export async function prepareVerifiedOfflineTransportPlan(inputs = {}) {
  exact(inputs, ["candidateDirectory", "trustedDirectory", "repositoryRoot"],
    "only three paths are permitted; no caller trust/evidence overrides");
  const { candidateDirectory, trustedDirectory, repositoryRoot } = inputs;
  safeAbsolute(candidateDirectory, "candidate");
  safeAbsolute(trustedDirectory, "operator trust");
  safeAbsolute(repositoryRoot, "canonical Git repository");
  requireIt(disjoint(candidateDirectory, trustedDirectory) &&
    disjoint(repositoryRoot, trustedDirectory), "trusted files cannot reside in Git tree or bundle");

  // All validation is read-only. Reject absent owner trust BEFORE any SSH.
  const candidate = await inspectUntrustedOfflineCandidate({ candidateDirectory });
  const trusted = readProtectedInputs(trustedDirectory);
  const { policy, config } = readOperatorPolicy(trusted["transport-policy.json"], trusted["ssh-known-hosts"]);
  requireIt(candidate.expected.sourceSha === policy.expectedRevision,
    "signed release differs from independently accepted operator SHA");
  const trust = prepareOfflineTrustedReleasePolicy({
    policyBytes: trusted["trust-policy.json"], ledgerBytes: trusted["ledger.json"],
    measuredHostIdentitySha256: candidate.expected.hostIdentitySha256,
  });
  const proof = verifyOfflineReleaseAttestation({
    manifestBytes: candidate.manifestBytes, signatures: candidate.signatures,
    trustedKeys: trust.trustedKeys,
    expected: { ...candidate.expected, hostIdentitySha256: trust.hostIdentitySha256,
      predecessorSha: trust.predecessorSha, lastSequence: trust.lastSequence },
  });
  requireIt(proof.sourceSha === policy.expectedRevision, "owner approval does not bind exact accepted source SHA");
  const ci = recheckSignedCi(candidateDirectory, candidate.expected);
  requireIt(ci.ok && ci.stageCount === 19, "local CI evidence does not have all 19 claimed stages");
  const source = inspectOfflineProductionSource({ repositoryRoot, expectedRevision: proof.sourceSha });
  requireIt(source.branch === "main" && source.revision === proof.sourceSha,
    "main / origin/main does not match signed release");

  const execute = approvedSshExecutor(trustedDirectory, config);
  const resolved = execute("ssh", ["-G", config.sshAlias]);
  requireIt(resolved.status === 0, "pinned SSH target could not be resolved");
  validateOfflineSshConfiguration(resolved.stdout, config);
  const remote = await runProductionPreflight({
    execute, config, mode: "offline",
    offlineArtifacts: {
      sourceArchiveBytes: candidate.expected.sourceArchiveSizeBytes,
      runtimeArchiveBytes: candidate.expected.runtimeImage.archiveSizeBytes,
      migratorArchiveBytes: candidate.expected.migratorImage.archiveSizeBytes,
      runtimeExpandedBytes: policy.runtimeExpandedBytes,
      migratorExpandedBytes: policy.migratorExpandedBytes,
      databaseBytes: policy.databaseBytes,
    },
  });
  requireIt(remote.status === 0 && remote.platform === "linux/amd64" &&
    remote.capacity?.ok === true,
  "eight native Linux probes or remote disk budget failed");
  const identity = execute("ssh", [...SSH_OPTIONS, config.sshAlias, "bash -s --"], { input: IDENTITY_SCRIPT });
  const match = /^VIRKI_OFFLINE_HOST_ID_SHA256=([a-f0-9]{64})\r?\n?$/u.exec(identity.stdout);
  requireIt(identity.status === 0 && match?.[1] === trust.hostIdentitySha256,
    "SSH target identity differs from the independently pinned signed host");
  const rechecked = await inspectUntrustedOfflineCandidate({ candidateDirectory });
  requireIt(rechecked.manifestDigest === candidate.manifestDigest &&
    JSON.stringify(rechecked.expected) === JSON.stringify(candidate.expected),
  "candidate changed while performing remote read-only checks");
  requireIt(sha256(readProtectedInputs(trustedDirectory)["ssh-known-hosts"]) === policy.knownHostsSha256,
    "protected SSH host public key changed during verification");
  return Object.freeze({
    status: "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED",
    deployAuthorized: false,
    transferAuthorized: false,
    signedManifestSha256: proof.manifestSha256,
    revision: proof.sourceSha,
    host: config.host,
    port: Number(config.port),
    platform: remote.platform,
    limitation: "The 19 local CI stages are claims, not independent runner provenance; source Git blobs at host, scanner execution, remote atomic ledger, protected restore and rollback remain unverified. Transport and deployment blocked.",
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("Offline transport is a read-only library; no transfer or deploy entrypoint.\\n");
  process.exitCode = 2;
}
