import { createHash } from "node:crypto";
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  readdirSync, realpathSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { prepareOfflineTrustedReleasePolicy } from "../../scripts/lib/offline-trusted-release-policy.mjs";

// An executable installed verifier is itself a security principal. Until its
// audited bytes, independent operator authorization and native root installer
// can be verified together, ONLY a read-only preflight may be exposed here.
// Uploaded release TARs never provide source code, public-key pins or policy.
export const AUDITED_VERIFIER_FILES = Object.freeze([
  "infra/offline/trusted-host-entry.mjs",
  "infra/offline/trusted-host-installer.mjs",
  "infra/offline/trusted-image-loader.mjs",
  "infra/offline/trusted-source-git.mjs",
  "scripts/lib/offline-docker-tar-verifier.mjs",
  "scripts/lib/offline-release-attestation.mjs",
  "scripts/lib/offline-source-tar-verifier.mjs",
  "scripts/lib/offline-trusted-release-policy.mjs",
]);

const OPERATOR_FILES = Object.freeze([
  "ledger.json", "trust-policy.json", "verifier-pins.json",
]);
const POLICY_DIRECTORY = "/etc/virki/offline-release";
const LEDGER_DIRECTORY = "/var/lib/virki/offline-release";
const UNTRUSTED_STAGING_ROOTS = Object.freeze([
  LEDGER_DIRECTORY + "/staging",
  "/var/lib/virki/offline-staging",
]);
const VERIFIER_DIRECTORY = "/usr/local/lib/virki/offline-release";
const PIN_FIELDS = ["version", "mode", "files", "trustPolicySha256", "ledgerSha256"];
const FILE_FIELDS = ["path", "sha256"];
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_CODE_BYTES = 2 * 1024 * 1024;
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const DIRECTORY_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY;

function refuse(reason) {
  throw new Error("Trusted host verifier provisioning refused: " + reason);
}
function requireIt(condition, reason) {
  if (!condition) refuse(reason);
}
function exact(value, names, label) {
  requireIt(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === names.length &&
    names.every((key, index) => Object.keys(value)[index] === key),
  label + " schema is missing, reordered or contains extra fields");
}
function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function identical(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
function parseCanonical(bytes, label, maxSize = MAX_JSON_BYTES) {
  requireIt(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= maxSize,
    label + " requires bounded nonempty bytes");
  let parsed;
  let raw;
  try {
    raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(raw);
  } catch {
    refuse(label + " is malformed UTF-8 JSON");
  }
  requireIt(JSON.stringify(parsed) === raw, label + " must be canonical JSON");
  return parsed;
}
function validatePinInventory(pins) {
  exact(pins, PIN_FIELDS, "independent verifier pins");
  requireIt(pins.version === 1 && pins.mode === "independent-native-verifier-pins-v1" &&
    SHA256.test(pins.trustPolicySha256) && SHA256.test(pins.ledgerSha256) &&
    Array.isArray(pins.files) && pins.files.length === AUDITED_VERIFIER_FILES.length,
  "independent audited inventory/version/digests invalid");
  const files = pins.files.map((file, index) => {
    exact(file, FILE_FIELDS, "audited source file");
    requireIt(file.path === AUDITED_VERIFIER_FILES[index] &&
      typeof file.sha256 === "string" && SHA256.test(file.sha256),
    "audited verifier dependency missing, unexpected or reordered");
    return Object.freeze({ path: file.path, sha256: file.sha256 });
  });
  return Object.freeze(files);
}

/**
 * Pure parser for independently provided operator audit material. It validates
 * the same protected policy v2 and ledger semantics as the host verifier, but
 * caller-provided bytes CANNOT prove the operator independently accepted them.
 * Thus neither this result nor this module can authorize installation.
 */
export function prepareTrustedVerifierPinSet({
  pinsBytes, policyBytes, ledgerBytes, measuredHostIdentitySha256,
} = {}) {
  const pins = parseCanonical(pinsBytes, "operator verifier pins", 16384);
  const files = validatePinInventory(pins);
  requireIt(Buffer.isBuffer(policyBytes) && sha256(policyBytes) === pins.trustPolicySha256 &&
    Buffer.isBuffer(ledgerBytes) && sha256(ledgerBytes) === pins.ledgerSha256,
  "protected policy or ledger differs from independently audited byte hashes");
  const trust = prepareOfflineTrustedReleasePolicy({
    policyBytes, ledgerBytes, measuredHostIdentitySha256,
  });
  return Object.freeze({
    status: "INDEPENDENT_PINS_PARSED_ONLY",
    files,
    hostIdentitySha256: trust.hostIdentitySha256,
    ledgerHeadSha: trust.predecessorSha,
    ledgerSequence: trust.lastSequence,
    operatorPinsSha256: sha256(pinsBytes),
  });
}

function canonicalAbsolute(dirname, label) {
  requireIt(typeof dirname === "string" && dirname.length > 1 &&
    dirname.length <= 4096 && path.isAbsolute(dirname) &&
    path.normalize(dirname) === dirname && dirname !== path.parse(dirname).root &&
    !dirname.includes("\0"), label + " requires an absolute canonical directory");
  let current = dirname;
  while (true) {
    const stat = lstatSync(current);
    requireIt(stat.isDirectory() && !stat.isSymbolicLink(),
      label + " contains a symlinked or non-directory ancestor");
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  requireIt(realpathSync.native(dirname) === dirname,
    label + " points through a filesystem alias");
  return dirname;
}

// Called only after native canonical-path checks by the privileged preview.
// Kept pure so both former and current candidate staging roots are covered
// by regression tests without attempting any root-owned host provisioning.
export function assertIndependentVerifierRoots({ sourceDirectory, operatorDirectory } = {}) {
  requireIt(typeof sourceDirectory === "string" && typeof operatorDirectory === "string" &&
    UNTRUSTED_STAGING_ROOTS.every((root) =>
      [sourceDirectory, operatorDirectory].every((candidate) =>
        candidate !== root && !candidate.startsWith(root + "/"))),
  "untrusted staging cannot supply verifier or trusted operator pins");
}
function ensureFileParents(sourceDirectory, relativePath) {
  const segments = relativePath.split("/");
  let current = sourceDirectory;
  for (const part of segments.slice(0, -1)) {
    current = path.join(current, part);
    const stat = lstatSync(current);
    requireIt(stat.isDirectory() && !stat.isSymbolicLink(),
      "audited source traverses a symlink or a non-directory");
  }
  return path.join(current, segments.at(-1));
}
function readPinnedRegular(filename, limit, { ownerRoot = false, mode0600 = false } = {}) {
  const before = lstatSync(filename, { bigint: true });
  requireIt(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
    before.size > 0n && before.size <= BigInt(limit),
  "audited file is missing, nonregular, linked or oversized");
  if (ownerRoot) {
    requireIt(before.uid === 0n && (before.mode & 0o7777n) === 0o600n,
      "trusted operator file must be root-owned 0600");
  } else if (mode0600) {
    requireIt((before.mode & 0o7777n) === 0o600n,
      "verifier source must be private 0600 before native staging");
  }
  const fd = openSync(filename, READ_FLAGS);
  try {
    const opened = fstatSync(fd, { bigint: true });
    requireIt(identical(before, opened), "audited file replaced during opening");
    const bytes = readFileSync(fd);
    requireIt(bytes.length === Number(before.size) &&
      identical(opened, fstatSync(fd, { bigint: true })) &&
      identical(opened, lstatSync(filename, { bigint: true })),
    "audited file was modified or replaced during inspection");
    return bytes;
  } finally {
    closeSync(fd);
  }
}

/**
 * Portable, read-only source inspector. A caller-supplied pin set is not
 * inherently trusted; the privileged preview obtains pins from independently
 * protected, root-owned operator files outside the candidate source.
 */
export function inspectAuditedVerifierFiles({ sourceDirectory, files } = {}) {
  canonicalAbsolute(sourceDirectory, "verifier source");
  requireIt(Array.isArray(files), "audited pin inventory is absent");
  const verified = validatePinInventory({
    version: 1, mode: "independent-native-verifier-pins-v1",
    files, trustPolicySha256: "0".repeat(64), ledgerSha256: "0".repeat(64),
  });
  const measured = [];
  for (const entry of verified) {
    const filename = ensureFileParents(sourceDirectory, entry.path);
    const bytes = readPinnedRegular(filename, MAX_CODE_BYTES);
    requireIt(sha256(bytes) === entry.sha256, "audited verifier SHA-256 mismatch: " + entry.path);
    measured.push(Object.freeze({ path: entry.path, sha256: entry.sha256 }));
  }
  return Object.freeze({
    status: "AUDITED_SOURCE_BYTES_MATCH_ONLY",
    files: Object.freeze(measured),
  });
}

function nativeRootOnly() {
  requireIt(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && !/microsoft|wsl/iu.test(os.release()) &&
    constants.O_NOFOLLOW && constants.O_DIRECTORY && constants.O_NONBLOCK,
  "native Linux/amd64 root required; Windows and WSL cannot bootstrap trust");
}
function readProtectedOperatorDirectory(dirname) {
  canonicalAbsolute(dirname, "independently supplied operator pins");
  const parentStat = lstatSync(dirname, { bigint: true });
  requireIt(parentStat.uid === 0n && parentStat.isDirectory() &&
    (parentStat.mode & 0o7777n) === 0o700n,
  "operator pin directory must be root-owned 0700");
  const fd = openSync(dirname, DIRECTORY_FLAGS);
  try {
    const opened = fstatSync(fd, { bigint: true });
    requireIt(identical(parentStat, opened), "operator directory changed during opening");
    const pinnedDirectory = "/proc/self/fd/" + fd;
    requireIt(JSON.stringify(readdirSync(pinnedDirectory).sort()) ===
      JSON.stringify([...OPERATOR_FILES].sort()),
    "operator directory must contain exactly the three independent pin/policy/ledger files");
    const output = {};
    for (const name of OPERATOR_FILES) {
      output[name] = readPinnedRegular(path.join(pinnedDirectory, name), MAX_JSON_BYTES, {
        ownerRoot: true,
      });
    }
    requireIt(identical(opened, fstatSync(fd, { bigint: true })) &&
      identical(opened, lstatSync(dirname, { bigint: true })),
    "operator directory changed during reading");
    return output;
  } finally {
    closeSync(fd);
  }
}
function measuredNativeHostIdentity() {
  const filename = "/etc/machine-id";
  requireIt(realpathSync.native(filename) === filename,
    "host machine-id must be a real root-owned file");
  const before = lstatSync(filename, { bigint: true });
  requireIt(before.isFile() && !before.isSymbolicLink() &&
    before.uid === 0n && (before.mode & 0o022n) === 0n &&
    before.nlink === 1n && before.size >= 32n && before.size <= 128n,
  "native machine-id has unsafe owner, mode or size");
  const bytes = readPinnedRegular(filename, 128);
  const identity = bytes.toString("utf8").trim();
  requireIt(/^[a-f0-9]{32}$/u.test(identity) && !/^0+$/u.test(identity),
    "native host identity malformed");
  return sha256("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0" + identity);
}

/**
 * Native-root read-only provisioning preview. Operator directory MUST be
 * independently provisioned outside the release/source tree and protected
 * before invoking this function. The preview deliberately has no install,
 * activation, ledger-mutation, shell, SSH, or Docker execution capability.
 *
 * Missing proof for a privileged install: an independently authenticated
 * operator approval for THIS verifier/policy revision and an audited native
 * installer whose root-only O_NOFOLLOW/O_EXCL temp files, fsync(file), atomic
 * rename and fsync(directory) behavior have been validated on the real host.
 */
export function previewTrustedHostVerifierProvisioning(request = {}) {
  nativeRootOnly();
  exact(request, ["sourceDirectory", "operatorDirectory"], "provisioning request");
  const { sourceDirectory, operatorDirectory } = request;
  canonicalAbsolute(sourceDirectory, "verifier source");
  canonicalAbsolute(operatorDirectory, "independent operator");
  requireIt(sourceDirectory !== operatorDirectory &&
    !sourceDirectory.startsWith(operatorDirectory + path.sep) &&
    !operatorDirectory.startsWith(sourceDirectory + path.sep),
  "source and operator trust roots must be disjoint");
  assertIndependentVerifierRoots({ sourceDirectory, operatorDirectory });
  const operator = readProtectedOperatorDirectory(operatorDirectory);
  const trustedPins = prepareTrustedVerifierPinSet({
    pinsBytes: operator["verifier-pins.json"],
    policyBytes: operator["trust-policy.json"],
    ledgerBytes: operator["ledger.json"],
    measuredHostIdentitySha256: measuredNativeHostIdentity(),
  });
  const audited = inspectAuditedVerifierFiles({
    sourceDirectory, files: trustedPins.files,
  });
  return Object.freeze({
    status: "NATIVE_VERIFIER_PREVIEW_ONLY_INSTALL_BLOCKED",
    auditedSourceCount: audited.files.length,
    inspectedPinsSha256: trustedPins.operatorPinsSha256,
    destinations: Object.freeze({
      trustPolicy: POLICY_DIRECTORY + "/trust-policy.json",
      ledger: LEDGER_DIRECTORY + "/ledger.json",
      verifierRoot: VERIFIER_DIRECTORY,
    }),
    requiredDirectoryMode: "root:root 0700",
    requiredFileMode: "root:root 0600",
    missingForInstallation: Object.freeze([
      "Independent authenticated approval of the exact audited verifier, policy and ledger bytes",
      "Audited root-only native installer with O_NOFOLLOW/O_EXCL, same-filesystem atomic rename and fsync of files and parent directories",
      "Verified root-owned, non-writable interpreter and installed verifier dependency closure remeasured at execution",
      "Atomic protected ledger acceptance, full release provenance and rollback controls",
    ]),
  });
}

// The module has no privileged installation entrypoint. CLI always refuses,
// including when an attacker supplies --install or fake operator approval.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("Trusted host verifier installation blocked; read-only library only.\n");
  process.exitCode = 2;
}
