import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { open } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { encodeCanonicalOfflineReleaseManifest } from "../../scripts/lib/offline-release-attestation.mjs";
import { verifyOfflineDockerSaveTar } from "../../scripts/lib/offline-docker-tar-verifier.mjs";
import { verifyInstalledOfflineRelease } from "../../scripts/lib/offline-trusted-release-policy.mjs";

// Standalone library/entrypoint foundation. Only an independently installed,
// root-protected copy of this code + dependencies may ever serve as a host
// verifier; NEVER import its implementation from the untrusted release bundle.
// No child-process execution, Docker load, ledger mutation or deployment.
const FILE_NAMES = Object.freeze([
  "manifest.json", "signatures.json", "source.tar", "runtime.tar", "migrator.tar",
  "ci-report.json", "scanner-report.json", "finding-review.json",
  "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json",
]);
const DIGEST_FIELD_TO_FILE = Object.freeze([
  ["ciReportSha256", "ci_report_sha256", "ci-report.json"],
  ["scannerReportSha256", "scanner_report_sha256", "scanner-report.json"],
  ["findingReviewSha256", "finding_review_sha256", "finding-review.json"],
  ["runtimeSmokeSha256", "runtime_smoke_sha256", "runtime-smoke.json"],
  ["migratorSmokeSha256", "migrator_smoke_sha256", "migrator-smoke.json"],
  ["backupRestoreSha256", "backup_restore_sha256", "backup-restore.json"],
]);
const ARCHIVES = Object.freeze([
  ["source.tar", 8 * 1024 * 1024 * 1024],
  ["runtime.tar", 8 * 1024 * 1024 * 1024],
  ["migrator.tar", 8 * 1024 * 1024 * 1024],
]);
const SMALL_LIMIT = 4 * 1024 * 1024;
const READ_BLOCK = 64 * 1024;
const DIGEST = /^[0-9a-f]{64}$/u;
const GIT_SHA = /^[0-9a-f]{40}$/u;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const OPEN_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;

function deny(reason) {
  throw new Error("Offline trusted host entry refused: " + reason);
}
function requireIt(ok, reason) {
  if (!ok) deny(reason);
}
function exact(value, fields, reason) {
  requireIt(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((name) => Object.hasOwn(value, name)), reason);
}
function sameMeta(a, b) {
  return ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function ensureRoot(directory) {
  requireIt(typeof directory === "string" && path.isAbsolute(directory) &&
    path.normalize(directory) === directory &&
    directory !== path.parse(directory).root && directory.length <= 4096,
  "candidate path must be absolute and canonical");
  requireIt(realpathSync.native(directory) === directory, "candidate or ancestor is a symbolic alias");
  const stat = lstatSync(directory, { bigint: true });
  requireIt(stat.isDirectory() && stat.uid === BigInt(process.getuid?.() ?? -1) &&
    (stat.mode & 0o7777n) === 0o700n,
  "candidate directory must be a private owner-only real directory");
  return stat;
}
async function inspectRegularFile(directory, name, maxSize, collect = false) {
  const pathname = path.join(directory, name);
  const before = lstatSync(pathname, { bigint: true });
  requireIt(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
    before.uid === BigInt(process.getuid?.() ?? -1) &&
    (before.mode & 0o7777n) === 0o600n &&
    before.size > 0n && before.size <= BigInt(maxSize),
  "unsafe candidate file or file size: " + name);
  const handle = await open(pathname, OPEN_FLAGS);
  try {
    const opened = await handle.stat({ bigint: true });
    requireIt(sameMeta(before, opened), "candidate changed while opening: " + name);
    const hasher = createHash("sha256");
    const chunks = [];
    const block = Buffer.allocUnsafe(READ_BLOCK);
    let cursor = 0;
    while (cursor < Number(before.size)) {
      const step = Math.min(block.length, Number(before.size) - cursor);
      const result = await handle.read(block, 0, step, cursor);
      requireIt(result.bytesRead > 0 && result.bytesRead <= step, "candidate read interrupted: " + name);
      const part = block.subarray(0, result.bytesRead);
      hasher.update(part);
      if (collect) chunks.push(Buffer.from(part));
      cursor += result.bytesRead;
    }
    requireIt(sameMeta(opened, await handle.stat({ bigint: true })) &&
      sameMeta(opened, lstatSync(pathname, { bigint: true })),
    "candidate was replaced during read: " + name);
    return Object.freeze({
      sha256: hasher.digest("hex"),
      sizeBytes: cursor,
      ...(collect ? { bytes: Buffer.concat(chunks) } : {}),
    });
  } finally {
    await handle.close();
  }
}
function parseCanonicalSignatures(bytes) {
  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    deny("invalid signature envelope JSON");
  }
  exact(payload, ["builder", "owner"], "signature envelope fields invalid");
  requireIt(SIGNATURE.test(payload.builder) && SIGNATURE.test(payload.owner),
    "signature envelope encoding invalid");
  requireIt(Buffer.from(JSON.stringify({ builder: payload.builder, owner: payload.owner })).equals(bytes),
    "signature envelope is not canonical");
  return Object.freeze({ builder: payload.builder, owner: payload.owner });
}
function parseManifest(bytes) {
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    requireIt(encodeCanonicalOfflineReleaseManifest(value).equals(bytes),
      "source manifest is not exactly canonical");
  } catch {
    deny("manifest is absent, malformed, noncanonical or unsupported");
  }
  return value;
}

/**
 * Hashes an UNTRUSTED staging candidate and checks only its internal
 * consistency, with O_NOFOLLOW, ownership and inode replay checks.
 * This never validates signatures/pins or authorizes a release.
 */
export async function inspectUntrustedOfflineCandidate(request = {}) {
  requireIt(process.platform === "linux" && typeof process.getuid === "function" &&
    constants.O_NOFOLLOW && constants.O_NONBLOCK && constants.O_DIRECTORY,
  "Linux no-follow file handling required");
  exact(request, ["candidateDirectory"], "untrusted envelope inspection accepts only candidateDirectory");
  const { candidateDirectory } = request;
  const rootBefore = ensureRoot(candidateDirectory);
  const actual = readdirSync(candidateDirectory).sort();
  const required = [...FILE_NAMES].sort();
  requireIt(actual.length === FILE_NAMES.length &&
    actual.every((name, index) => name === required[index]),
  "candidate contains missing or untrusted extra files");
  const m = await inspectRegularFile(candidateDirectory, "manifest.json", 8192, true);
  const s = await inspectRegularFile(candidateDirectory, "signatures.json", SMALL_LIMIT, true);
  const manifest = parseManifest(m.bytes);
  const signatures = parseCanonicalSignatures(s.bytes);
  const scanned = new Map();
  for (const [name, maxSize] of ARCHIVES) {
    scanned.set(name, await inspectRegularFile(candidateDirectory, name, maxSize));
  }
  for (const [, , name] of DIGEST_FIELD_TO_FILE) {
    scanned.set(name, await inspectRegularFile(candidateDirectory, name, 16 * 1024 * 1024));
  }
  requireIt(sameMeta(rootBefore, ensureRoot(candidateDirectory)),
    "candidate root changed during scanning");
  const source = scanned.get("source.tar");
  const runtime = scanned.get("runtime.tar");
  const migrator = scanned.get("migrator.tar");
  requireIt(manifest.source_archive_sha256 === source.sha256 &&
    manifest.source_archive_size_bytes === source.sizeBytes &&
    manifest.runtime_image.archive_sha256 === runtime.sha256 &&
    manifest.runtime_image.archive_size_bytes === runtime.sizeBytes &&
    manifest.migrator_image.archive_sha256 === migrator.sha256 &&
    manifest.migrator_image.archive_size_bytes === migrator.sizeBytes,
  "candidate archive hashes do not match signed-manifest claims");
  const evidence = {};
  for (const [expectedKey, manifestKey, file] of DIGEST_FIELD_TO_FILE) {
    const digest = scanned.get(file).sha256;
    requireIt(manifest.evidence[manifestKey] === digest, "raw evidence differs from manifest: " + file);
    evidence[expectedKey] = digest;
  }
  const expected = Object.freeze({
    sourceSha: manifest.source_sha,
    sourceArchiveSha256: source.sha256,
    sourceArchiveSizeBytes: source.sizeBytes,
    platform: "linux/amd64",
    hostIdentitySha256: manifest.host_identity_sha256,
    predecessorSha: manifest.predecessor_sha,
    runtimeImage: { archiveSha256: runtime.sha256, archiveSizeBytes: runtime.sizeBytes, imageId: manifest.runtime_image.image_id },
    migratorImage: { archiveSha256: migrator.sha256, archiveSizeBytes: migrator.sizeBytes, imageId: manifest.migrator_image.image_id },
    ...evidence,
    scannerRulesCommit: manifest.evidence.scanner_rules_commit,
    lastSequence: manifest.sequence - 1,
  });
  requireIt(GIT_SHA.test(expected.sourceSha) && DIGEST.test(expected.hostIdentitySha256) &&
    Number.isSafeInteger(expected.lastSequence) && expected.lastSequence >= 0,
  "candidate expected identity malformed");
  return Object.freeze({
    status: "UNTRUSTED_ENVELOPE_ONLY",
    manifestBytes: Buffer.from(m.bytes),
    signatures,
    manifestDigest: m.sha256,
    expected,
    archivePaths: Object.freeze({
      source: path.join(candidateDirectory, "source.tar"),
      runtime: path.join(candidateDirectory, "runtime.tar"),
      migrator: path.join(candidateDirectory, "migrator.tar"),
    }),
  });
}

function requireNative() {
  requireIt(process.platform === "linux" && process.arch === "x64" &&
    typeof process.getuid === "function" && process.getuid() === 0 &&
    !/microsoft|wsl/iu.test(os.release()),
  "native Linux/amd64 root verifier required; WSL/Microsoft kernels forbidden");
}
function measuredMachineIdDigest() {
  // The host identity is measured from a Linux system file, not submitted by
  // the uploader. Policy provisioning must pin this exact domain-separated
  // identity independently. Machine-id may be cloned; this is not a TPM proof.
  const filename = "/etc/machine-id";
  requireIt(realpathSync.native(filename) === filename, "machine-id must not be a symlink");
  const before = lstatSync(filename, { bigint: true });
  requireIt(before.isFile() && before.uid === 0n &&
    (before.mode & 0o022n) === 0n && before.size <= 128n && before.size >= 32n,
  "unsafe root-owned machine-id metadata");
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let raw;
  try {
    const opened = fstatSync(fd, { bigint: true });
    requireIt(sameMeta(before, opened), "machine-id replaced during open");
    raw = readFileSync(fd);
    requireIt(sameMeta(opened, fstatSync(fd, { bigint: true })) &&
      sameMeta(opened, lstatSync(filename, { bigint: true })),
    "machine-id changed during inspection");
  } finally {
    closeSync(fd);
  }
  const normalized = raw.toString("utf8").trim();
  requireIt(/^[a-f0-9]{32}$/u.test(normalized) && !/^0+$/u.test(normalized),
    "invalid machine-id identity");
  return createHash("sha256").update("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0" + normalized).digest("hex");
}

/**
 * READ-ONLY installed native entrypoint. No caller-supplied trust pins,
 * expected digests, host SHA, ledger state or signing keys are consulted.
 * The installed verifier reads fixed trust roots itself and checks two
 * owner/builder signatures before Docker TAR parsing.
 *
 * Returns a NON-AUTHORIZING inspection only. Source tar blob-vs-Git validation,
 * independent CI/scanner report semantics, exclusive ledger acceptance and
 * preflight/rollback controls are OUTSIDE this function; release stays blocked.
 */
export async function verifyTrustedHostOfflineCandidate(request = {}) {
  requireNative();
  exact(request, ["candidateDirectory"], "entrypoint accepts only candidateDirectory; caller trust claims forbidden");
  const { candidateDirectory } = request;
  const candidate = await inspectUntrustedOfflineCandidate({ candidateDirectory });
  const hostIdentity = measuredMachineIdDigest();
  const signed = verifyInstalledOfflineRelease({
    manifestBytes: candidate.manifestBytes,
    signatures: candidate.signatures,
    measuredHostIdentitySha256: hostIdentity,
    expected: { ...candidate.expected, hostIdentitySha256: hostIdentity },
  });
  const { expected, archivePaths } = candidate;
  const imageChecks = await Promise.all(["runtime", "migrator"].map((role) => {
    const image = role === "runtime" ? expected.runtimeImage : expected.migratorImage;
    return verifyOfflineDockerSaveTar({
      role,
      archivePath: archivePaths[role],
      expectedImageId: image.imageId,
      expectedRevision: signed.sourceSha,
      expectedArchiveSha256: image.archiveSha256,
      expectedArchiveSizeBytes: image.archiveSizeBytes,
    });
  }));
  return Object.freeze({
    status: "INSPECTED_ONLY_RELEASE_BLOCKED",
    deployAuthorized: false,
    sourceSha: signed.sourceSha,
    verifiedManifestSha256: signed.verifiedManifestSha256,
    checkedImageRoles: Object.freeze(imageChecks.map((entry) => entry.role)),
    limitations: Object.freeze([
      "No authenticated Git blob/content validation of source tar in this entrypoint",
      "No independent proof of local CI/scanner/finding review execution",
      "No exclusive persistent ledger acceptance, deployment preflight or rollback",
      "No Docker load, execution, deployment or production mutation is allowed",
    ]),
  });
}

// A direct invocation must never exit 0 as a release/deployment signal.
// This only performs preflight inspection; the operator's independent,
// audited acceptance/ledger/deployment path is NOT implemented here.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireIt(process.argv.length === 3, "one absolute candidate path argument required");
    const result = await verifyTrustedHostOfflineCandidate({ candidateDirectory: process.argv[2] });
    process.stderr.write("Offline trust preflight " + result.status + "; deploy remains BLOCKED.\n");
    process.exitCode = 2;
  } catch {
    process.stderr.write("Offline trust preflight refused; no deployment allowed.\n");
    process.exitCode = 1;
  }
}
