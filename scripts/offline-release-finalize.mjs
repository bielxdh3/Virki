import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readSync, readdirSync, realpathSync, renameSync, rmdirSync,
  unlinkSync, writeSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { encodeCanonicalOfflineReleaseManifest, verifyOfflineReleaseAttestation } from "./lib/offline-release-attestation.mjs";

// Manual packaging only. The two signatures must exist BEFORE invocation.
// Trusted public-key pins, reviewed digest and expected release identity are
// independent operator inputs and must NEVER be read from unsignedDirectory.
// No private keys, sign(), Git, Docker, network or production services here.
const UNSIGNED_FILES = Object.freeze([
  "manifest.json", "source.tar", "runtime.tar", "migrator.tar",
  "ci-report.json", "scanner-report.json", "finding-review.json",
  "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json",
]);
const SIGNED_FILES = Object.freeze([...UNSIGNED_FILES, "signatures.json"]);
const REPORT_MAP = Object.freeze([
  ["source.tar", "source_archive_sha256", "source_archive_size_bytes"],
  ["runtime.tar", "runtime_image.archive_sha256", "runtime_image.archive_size_bytes"],
  ["migrator.tar", "migrator_image.archive_sha256", "migrator_image.archive_size_bytes"],
  ["ci-report.json", "evidence.ci_report_sha256"],
  ["scanner-report.json", "evidence.scanner_report_sha256"],
  ["finding-review.json", "evidence.finding_review_sha256"],
  ["runtime-smoke.json", "evidence.runtime_smoke_sha256"],
  ["migrator-smoke.json", "evidence.migrator_smoke_sha256"],
  ["backup-restore.json", "evidence.backup_restore_sha256"],
]);
const SOURCE_LIMIT = 8 * 1024 * 1024 * 1024;
const REPORT_LIMIT = 16 * 1024 * 1024;
const MANIFEST_LIMIT = 8192;
const READ_BYTES = 64 * 1024;
const HASH = /^[0-9a-f]{64}$/u;
const KEY_ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/u;
const B64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const WRITE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const EXPECTED_FIELDS = Object.freeze([
  "sourceSha", "sourceArchiveSha256", "sourceArchiveSizeBytes", "platform",
  "hostIdentitySha256", "predecessorSha", "runtimeImage", "migratorImage",
  "ciReportSha256", "scannerReportSha256", "scannerRulesCommit", "findingReviewSha256",
  "runtimeSmokeSha256", "migratorSmokeSha256", "backupRestoreSha256", "lastSequence",
]);

function refuse(reason) { throw new Error(`Offline signed package finalization refused: ${reason}`); }
function requireFields(value, fields, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) {
    refuse(`${label} must contain exactly the required fields`);
  }
}
function requireNativeFileSecurity() {
  if (process.platform !== "linux" || typeof process.getuid !== "function" ||
      !Number.isInteger(constants.O_NOFOLLOW) || !Number.isInteger(constants.O_DIRECTORY) ||
      !Number.isInteger(constants.O_NONBLOCK)) {
    refuse("native Linux file ownership and no-follow handling are required");
  }
}
function absoluteCanonical(filename, label) {
  if (typeof filename !== "string" || filename.length === 0 || filename.length > 4096 ||
      filename.includes("\0") || !path.isAbsolute(filename) || filename !== path.normalize(filename) ||
      filename === path.parse(filename).root) refuse(`${label} is not a canonical absolute path`);
  return filename;
}
function directoryIdentity(dirname, label) {
  absoluteCanonical(dirname, label);
  // Check every ancestor rather than relying on O_NOFOLLOW for the final one.
  let part = dirname;
  while (true) {
    const stat = lstatSync(part, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) refuse(`${label} has a symlink or unsafe ancestor`);
    const parent = path.dirname(part);
    if (part === parent) break;
    part = parent;
  }
  if (realpathSync.native(dirname) !== dirname) refuse(`${label} is an aliased directory`);
  const stat = lstatSync(dirname, { bigint: true });
  if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o7777n) !== 0o700n) {
    refuse(`${label} must be an owner-only 0700 directory`);
  }
  return stat;
}
function sameFile(a, b) {
  return ["dev", "ino", "uid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
function sameDirectory(a, b) {
  // Contents alter directory timestamps; inode, device and security bits must stay.
  return ["dev", "ino", "uid", "mode"].every((field) => a[field] === b[field]);
}
function confirmDirectory(dirname, pinned, label) {
  if (!sameDirectory(pinned, directoryIdentity(dirname, label))) refuse(`${label} identity changed`);
}
function confirmNames(dirname, names) {
  const current = readdirSync(dirname).sort();
  const required = [...names].sort();
  if (current.length !== required.length || current.some((name, i) => name !== required[i])) {
    refuse("directory has unexpected, missing or injected files");
  }
}
function requireSafeRegular(stat, label, max) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o7777n) !== 0o600n || stat.nlink !== 1n ||
      stat.size < 1n || stat.size > BigInt(max)) {
    refuse(`${label} must be a private, 0600, single-link regular file`);
  }
}
function maxFor(name) {
  return name === "manifest.json" ? MANIFEST_LIMIT : name.endsWith(".tar") ? SOURCE_LIMIT : REPORT_LIMIT;
}
function readTrustedFile(filename, name) {
  const before = lstatSync(filename, { bigint: true });
  requireSafeRegular(before, name, maxFor(name));
  const fd = openSync(filename, READ_FLAGS);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameFile(before, opened)) refuse(`${name} changed before opening`);
    const digest = createHash("sha256");
    const buf = Buffer.allocUnsafe(READ_BYTES);
    let offset = 0;
    const pieces = [];
    while (offset < Number(before.size)) {
      const n = readSync(fd, buf, 0, Math.min(READ_BYTES, Number(before.size) - offset), offset);
      if (n <= 0) refuse(`${name} has an incomplete read`);
      digest.update(buf.subarray(0, n));
      if (name === "manifest.json") pieces.push(Buffer.from(buf.subarray(0, n)));
      offset += n;
    }
    if (!sameFile(opened, fstatSync(fd, { bigint: true })) ||
        !sameFile(opened, lstatSync(filename, { bigint: true }))) {
      refuse(`${name} changed during reading`);
    }
    return Object.freeze({
      stat: opened, sha256: digest.digest("hex"), sizeBytes: offset,
      ...(name === "manifest.json" ? { bytes: Buffer.concat(pieces) } : {}),
    });
  } finally { closeSync(fd); }
}
function canonicalManifest(raw) {
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    if (!encodeCanonicalOfflineReleaseManifest(parsed).equals(raw)) refuse("manifest is not canonical");
  } catch {
    refuse("manifest is not canonical UTF-8 JSON");
  }
  return parsed;
}
function manifestField(parsed, field) {
  return field.split(".").reduce((value, key) => value?.[key], parsed);
}
function requiredSignatures(signatures) {
  requireFields(signatures, ["builder", "owner"], "external signature pair");
  for (const label of ["builder", "owner"]) {
    const value = signatures[label];
    if (typeof value !== "string" || !B64_SIGNATURE.test(value) ||
        Buffer.from(value, "base64").length !== 64 ||
        Buffer.from(value, "base64").toString("base64") !== value) {
      refuse(`${label} signature is not canonical Ed25519 base64`);
    }
  }
  return Object.freeze({ builder: signatures.builder, owner: signatures.owner });
}
function checkedTrustInputs(keys, expected, digest) {
  requireFields(keys, ["builder", "owner"], "independent public-key trust anchors");
  for (const role of ["builder", "owner"]) {
    // The exact v2 schema is provisioned independently by the owner and
    // installed host policy. Never drop key IDs to satisfy a legacy signer.
    requireFields(keys[role], ["keyId", "publicKeyPem", "pinSha256"], `${role} public key`);
    if (typeof keys[role].keyId !== "string" || !KEY_ID.test(keys[role].keyId)) {
      refuse(`${role} independently pinned key ID is invalid`);
    }
  }
  if (keys.builder.keyId === keys.owner.keyId ||
      keys.builder.pinSha256 === keys.owner.pinSha256) {
    refuse("builder and owner need distinct independently pinned identities");
  }
  requireFields(expected, EXPECTED_FIELDS, "independent release identity");
  if (typeof digest !== "string" || !HASH.test(digest)) refuse("independently reviewed manifest SHA-256 is missing");
  return Object.freeze({
    builder: Object.freeze({ ...keys.builder }),
    owner: Object.freeze({ ...keys.owner }),
  });
}
function copyPinnedFile(source, destination, name, measurement) {
  const before = lstatSync(source, { bigint: true });
  if (!sameFile(before, measurement.stat)) refuse(`${name} was replaced after validation`);
  const from = openSync(source, READ_FLAGS);
  try {
    if (!sameFile(fstatSync(from, { bigint: true }), measurement.stat)) {
      refuse(`${name} changed while reopening`);
    }
    const to = openSync(destination, WRITE_FLAGS, 0o600);
    try {
      const targetStat = fstatSync(to, { bigint: true });
      if (!targetStat.isFile() || targetStat.uid !== BigInt(process.getuid()) ||
          (targetStat.mode & 0o7777n) !== 0o600n || targetStat.nlink !== 1n ||
          targetStat.size !== 0n) refuse(`${name} destination is an unsafe new file`);
      const buffer = Buffer.allocUnsafe(READ_BYTES);
      const digest = createHash("sha256");
      let offset = 0;
      while (offset < measurement.sizeBytes) {
        const received = readSync(from, buffer, 0, Math.min(READ_BYTES, measurement.sizeBytes - offset), offset);
        if (received <= 0) refuse(`${name} changed or was truncated while copying`);
        digest.update(buffer.subarray(0, received));
        let written = 0;
        while (written < received) {
          const n = writeSync(to, buffer, written, received - written, offset + written);
          if (n <= 0) refuse(`${name} could not be copied fully`);
          written += n;
        }
        offset += received;
      }
      if (offset !== measurement.sizeBytes || digest.digest("hex") !== measurement.sha256) {
        refuse(`${name} bytes changed between validation and copy`);
      }
      fsyncSync(to);
      const completed = fstatSync(to, { bigint: true });
      requireSafeRegular(completed, name, maxFor(name));
      if (completed.size !== BigInt(measurement.sizeBytes) ||
          !sameFile(completed, lstatSync(destination, { bigint: true }))) {
        refuse(`${name} staged copy was replaced`);
      }
    } finally { closeSync(to); }
    if (!sameFile(measurement.stat, fstatSync(from, { bigint: true })) ||
        !sameFile(measurement.stat, lstatSync(source, { bigint: true }))) {
      refuse(`${name} source was changed during copy`);
    }
  } finally { closeSync(from); }
}
function writeSignatures(directory, signatures) {
  // Host verifier accepts precisely this JSON order with no trailing newline.
  const bytes = Buffer.from(JSON.stringify({ builder: signatures.builder, owner: signatures.owner }));
  const target = path.join(directory, "signatures.json");
  const fd = openSync(target, WRITE_FLAGS, 0o600);
  try {
    writeSync(fd, bytes, 0, bytes.length, 0);
    fsyncSync(fd);
    const meta = fstatSync(fd, { bigint: true });
    requireSafeRegular(meta, "signatures.json", REPORT_LIMIT);
    if (meta.size !== BigInt(bytes.length) || !sameFile(meta, lstatSync(target, { bigint: true }))) {
      refuse("signature envelope was replaced");
    }
  } finally { closeSync(fd); }
}
function syncDirectory(directory) {
  const fd = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function cleanupOwnPending(directory, identity) {
  if (!sameDirectory(identity, directoryIdentity(directory, "pending package"))) {
    refuse("pending package was replaced; manual cleanup required");
  }
  const names = readdirSync(directory);
  if (names.some((name) => !SIGNED_FILES.includes(name))) {
    refuse("foreign pending file detected; manual cleanup required");
  }
  for (const name of names) {
    const file = path.join(directory, name);
    requireSafeRegular(lstatSync(file, { bigint: true }), name, maxFor(name));
    unlinkSync(file);
  }
  rmdirSync(directory);
}

/**
 * Converts one fully verified 10-file unsigned stage into an independent,
 * private 11-file signed candidate. It checks both externally produced
 * Ed25519 signatures before creating any output, and never signs by itself.
 * `expected`, public-key pins and the reviewed digest MUST be provisioned
 * separately from the candidate bundle by a trusted operator.
 *
 * 0600 protects custody, not cryptographic immutability. A separately installed
 * host verifier must recheck all bytes at use time; deployment is still blocked.
 */
export async function finalizeSignedOfflineRelease({
  unsignedDirectory, outputParent, signatures, trustedKeys, expected,
  reviewedManifestSha256, nowSeconds,
} = {}) {
  requireNativeFileSecurity();
  if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 1) {
    refuse("explicit trusted verification time is required");
  }
  const keys = checkedTrustInputs(trustedKeys, expected, reviewedManifestSha256);
  const checkedSignatures = requiredSignatures(signatures);
  const unsignedStat = directoryIdentity(unsignedDirectory, "unsigned input");
  const parentStat = directoryIdentity(outputParent, "output parent");
  if (outputParent === unsignedDirectory || outputParent.startsWith(`${unsignedDirectory}/`)) {
    refuse("output parent cannot be within unsigned input");
  }
  confirmNames(unsignedDirectory, UNSIGNED_FILES);
  const measured = new Map();
  for (const name of UNSIGNED_FILES) {
    measured.set(name, readTrustedFile(path.join(unsignedDirectory, name), name));
    confirmDirectory(unsignedDirectory, unsignedStat, "unsigned input");
  }
  confirmNames(unsignedDirectory, UNSIGNED_FILES);
  const manifestEntry = measured.get("manifest.json");
  if (manifestEntry.sha256 !== reviewedManifestSha256) refuse("manifest SHA-256 differs from independently reviewed bytes");
  const manifest = canonicalManifest(manifestEntry.bytes);
  for (const [name, digestKey, sizeKey] of REPORT_MAP) {
    const entry = measured.get(name);
    if (entry.sha256 !== manifestField(manifest, digestKey) ||
        (sizeKey && entry.sizeBytes !== manifestField(manifest, sizeKey))) {
      refuse(`${name} SHA-256/size differs from canonical signed manifest`);
    }
  }
  // The domain-separated signature verifier also checks pinned key identity,
  // independent source/host/predecessor/image/report facts, expiry and replay.
  const verification = verifyOfflineReleaseAttestation({
    manifestBytes: manifestEntry.bytes, signatures: checkedSignatures,
    trustedKeys: keys, expected, nowSeconds,
  });
  if (verification.manifestSha256 !== reviewedManifestSha256) refuse("reviewed signed manifest mismatch");

  // An exclusive, private pending directory prevents visible partial releases.
  // Rename publishes only after all eleven files are completed and rechecked.
  confirmDirectory(outputParent, parentStat, "output parent");
  const id = randomBytes(16).toString("hex");
  const pending = path.join(outputParent, `.virki-signed-pending-${id}`);
  const finalDirectory = path.join(outputParent, `virki-signed-${manifest.source_sha.slice(0, 12)}-${id}`);
  if (existsSync(pending) || existsSync(finalDirectory)) refuse("unique candidate directory already exists");
  mkdirSync(pending, { mode: 0o700 });
  const pendingStat = directoryIdentity(pending, "pending package");
  let published = false;
  try {
    for (const name of UNSIGNED_FILES) {
      copyPinnedFile(path.join(unsignedDirectory, name), path.join(pending, name), name, measured.get(name));
      confirmDirectory(pending, pendingStat, "pending package");
      confirmDirectory(unsignedDirectory, unsignedStat, "unsigned input");
    }
    writeSignatures(pending, checkedSignatures);
    confirmNames(pending, SIGNED_FILES);
    confirmNames(unsignedDirectory, UNSIGNED_FILES);
    // Verify copies from the destination inode before the atomic publication.
    for (const name of UNSIGNED_FILES) {
      const copied = readTrustedFile(path.join(pending, name), name);
      if (copied.sha256 !== measured.get(name).sha256 ||
          copied.sizeBytes !== measured.get(name).sizeBytes) {
        refuse(`${name} staged bytes changed after copying`);
      }
      const initial = measured.get(name).stat;
      if (!sameFile(initial, lstatSync(path.join(unsignedDirectory, name), { bigint: true }))) {
        refuse(`${name} original was replaced during finalization`);
      }
    }
    confirmDirectory(pending, pendingStat, "pending package");
    confirmDirectory(unsignedDirectory, unsignedStat, "unsigned input");
    confirmDirectory(outputParent, parentStat, "output parent");
    syncDirectory(pending);
    renameSync(pending, finalDirectory);
    published = true;
    confirmDirectory(finalDirectory, pendingStat, "published candidate");
    confirmNames(finalDirectory, SIGNED_FILES);
    syncDirectory(outputParent);
    return Object.freeze({
      status: "SIGNED_CANDIDATE_ONLY", candidateDirectory: finalDirectory,
      manifestSha256: verification.manifestSha256,
      sourceSha: verification.sourceSha, sequence: verification.sequence,
      limitation: "Operator-supplied independent trust only; native host must verify again. No deployment authorized.",
    });
  } catch (error) {
    if (!published && existsSync(pending)) {
      try { cleanupOwnPending(pending, pendingStat); }
      catch (cleanupError) {
        throw new AggregateError([error, cleanupError],
          "Unsigned output failed and requires manual inspection", { cause: cleanupError });
      }
    }
    throw error;
  }
}

// Explicit operator-only CLI. A trusted request file exists outside the bundle
// and carries public keys and signature strings; no private key is loaded.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireNativeFileSecurity();
    if (process.argv.length !== 4 || process.argv[2] !== "--request") {
      refuse("usage: node scripts/offline-release-finalize.mjs --request <absolute-operator-request.json>");
    }
    const filename = absoluteCanonical(process.argv[3], "operator request");
    directoryIdentity(path.dirname(filename), "operator request parent");
    const stat = lstatSync(filename, { bigint: true });
    requireSafeRegular(stat, "operator request", REPORT_LIMIT);
    readTrustedFile(filename, "operator request");
    const fd = openSync(filename, READ_FLAGS);
    let request;
    try {
      if (!sameFile(stat, fstatSync(fd, { bigint: true }))) refuse("operator request replaced");
      const raw = readFileSync(fd);
      request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
      if (!Buffer.from(JSON.stringify(request)).equals(raw)) {
        refuse("operator request must be canonical JSON without duplicate or ambiguous keys");
      }
      if (!sameFile(stat, fstatSync(fd, { bigint: true })) ||
          !sameFile(stat, lstatSync(filename, { bigint: true }))) refuse("operator request mutated");
    } finally { closeSync(fd); }
    requireFields(request, ["unsignedDirectory", "outputParent", "signatures", "trustedKeys",
      "expected", "reviewedManifestSha256"], "operator request");
    if (filename.startsWith(`${request.unsignedDirectory}/`)) refuse("operator trust request is inside untrusted bundle");
    const result = await finalizeSignedOfflineRelease({ ...request, nowSeconds: Math.floor(Date.now() / 1000) });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write("Offline signed package finalization refused; no deployment allowed.\n");
    process.exitCode = 1;
  }
}
