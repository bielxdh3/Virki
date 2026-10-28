import { createHash } from "node:crypto";
import {
  closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync,
  renameSync, statfsSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectUntrustedOfflineCandidate } from "./trusted-host-entry.mjs";
import { prepareOfflineTrustedReleasePolicy } from "../../scripts/lib/offline-trusted-release-policy.mjs";
import { verifyOfflineReleaseAttestation } from "../../scripts/lib/offline-release-attestation.mjs";

// Executable development experiment ONLY. No network transport, destination
// override, production root, CLI, GitHub operation, release or Docker authority.
// The caller's identity SHA is a synthetic fixture challenge and never proves
// independent native host identity. Root provisioned pins are mandatory even
// in the disposable fixture. A native externally audited receiver is missing.
const FILENAMES = Object.freeze([
  "backup-restore.json", "ci-report.json", "finding-review.json", "manifest.json",
  "migrator-smoke.json", "migrator.tar", "runtime-smoke.json", "runtime.tar",
  "scanner-report.json", "signatures.json", "source.tar",
]);
const OPERATOR = Object.freeze(["ledger.json", "transfer-pins.json", "trust-policy.json"]);
const SHA = /^[0-9a-f]{64}$/u;
const ROOT_PREFIX = "virki-offline-transfer-fixture-";
const BLOCK = 64 * 1024;
const MAX_ARCHIVE = 8 * 1024 ** 3;
const DIR_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY;
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const WRITE_FLAGS = constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
function requireIt(value) { if (!value) throw new Error("fixture invariant refused"); }
function identical(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
function sameDirectory(a, b) {
  return b.isDirectory() && ["dev", "ino", "uid", "gid", "mode"]
    .every((field) => a[field] === b[field]);
}
function privateDir(dirname) {
  requireIt(path.isAbsolute(dirname) && path.normalize(dirname) === dirname &&
    realpathSync.native(dirname) === dirname);
  const stat = lstatSync(dirname, { bigint: true });
  requireIt(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0n &&
    stat.gid === 0n && (stat.mode & 0o7777n) === 0o700n);
  return stat;
}
function guardFixture(request) {
  requireIt(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && existsSync("/.dockerenv") &&
    process.env.VIRKI_OFFLINE_TRANSFER_FIXTURE === "1" &&
    constants.O_NOFOLLOW && constants.O_EXCL && constants.O_DIRECTORY &&
    statfsSync(os.tmpdir()).type === 0x01021994);
  requireIt(request && typeof request === "object" && !Array.isArray(request) &&
    Object.keys(request).length === 5 &&
    ["fixtureRoot", "candidateDirectory", "operatorDirectory", "stagingDirectory",
      "measuredHostIdentitySha256"].every((key) => Object.hasOwn(request, key)));
  const { fixtureRoot, candidateDirectory, operatorDirectory,
    stagingDirectory, measuredHostIdentitySha256 } = request;
  const temp = realpathSync.native(os.tmpdir());
  requireIt(typeof fixtureRoot === "string" && path.dirname(fixtureRoot) === temp &&
    new RegExp(`^${ROOT_PREFIX}[A-Za-z0-9]{6}$`, "u").test(path.basename(fixtureRoot)) &&
    candidateDirectory === path.join(fixtureRoot, "candidate") &&
    operatorDirectory === path.join(fixtureRoot, "operator") &&
    stagingDirectory === path.join(fixtureRoot, "staging") &&
    SHA.test(measuredHostIdentitySha256));
  for (const dir of [fixtureRoot, candidateDirectory, operatorDirectory, stagingDirectory])
    privateDir(dir);
}
function exactJson(bytes, fields) {
  requireIt(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 65536);
  const raw = new TextDecoder("utf8", { fatal: true }).decode(bytes);
  const parsed = JSON.parse(raw);
  requireIt(parsed && typeof parsed === "object" && !Array.isArray(parsed) &&
    JSON.stringify(Object.keys(parsed)) === JSON.stringify(fields) &&
    JSON.stringify(parsed) === raw);
  return parsed;
}
function checkedFile(dirFd, name, maximum, expected = null) {
  const filename = `/proc/self/fd/${dirFd}/${name}`;
  const before = lstatSync(filename, { bigint: true });
  requireIt(before.isFile() && !before.isSymbolicLink() && before.uid === 0n &&
    before.gid === 0n && before.nlink === 1n &&
    (before.mode & 0o7777n) === 0o600n && before.size > 0n &&
    before.size <= BigInt(maximum) &&
    (!expected || before.size === BigInt(expected.sizeBytes)));
  const fd = openSync(filename, READ_FLAGS);
  try {
    requireIt(identical(before, fstatSync(fd, { bigint: true })));
    const digest = hashFd(fd, Number(before.size));
    requireIt((!expected || digest === expected.sha256) &&
      identical(before, fstatSync(fd, { bigint: true })) &&
      identical(before, lstatSync(filename, { bigint: true })));
    return { fd, name, stat: before, digest, size: Number(before.size) };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}
function hashFd(fd, size) {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(BLOCK);
  let cursor = 0;
  while (cursor < size) {
    const read = readSync(fd, buffer, 0, Math.min(BLOCK, size - cursor), cursor);
    requireIt(read > 0);
    hash.update(buffer.subarray(0, read));
    cursor += read;
  }
  return hash.digest("hex");
}
function stillSame(file, directoryFd) {
  return identical(file.stat, fstatSync(file.fd, { bigint: true })) &&
    identical(file.stat, lstatSync(`/proc/self/fd/${directoryFd}/${file.name}`, { bigint: true }));
}
function readOperator(operatorFd) {
  requireIt(JSON.stringify(readdirSync(`/proc/self/fd/${operatorFd}`).sort()) ===
    JSON.stringify(OPERATOR));
  const output = {};
  for (const name of OPERATOR) {
    const file = checkedFile(operatorFd, name, 1024 * 1024);
    try {
      output[name] = readFileSync(file.fd);
      requireIt(output[name].length === file.size && stillSame(file, operatorFd));
    }
    finally { closeSync(file.fd); }
  }
  return output;
}
function verifyPins(raw, challenge) {
  const pins = exactJson(raw, ["version", "mode", "hostIdentitySha256", "files"]);
  requireIt(pins.version === 1 && pins.mode === "disposable-candidate-transfer-v1" &&
    pins.hostIdentitySha256 === challenge && Array.isArray(pins.files) &&
    pins.files.length === FILENAMES.length);
  for (let i = 0; i < FILENAMES.length; i++) {
    const pin = pins.files[i];
    requireIt(pin && typeof pin === "object" && !Array.isArray(pin) &&
      JSON.stringify(Object.keys(pin)) === JSON.stringify(["name", "sizeBytes", "sha256"]) &&
      pin.name === FILENAMES[i] && SHA.test(pin.sha256) &&
      Number.isSafeInteger(pin.sizeBytes) && pin.sizeBytes > 0 &&
      pin.sizeBytes <= (pin.name.endsWith(".tar") ? MAX_ARCHIVE : 16 * 1024 * 1024));
  }
  return pins;
}
function stageFile(candidateFd, incomingFd, source, pin, onPhase) {
  const destination = `/proc/self/fd/${incomingFd}/${pin.name}`;
  const stageFd = openSync(destination, WRITE_FLAGS, 0o600);
  try {
    const buffer = Buffer.allocUnsafe(BLOCK);
    const digest = createHash("sha256");
    let cursor = 0;
    while (cursor < source.size) {
      const count = readSync(source.fd, buffer, 0, Math.min(BLOCK, source.size - cursor), cursor);
      requireIt(count > 0);
      digest.update(buffer.subarray(0, count));
      let written = 0;
      while (written < count) {
        const n = writeSync(stageFd, buffer, written, count - written, cursor + written);
        requireIt(n > 0);
        written += n;
      }
      cursor += count;
      onPhase?.("chunkCopied");
    }
    fsyncSync(stageFd);
    const stat = fstatSync(stageFd, { bigint: true });
    requireIt(digest.digest("hex") === pin.sha256 && stat.isFile() &&
      stat.uid === 0n && stat.gid === 0n && stat.nlink === 1n &&
      (stat.mode & 0o7777n) === 0o600n && stat.size === BigInt(pin.sizeBytes) &&
      hashFd(stageFd, source.size) === pin.sha256 && stillSame(source, candidateFd));
    return { fd: stageFd, name: pin.name, stat };
  } catch (error) { closeSync(stageFd); throw error; }
}

/**
 * Copies an owner-signed release candidate through preverified, pinned FDs into
 * a private root-owned disposable staging directory. A one-shot .incoming
 * directory is a durable abort latch; only after all bytes are verified is it
 * atomically renamed to published. No SSH, GitHub, rsync or shell is invoked.
 * This is a protocol fixture, never a real host admission or transfer API.
 */
export async function rehearseDisposableCandidateTransfer(request = {}, { onPhase } = {}) {
  const openFds = [];
  try {
    guardFixture(request);
    requireIt(onPhase === undefined || typeof onPhase === "function");
    const { candidateDirectory, operatorDirectory, stagingDirectory,
      measuredHostIdentitySha256 } = request;
    const candidateMeta = privateDir(candidateDirectory);
    const operatorMeta = privateDir(operatorDirectory);
    const stagingMeta = privateDir(stagingDirectory);
    const operatorFd = openSync(operatorDirectory, DIR_FLAGS); openFds.push(operatorFd);
    const candidateFd = openSync(candidateDirectory, DIR_FLAGS); openFds.push(candidateFd);
    const stagingFd = openSync(stagingDirectory, DIR_FLAGS); openFds.push(stagingFd);
    requireIt(identical(operatorMeta, fstatSync(operatorFd, { bigint: true })) &&
      identical(candidateMeta, fstatSync(candidateFd, { bigint: true })) &&
      identical(stagingMeta, fstatSync(stagingFd, { bigint: true })));
    const operator = readOperator(operatorFd);
    const pins = verifyPins(operator["transfer-pins.json"], measuredHostIdentitySha256);
    const trust = prepareOfflineTrustedReleasePolicy({
      policyBytes: operator["trust-policy.json"], ledgerBytes: operator["ledger.json"],
      measuredHostIdentitySha256,
    });
    requireIt(JSON.stringify(readdirSync(`/proc/self/fd/${candidateFd}`).sort()) ===
      JSON.stringify(FILENAMES));
    const sourceFiles = pins.files.map((pin) => {
      const file = checkedFile(candidateFd, pin.name,
        pin.name.endsWith(".tar") ? MAX_ARCHIVE : 16 * 1024 * 1024, pin);
      openFds.push(file.fd);
      return file;
    });
    const candidate = await inspectUntrustedOfflineCandidate({ candidateDirectory });
    const signed = verifyOfflineReleaseAttestation({
      manifestBytes: candidate.manifestBytes, signatures: candidate.signatures,
      trustedKeys: trust.trustedKeys, expected: { ...candidate.expected,
        hostIdentitySha256: trust.hostIdentitySha256,
        predecessorSha: trust.predecessorSha, lastSequence: trust.lastSequence },
    });
    requireIt(signed.manifestSha256 === pins.files.find((x) => x.name === "manifest.json").sha256 &&
      sourceFiles.every((file) => stillSame(file, candidateFd)) &&
      identical(candidateMeta, lstatSync(candidateDirectory, { bigint: true })) &&
      identical(operatorMeta, lstatSync(operatorDirectory, { bigint: true })) &&
      identical(stagingMeta, lstatSync(stagingDirectory, { bigint: true })) &&
      readdirSync(`/proc/self/fd/${stagingFd}`).length === 0);

    const anchored = `/proc/self/fd/${stagingFd}`;
    mkdirSync(path.join(anchored, ".incoming"), { mode: 0o700 });
    fsyncSync(stagingFd);
    const incomingMeta = privateDir(path.join(stagingDirectory, ".incoming"));
    const incomingFd = openSync(path.join(anchored, ".incoming"), DIR_FLAGS);
    openFds.push(incomingFd);
    requireIt(identical(incomingMeta, fstatSync(incomingFd, { bigint: true })));
    onPhase?.("afterPreflight");
    const staged = pins.files.map((pin, i) => {
      const file = stageFile(candidateFd, incomingFd, sourceFiles[i], pin, onPhase);
      openFds.push(file.fd);
      return file;
    });
    fsyncSync(incomingFd);
    fsyncSync(stagingFd);
    onPhase?.("beforePublish");
    const operatorFinal = readOperator(operatorFd);
    requireIt(OPERATOR.every((name) => operatorFinal[name].equals(operator[name])));
    requireIt(sameDirectory(incomingMeta, fstatSync(incomingFd, { bigint: true })) &&
      sameDirectory(incomingMeta, lstatSync(path.join(anchored, ".incoming"), { bigint: true })) &&
      JSON.stringify(readdirSync(`/proc/self/fd/${incomingFd}`).sort()) ===
        JSON.stringify(FILENAMES) &&
      staged.every((f, i) => stillSame(f, incomingFd) &&
        hashFd(f.fd, Number(f.stat.size)) === pins.files[i].sha256) &&
      sourceFiles.every((f) => stillSame(f, candidateFd)) &&
      sameDirectory(candidateMeta, fstatSync(candidateFd, { bigint: true })) &&
      sameDirectory(candidateMeta, lstatSync(candidateDirectory, { bigint: true })) &&
      sameDirectory(operatorMeta, fstatSync(operatorFd, { bigint: true })) &&
      sameDirectory(operatorMeta, lstatSync(operatorDirectory, { bigint: true })) &&
      sameDirectory(stagingMeta, fstatSync(stagingFd, { bigint: true })) &&
      sameDirectory(stagingMeta, lstatSync(stagingDirectory, { bigint: true })) &&
      readdirSync(anchored).length === 1);
    renameSync(path.join(anchored, ".incoming"), path.join(anchored, "published"));
    fsyncSync(stagingFd);
    requireIt(readdirSync(anchored).length === 1 && readdirSync(anchored)[0] === "published" &&
      sameDirectory(incomingMeta, lstatSync(path.join(anchored, "published"), { bigint: true })));
    return Object.freeze({ status: "DISPOSABLE_CANDIDATE_TRANSFER_STAGED_ONLY",
      filesStaged: pins.files.length, signedManifestSha256: signed.manifestSha256,
      transferAuthorized: false, deployAuthorized: false,
      independentHostIdentityVerified: false });
  } catch {
    // Never surface inputs, SSH material, private paths or secrets to a caller.
    throw new Error("Disposable offline candidate transfer refused; publication remains blocked");
  } finally {
    for (const fd of openFds.reverse()) {
      try { closeSync(fd); } catch { /* original fail-closed error takes precedence */ }
    }
  }
}

function isDirectMainInvocation() {
  const entry = process.argv[1];
  if (typeof entry !== "string" || !path.isAbsolute(entry)) return false;
  const entryLexical = path.resolve(entry);
  const moduleLexical = fileURLToPath(import.meta.url);
  if (entryLexical === moduleLexical) return true;
  // Node normally realpaths the loaded ESM entry, while argv still names a
  // symlink or aliased parent. With --preserve-symlinks-main the reverse can
  // occur. In both cases the same underlying executable must refuse its CLI.
  try { return realpathSync.native(entryLexical) === realpathSync.native(moduleLexical); }
  catch { return false; }
}

if (isDirectMainInvocation()) {
  process.stderr.write("Disposable offline candidate staging has no command-line transfer entrypoint.\n");
  process.exitCode = 2;
}
