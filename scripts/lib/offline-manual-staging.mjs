import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync, closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readSync, realpathSync, renameSync,
  rmSync, writeSync,
} from "node:fs";
import path from "node:path";
import { inspectUntrustedOfflineCandidate } from "../../infra/offline/trusted-host-entry.mjs";

// Local byte staging only; this module has no child process, SSH, Docker,
// witness-CAS, ledger-write or deployment entrypoint. No transfer authority.
const FILES = Object.freeze([
  "manifest.json", "signatures.json", "source.tar", "runtime.tar", "migrator.tar",
  "ci-report.json", "scanner-report.json", "finding-review.json",
  "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json",
]);
const LIMIT = 8 * 1024 ** 3;
const BUFFER_SIZE = 128 * 1024;
const SHA = /^[a-f0-9]{64}$/u;
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;

function refuse(message) { throw new Error("Manual local staging refused: " + message); }
function need(ok, message) { if (!ok) refuse(message); }
function same(a, b) {
  return ["dev", "ino", "uid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"].every((key) => a[key] === b[key]);
}
function sameDirectoryOwner(a, b) {
  // Creating our own temporary staging directory necessarily updates the
  // parent's ctime/mtime and, on some filesystems, its link count.
  return ["dev", "ino", "uid", "mode"].every((key) => a[key] === b[key]);
}
function canonicalPrivateDirectory(filename) {
  need(typeof filename === "string" && filename.length > 1 && filename.length <= 4096 &&
    path.isAbsolute(filename) && path.normalize(filename) === filename &&
    filename !== path.parse(filename).root && !filename.includes("\0"), "noncanonical absolute directory");
  need(realpathSync.native(filename) === filename, "aliased directory");
  const st = lstatSync(filename, { bigint: true });
  need(st.isDirectory() && !st.isSymbolicLink() && st.uid === BigInt(process.getuid()) &&
    (st.mode & 0o7777n) === 0o700n, "private owner-only 0700 directory required");
  return st;
}
function disjoint(a, b) {
  return a !== b && !a.startsWith(b + path.sep) && !b.startsWith(a + path.sep);
}
function syncDirectory(dirname) {
  const fd = openSync(dirname, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function copyPinnedFile(source, destination) {
  const before = lstatSync(source, { bigint: true });
  need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
    before.uid === BigInt(process.getuid()) && (before.mode & 0o7777n) === 0o600n &&
    before.size > 0n && before.size <= BigInt(LIMIT), "unsafe source inode");
  const input = openSync(source, READ_FLAGS);
  try {
    need(same(before, fstatSync(input, { bigint: true })), "source inode changed before copy");
    const output = openSync(destination, CREATE_FLAGS, 0o600);
    let bytes = 0;
    const digest = createHash("sha256");
    try {
      const buffer = Buffer.allocUnsafe(BUFFER_SIZE);
      while (bytes < Number(before.size)) {
        const step = Math.min(buffer.length, Number(before.size) - bytes);
        const length = readSync(input, buffer, 0, step, bytes);
        need(length > 0 && length <= step, "source truncated during copy");
        digest.update(buffer.subarray(0, length));
        for (let written = 0; written < length;) {
          const count = writeSync(output, buffer, written, length - written);
          need(count > 0, "staging sink made no progress");
          written += count;
        }
        bytes += length;
      }
      fsyncSync(output);
      need(fstatSync(output, { bigint: true }).size === before.size, "staged output size mismatch");
    } finally { closeSync(output); }
    need(same(before, fstatSync(input, { bigint: true })) &&
      same(before, lstatSync(source, { bigint: true })), "source inode changed during copy");
    const expected = digest.digest("hex");
    const written = openSync(destination, READ_FLAGS);
    try {
      const checked = createHash("sha256");
      const buffer = Buffer.allocUnsafe(BUFFER_SIZE);
      for (let offset = 0; offset < bytes;) {
        const length = readSync(written, buffer, 0, Math.min(buffer.length, bytes - offset), offset);
        need(length > 0, "staged readback truncated");
        checked.update(buffer.subarray(0, length));
        offset += length;
      }
      need(checked.digest("hex") === expected, "staged readback digest differs from source");
    } finally { closeSync(written); }
    return expected;
  } finally { closeSync(input); }
}

/**
 * Copies a structurally self-consistent signed-envelope candidate to a private
 * LOCAL staging directory. This deliberately does not validate the owner's
 * Ed25519 key pin, verify independent host trust or contact a host. Its output
 * is UNTRUSTED for transfer and deployment even when all bytes match.
 *
 * A separate independently trusted operator must run signature/witness/host
 * validation before any future remote transport or release authorization.
 */
export async function stageLocalOfflineCandidate(request = {}) {
  need(process.platform === "linux" && process.getuid && constants.O_NOFOLLOW &&
    constants.O_DIRECTORY && constants.O_EXCL, "Linux private file API required");
  need(request && typeof request === "object" && !Array.isArray(request) &&
    Object.keys(request).length === 2 && Object.hasOwn(request, "candidateDirectory") &&
    Object.hasOwn(request, "stagingParent"), "only candidateDirectory and stagingParent allowed");
  const { candidateDirectory, stagingParent } = request;
  const candidateStat = canonicalPrivateDirectory(candidateDirectory);
  const destinationStat = canonicalPrivateDirectory(stagingParent);
  need(disjoint(candidateDirectory, stagingParent), "candidate and stage roots must be disjoint");
  const inspected = await inspectUntrustedOfflineCandidate({ candidateDirectory });
  need(SHA.test(inspected.manifestDigest), "candidate manifest digest invalid");
  let tempDirectory;
  let publishedDirectory;
  let created = false;
  try {
    tempDirectory = path.join(stagingParent, ".copy-pending-" + randomBytes(16).toString("hex"));
    mkdirSync(tempDirectory, { mode: 0o700 });
    created = true;
    chmodSync(tempDirectory, 0o700);
    const digestMap = new Map();
    for (const name of FILES) {
      digestMap.set(name, copyPinnedFile(path.join(candidateDirectory, name), path.join(tempDirectory, name)));
    }
    syncDirectory(tempDirectory);
    need(same(candidateStat, lstatSync(candidateDirectory, { bigint: true })) &&
      sameDirectoryOwner(destinationStat, lstatSync(stagingParent, { bigint: true })),
    "candidate or staging root changed during copy");
    const recheckedSource = await inspectUntrustedOfflineCandidate({ candidateDirectory });
    const recheckedStage = await inspectUntrustedOfflineCandidate({ candidateDirectory: tempDirectory });
    need(recheckedSource.manifestDigest === inspected.manifestDigest &&
      recheckedStage.manifestDigest === inspected.manifestDigest &&
      recheckedSource.signatures.owner === inspected.signatures.owner &&
      recheckedSource.signatures.builder === inspected.signatures.builder &&
      recheckedStage.signatures.owner === inspected.signatures.owner &&
      recheckedStage.signatures.builder === inspected.signatures.builder &&
      JSON.stringify(recheckedSource.expected) === JSON.stringify(inspected.expected) &&
      JSON.stringify(recheckedStage.expected) === JSON.stringify(inspected.expected),
    "source or staged candidate changed during complete inspection");
    for (const [name, digest] of digestMap) {
      const raw = name === "manifest.json" ? recheckedStage.manifestBytes
        : name === "signatures.json" ? Buffer.from(JSON.stringify(recheckedStage.signatures)) : null;
      if (raw) need(createHash("sha256").update(raw).digest("hex") === digest,
        "signed metadata changed during readback");
    }
    const completed = path.join(stagingParent, "candidate-" + randomBytes(16).toString("hex"));
    renameSync(tempDirectory, completed);
    tempDirectory = undefined;
    publishedDirectory = completed;
    // Negative fault injection exists solely for WSL private disposable test
    // dirs, never for a native production host; it only forces a refusal.
    if (process.env.VIRKI_TEST_MANUAL_STAGING_SYNC_FAIL === "1" &&
      /microsoft|wsl/iu.test((await import("node:os")).release()) &&
      stagingParent.startsWith("/tmp/virki-manual-stage-")) {
      throw new Error("fixture-injected post-rename sync failure");
    }
    syncDirectory(stagingParent);
    publishedDirectory = undefined;
    return Object.freeze({
      status: "LOCAL_STAGING_BYTES_COPIED_UNTRUSTED",
      stagedDirectory: completed,
      manifestSha256: inspected.manifestDigest,
      fileCount: FILES.length,
      transferAuthorized: false,
      deployAuthorized: false,
    });
  } catch (error) {
    if (publishedDirectory) {
      // It is unsafe to automatically delete a published stage after an
      // unconfirmed directory fsync. Preserve the exact random owned path and
      // report it for operator reconciliation rather than lose the reference.
      const uncertain = new Error("Published manual stage parent sync uncertain; owner reconciliation required");
      uncertain.code = "MANUAL_STAGE_AFTER_RENAME_UNCERTAIN";
      uncertain.stagedDirectory = publishedDirectory;
      throw uncertain;
    }
    throw error;
  } finally {
    if (created && tempDirectory) rmSync(tempDirectory, { recursive: true, force: true });
  }
}
