import { randomBytes } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync,
  readdirSync, realpathSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

// This is an isolated local persistence component, NOT a release authorization,
// deploy path, cryptographic signature verifier or production ledger installer.
// A trusted operator must provision ledger.json (0600) inside an owner-only
// directory (0700): {"version":1,"anchorSha":"<40 lowercase hex>","entries":[]}.
// This component deliberately refuses to invent its own trust anchor.
const LEDGER_NAME = "ledger.json";
const LOCK_NAME = ".offline-release.lock";
const MAX_ENTRIES = 1024;
const MAX_LEDGER_BYTES = 1024 * 1024;
const SHA = /^[a-f0-9]{40}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const NONCE = /^[a-f0-9]{32}$/u;
const ENTRY_FIELDS = ["sequence", "priorSha", "nextSha", "manifestSha256", "nonce", "approvalDigest"];
const OPEN_DIRECTORY = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const CREATE_NEW = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;

function invariant(holds, reason) {
  if (!holds) throw new Error(`Offline release ledger refused: ${reason}.`);
}

function ownPrivateFile(stat, type, mode) {
  invariant((type === "directory" ? stat.isDirectory() : stat.isFile()) &&
    stat.uid === process.getuid() && (stat.mode & 0o7777) === mode &&
    (type === "directory" || stat.nlink === 1),
  `unsafe ${type} owner, mode or link count`);
}

function requireExactFields(value, fields) {
  invariant(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((name, index) => Object.keys(value)[index] === name),
  "unexpected or absent ledger fields");
}

function validateHistory(state) {
  requireExactFields(state, ["version", "anchorSha", "entries"]);
  invariant(state.version === 1 && SHA.test(state.anchorSha) && Array.isArray(state.entries) &&
    state.entries.length <= MAX_ENTRIES, "invalid ledger version, anchor or size");

  const usedSha = new Set([state.anchorSha]);
  const usedNonces = new Set();
  const usedManifests = new Set();
  const usedApprovals = new Set();
  let current = state.anchorSha;
  for (const [index, entry] of state.entries.entries()) {
    requireExactFields(entry, ENTRY_FIELDS);
    invariant(entry.sequence === index + 1 && entry.priorSha === current &&
      SHA.test(entry.nextSha) && !usedSha.has(entry.nextSha) &&
      DIGEST.test(entry.manifestSha256) && !usedManifests.has(entry.manifestSha256) &&
      NONCE.test(entry.nonce) && !usedNonces.has(entry.nonce) &&
      DIGEST.test(entry.approvalDigest) && !usedApprovals.has(entry.approvalDigest),
    "inconsistent or replayed approval history");
    usedSha.add(entry.nextSha);
    usedNonces.add(entry.nonce);
    usedManifests.add(entry.manifestSha256);
    usedApprovals.add(entry.approvalDigest);
    current = entry.nextSha;
  }
  return { current, usedSha, usedNonces, usedManifests, usedApprovals };
}

function validateRequest(request) {
  invariant(request && typeof request === "object" && !Array.isArray(request), "request must be an object");
  const { directory, manifestSha256, priorSha, nextSha, nonce, sequence, approvalDigest } = request;
  invariant(typeof directory === "string" && path.isAbsolute(directory) &&
    path.normalize(directory) === directory && directory !== path.parse(directory).root,
  "trusted directory path must be absolute and normalized");
  invariant(DIGEST.test(manifestSha256) && DIGEST.test(approvalDigest) &&
    SHA.test(priorSha) && SHA.test(nextSha) && priorSha !== nextSha &&
    NONCE.test(nonce) && Number.isSafeInteger(sequence) && sequence > 0 && sequence <= MAX_ENTRIES,
  "invalid SHA, nonce, approval digest or sequence");
  return { directory, manifestSha256, priorSha, nextSha, nonce, sequence, approvalDigest };
}

/** Pure state transition: no I/O, keys, network or process-global overrides. */
export function validateOfflineLedgerTransition(state, request) {
  const accepted = validateRequest(request);
  const history = validateHistory(state);
  invariant(state.entries.length < MAX_ENTRIES && accepted.sequence === state.entries.length + 1 &&
    accepted.priorSha === history.current && !history.usedSha.has(accepted.nextSha) &&
    !history.usedNonces.has(accepted.nonce) &&
    !history.usedManifests.has(accepted.manifestSha256) &&
    !history.usedApprovals.has(accepted.approvalDigest),
  "predecessor, monotonic sequence or replay check failed");
  const entry = {
    sequence: accepted.sequence, priorSha: accepted.priorSha,
    nextSha: accepted.nextSha, manifestSha256: accepted.manifestSha256,
    nonce: accepted.nonce, approvalDigest: accepted.approvalDigest,
  };
  return { version: 1, anchorSha: state.anchorSha, entries: [...state.entries, entry] };
}

function openTrustedDirectory(directory) {
  // Reject symlinks in any path component before pinning the final inode.
  invariant(realpathSync.native(directory) === directory, "ledger directory has a symlinked path");
  const fd = openSync(directory, OPEN_DIRECTORY);
  try {
    const meta = fstatSync(fd);
    ownPrivateFile(meta, "directory", 0o700);
    const lexical = lstatSync(directory);
    invariant(lexical.isDirectory() && !lexical.isSymbolicLink() &&
      lexical.dev === meta.dev && lexical.ino === meta.ino,
    "trusted directory changed identity during open");
    // Every subsequent file operation is relative to this opened Linux inode.
    // No pathname is re-resolved through an attacker-replaceable directory.
    return { fd, dir: `/proc/self/fd/${fd}` };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function openAndCheckLedger(base) {
  const filenames = readdirSync(base);
  invariant(filenames.length === 2 && filenames.includes(LEDGER_NAME) &&
    filenames.includes(LOCK_NAME),
  "ledger directory has missing, foreign or interrupted transaction files");
  const fd = openSync(path.join(base, LEDGER_NAME), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try {
    const meta = fstatSync(fd);
    ownPrivateFile(meta, "file", 0o600);
    invariant(meta.size > 0 && meta.size <= MAX_LEDGER_BYTES, "ledger size out of bounds");
    const raw = readFileSync(fd);
    invariant(raw.byteLength === meta.size, "ledger changed during read");
    const content = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    const parsed = JSON.parse(content);
    invariant(JSON.stringify(parsed) === content, "ledger JSON is not canonical");
    return parsed;
  } finally {
    closeSync(fd);
  }
}

function writeAll(fd, bytes) {
  let written = 0;
  while (written < bytes.length) {
    const length = writeSync(fd, bytes, written, bytes.length - written);
    invariant(Number.isInteger(length) && length > 0, "short or failed durable write");
    written += length;
  }
}

/**
 * Record a previously VERIFIED manifest and owner approval in an independently
 * bootstrapped native-Linux private ledger. The caller must already have
 * verified both signatures; SHA and digest arguments are opaque identifiers.
 *
 * The owner is responsible for manually reconciling any retained .lock or
 * .pending-* file following interruption. A successful write removes its own
 * lock; a failed operation after acquiring it leaves a permanent latch.
 *
 * @param {{directory:string,manifestSha256:string,priorSha:string,nextSha:string,
 *   nonce:string,sequence:number,approvalDigest:string}} request
 */
export function recordOfflineReleaseAcceptance(request) {
  invariant(process.platform === "linux" && !/microsoft|wsl/iu.test(os.release()) &&
    typeof process.getuid === "function" && constants.O_NOFOLLOW && constants.O_DIRECTORY &&
    typeof process.getuid() === "number", "native Linux and O_NOFOLLOW are required");
  const accepted = validateRequest(request);
  const { fd: directoryFd, dir } = openTrustedDirectory(accepted.directory);
  let lockFd;
  let temporaryFd;
  try {
    const lockPath = path.join(dir, LOCK_NAME);
    // O_EXCL is the cross-process admission boundary. Existing lock always
    // fails closed (including stale lock left by SIGKILL); never steal it.
    lockFd = openSync(lockPath, CREATE_NEW, 0o600);
    ownPrivateFile(fstatSync(lockFd), "file", 0o600);
    writeAll(lockFd, Buffer.from(JSON.stringify({ pid: process.pid, reason: "unresolved-until-success" })));
    fsyncSync(lockFd);
    fsyncSync(directoryFd);

    const state = openAndCheckLedger(dir);
    const updated = Buffer.from(JSON.stringify(validateOfflineLedgerTransition(state, accepted)));
    invariant(updated.length <= MAX_LEDGER_BYTES, "ledger has reached capacity");

    const tempPath = path.join(dir, `.pending-${randomBytes(16).toString("hex")}`);
    temporaryFd = openSync(tempPath, CREATE_NEW, 0o600);
    ownPrivateFile(fstatSync(temporaryFd), "file", 0o600);
    writeAll(temporaryFd, updated);
    fsyncSync(temporaryFd);
    closeSync(temporaryFd);
    temporaryFd = undefined;

    // File data is durable before the atomic replace; dir fsync makes the
    // rename durable before the success lock is removed and synced again.
    renameSync(tempPath, path.join(dir, LEDGER_NAME));
    fsyncSync(directoryFd);
    const lockMeta = fstatSync(lockFd);
    const onDiskLock = lstatSync(lockPath);
    invariant(onDiskLock.isFile() && !onDiskLock.isSymbolicLink() &&
      onDiskLock.ino === lockMeta.ino && onDiskLock.dev === lockMeta.dev &&
      onDiskLock.nlink === 1, "lock inode was replaced");
    closeSync(lockFd);
    lockFd = undefined;
    unlinkSync(lockPath);
    fsyncSync(directoryFd);
    return Object.freeze({ headSha: accepted.nextSha, sequence: accepted.sequence });
  } finally {
    // No catch removes a lock or a temporary file. Interrupted attempts must
    // be reconciled independently by a trusted operator before further use.
    if (temporaryFd !== undefined) closeSync(temporaryFd);
    if (lockFd !== undefined) closeSync(lockFd);
    closeSync(directoryFd);
  }
}
