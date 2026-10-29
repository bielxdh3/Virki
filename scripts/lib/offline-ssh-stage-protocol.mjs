import { createHash, randomBytes } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readSync, realpathSync, readdirSync, renameSync, rmSync, writeSync, statfsSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

// Native host imports only the independently owner-installed verifier and its
// pinned dependency closure. The candidate and local checkout are never code.
const HOST_VERIFIER = "file:///usr/local/lib/virki/offline-release/infra/offline/trusted-host-entry.mjs";

// Data-only transport. No trust claims from the wire grant host admission.
// The independently installed native root receiver performs signature and
// machine-id verification before publishing this private pending directory.
export const OFFLINE_WIRE_FILES = Object.freeze([
  "manifest.json", "signatures.json", "source.tar", "runtime.tar", "migrator.tar",
  "ci-report.json", "scanner-report.json", "finding-review.json",
  "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json",
]);
const MAX_FILE = 8 * 1024 ** 3;
const RESERVE = 4 * 1024 ** 3;
const MAX_METADATA = 8192;
const BLOCK = 128 * 1024;
const HASH = /^[a-f0-9]{64}$/u;
const READ = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const CREATE = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
function need(ok, reason) {
  if (!ok) throw new Error("Offline SSH stage refused: " + reason);
}
function same(a, b) {
  return ["dev", "ino", "uid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
function hashFile(fd, length) {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(BLOCK);
  for (let offset = 0; offset < length;) {
    const count = readSync(fd, buffer, 0, Math.min(BLOCK, length - offset), offset);
    need(count > 0, "unexpected EOF on pinned file");
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  return hash.digest("hex");
}
function checkedFile(directory, name) {
  const filename = path.join(directory, name);
  const before = lstatSync(filename, { bigint: true });
  need(before.isFile() && !before.isSymbolicLink() &&
    before.nlink === 1n && before.uid === BigInt(process.getuid()) &&
    (before.mode & 0o7777n) === 0o600n && before.size > 0n &&
    before.size <= BigInt(MAX_FILE), "unsafe file inode " + name);
  const fd = openSync(filename, READ);
  const after = fstatSync(fd, { bigint: true });
  if (!same(before, after)) {
    closeSync(fd);
    need(false, "file changed during open " + name);
  }
  return { fd, before, filename };
}
function checkAgain(file) {
  need(same(file.before, fstatSync(file.fd, { bigint: true })) &&
    same(file.before, lstatSync(file.filename, { bigint: true })),
  "file changed during use");
}
function privateDirectory(dirname, rootOwned) {
  need(process.platform === "linux" && typeof process.getuid === "function" &&
    Number.isInteger(constants.O_NOFOLLOW) && Number.isInteger(constants.O_DIRECTORY),
  "Linux no-follow filesystem required");
  need(typeof dirname === "string" && dirname.length > 1 && dirname.length <= 4096 &&
    path.isAbsolute(dirname) && path.normalize(dirname) === dirname &&
    dirname !== path.parse(dirname).root && !dirname.includes("\0") &&
    realpathSync.native(dirname) === dirname, "noncanonical or aliased directory");
  const before = lstatSync(dirname, { bigint: true });
  need(before.isDirectory() && !before.isSymbolicLink() &&
    before.uid === BigInt(rootOwned ? 0 : process.getuid()) &&
    (before.mode & 0o7777n) === 0o700n,
  "owner-private 0700 directory required");
  const fd = openSync(dirname, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const after = fstatSync(fd, { bigint: true });
    need(before.dev === after.dev && before.ino === after.ino && before.mode === after.mode &&
      before.uid === after.uid, "private directory changed on open");
  } finally { closeSync(fd); }
}
function syncDirectory(dirname) {
  const fd = openSync(dirname, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
async function writeBlock(stream, block) {
  need(!stream.destroyed, "SSH stream closed");
  if (!stream.write(block)) {
    await new Promise((resolve, reject) => {
      const finish = (error) => {
        clearTimeout(timeout);
        stream.off("drain", onDrain);
        stream.off("close", onClose);
        stream.off("error", onError);
        if (error) reject(error);
        else resolve();
      };
      const onDrain = () => finish();
      const onClose = () => finish(new Error("SSH receiver disconnected"));
      const onError = (error) => finish(error);
      const timeout = setTimeout(
        () => finish(new Error("SSH receiver stopped draining")), 60_000);
      stream.once("drain", onDrain);
      stream.once("close", onClose);
      stream.once("error", onError);
    });
  }
}
function headerFrom(files, signedPermit) {
  const metadata = Buffer.from(JSON.stringify({
    version: signedPermit ? 2 : 1,
    files: files.map(({ name, size, sha256 }) => ({ name, size, sha256 })),
    ...(signedPermit ? {
      permitBase64: signedPermit.permitBytes.toString("base64"),
      signatureBase64: signedPermit.signatureBytes.toString("ascii"),
    } : {}),
  }));
  need(metadata.length <= MAX_METADATA, "protocol metadata too large");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(metadata.length);
  return Buffer.concat([prefix, metadata]);
}
function parseHeader(raw) {
  need(raw.length > 0 && raw.length <= MAX_METADATA, "invalid wire header length");
  let obj;
  try { obj = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { need(false, "invalid UTF-8 wire metadata"); }
  need(obj && typeof obj === "object" && !Array.isArray(obj) &&
    (obj.version === 1 || obj.version === 2) &&
    Object.keys(obj).length === (obj.version === 2 ? 4 : 2) &&
    Object.keys(obj)[0] === "version" && Object.keys(obj)[1] === "files" &&
    Array.isArray(obj.files) && obj.files.length === OFFLINE_WIRE_FILES.length,
  "invalid wire inventory");
  if (obj.version === 2) {
    need(Object.keys(obj)[2] === "permitBase64" &&
      Object.keys(obj)[3] === "signatureBase64" &&
      typeof obj.permitBase64 === "string" && obj.permitBase64.length <= 5464 &&
      /^[A-Za-z0-9+/]+={0,2}$/u.test(obj.permitBase64) &&
      typeof obj.signatureBase64 === "string" &&
      /^[A-Za-z0-9+/]{86}==$/u.test(obj.signatureBase64),
    "malformed transfer authorization envelope");
  }
  for (let i = 0; i < OFFLINE_WIRE_FILES.length; i++) {
    const file = obj.files[i];
    const limit = i === 0 ? 8192 : i === 1 ? 4 * 1024 ** 2
      : i <= 4 ? MAX_FILE : i === 5 ? 65536 : 16 * 1024 ** 2;
    need(file && typeof file === "object" && !Array.isArray(file) &&
      Object.keys(file).length === 3 &&
      file.name === OFFLINE_WIRE_FILES[i] &&
      Number.isSafeInteger(file.size) && file.size > 0 && file.size <= limit &&
      HASH.test(file.sha256), "malformed or unexpected file " + i);
  }
  need(Buffer.from(JSON.stringify(obj)).equals(raw), "wire metadata not canonical");
  return obj;
}

/** Sends exactly the eleven private files as a bounded, binary, hash-bound stream. */
export async function streamOfflineStageToWritable({
  candidateDirectory, writable, expectedManifestSha256, expectedEnvelopeSha256, signedPermit,
}) {
  privateDirectory(candidateDirectory, false);
  need(writable && typeof writable.write === "function", "missing writable stream");
  need(JSON.stringify(readdirSync(candidateDirectory).sort()) ===
    JSON.stringify([...OFFLINE_WIRE_FILES].sort()), "foreign or missing candidate files");
  const files = [];
  try {
    for (const name of OFFLINE_WIRE_FILES) {
      const pinned = checkedFile(candidateDirectory, name);
      files.push({ ...pinned, name, size: Number(pinned.before.size),
        sha256: hashFile(pinned.fd, Number(pinned.before.size)) });
      checkAgain(pinned);
    }
    if (expectedManifestSha256 !== undefined) {
      need(files[0].sha256 === expectedManifestSha256, "owner-pinned manifest changed before sending");
    }
    if (expectedEnvelopeSha256 !== undefined) {
      need(files[1].sha256 === expectedEnvelopeSha256, "owner-pinned signature envelope changed before sending");
    }
    if (signedPermit !== undefined) {
      need(signedPermit && Buffer.isBuffer(signedPermit.permitBytes) &&
        signedPermit.permitBytes.length > 0 && signedPermit.permitBytes.length <= 4096 &&
        Buffer.isBuffer(signedPermit.signatureBytes) &&
        signedPermit.signatureBytes.length === 88,
      "real owner-signed permit envelope required before sending");
    }
    await writeBlock(writable, headerFrom(files, signedPermit));
    const buffer = Buffer.allocUnsafe(BLOCK);
    for (const file of files) {
      const hasher = createHash("sha256");
      for (let offset = 0; offset < file.size;) {
        const count = readSync(file.fd, buffer, 0, Math.min(BLOCK, file.size - offset), offset);
        need(count > 0, "source truncated after metadata");
        const chunk = buffer.subarray(0, count);
        hasher.update(chunk);
        // The writable may retain the buffer after write() returns true.
        // Never reuse the same read buffer while SSH still owns those bytes.
        await writeBlock(writable, Buffer.from(chunk));
        offset += count;
      }
      need(hasher.digest("hex") === file.sha256, "source hash changed during SSH copy");
      checkAgain(file);
    }
    privateDirectory(candidateDirectory, false);
    writable.end();
    return Object.freeze({ status: "UNTRUSTED_WIRE_SENT", fileCount: files.length });
  } finally {
    for (const file of files) closeSync(file.fd);
  }
}

class WireReader {
  constructor(readable) { this.iterator = readable[Symbol.asyncIterator](); this.buffer = Buffer.alloc(0); }
  async take(count) {
    need(Number.isSafeInteger(count) && count >= 0 && count <= BLOCK, "invalid bounded read");
    while (this.buffer.length < count) {
      const next = await this.iterator.next();
      need(!next.done && Buffer.isBuffer(next.value), "truncated SSH payload");
      need(next.value.length > 0 && next.value.length <= 1024 * 1024, "oversized SSH chunk");
      this.buffer = Buffer.concat([this.buffer, next.value]);
    }
    const result = this.buffer.subarray(0, count);
    this.buffer = this.buffer.subarray(count);
    return result;
  }
  async end() {
    need(this.buffer.length === 0, "trailing SSH payload");
    const next = await this.iterator.next();
    need(next.done, "trailing SSH payload");
  }
}

/**
 * Receives bytes into a randomly named private quarantine. No public stage,
 * trust decision, release authorization, or caller-supplied filenames.
 * Caller must independently validate owner signatures and host trust before
 * publishPendingOfflineStage; until then the quarantine must not be used.
 */
export async function receiveOfflineWireToQuarantine({
  readable, stagingParent, requireRoot = true, authorizeTransfer,
}) {
  privateDirectory(stagingParent, requireRoot);
  need(readable && typeof readable[Symbol.asyncIterator] === "function", "missing SSH input");
  const reader = new WireReader(readable);
  const metadataLength = (await reader.take(4)).readUInt32BE(0);
  need(metadataLength <= MAX_METADATA && metadataLength > 0, "header size refused");
  const header = parseHeader(await reader.take(metadataLength));
  const files = header.files;
  if (requireRoot) {
    // No data chunk can enter a native file before independent Ed25519 permit
    // verification AND durable single-use nonce consumption. A plain V1
    // archive is deliberately unsupported for root admission.
    need(header.version === 2 && typeof authorizeTransfer === "function",
      "native receiver requires signed one-use transfer permit before payload");
    const permitBytes = Buffer.from(header.permitBase64, "base64");
    const signatureBytes = Buffer.from(header.signatureBase64, "ascii");
    need(permitBytes.toString("base64") === header.permitBase64 &&
      signatureBytes.toString("ascii") === header.signatureBase64,
    "noncanonical signed transfer authorization");
    await authorizeTransfer({
      permitBytes, signatureBytes,
      manifestSha256: files[0].sha256, envelopeSha256: files[1].sha256,
    });
    // The installed receiver owns an exclusive root-only O_EXCL lock for the
    // entire receive -> native verifier -> published-stage transaction. Any
    // prior candidate or interrupted transfer requires owner reconciliation.
    const entries = readdirSync(stagingParent);
    need(entries.length === 1 && entries[0] === ".receiver-lock",
      "native exclusive receiver lock or clean stage root absent");
    const lock = lstatSync(path.join(stagingParent, entries[0]), { bigint: true });
    need(lock.isFile() && lock.uid === 0n && lock.nlink === 1n &&
      (lock.mode & 0o7777n) === 0o600n, "unsafe native receiver lock");
    const budget = statfsSync(stagingParent, { bigint: true });
    const required = files.reduce((sum, file) => sum + BigInt(file.size), 0n);
    need(budget.bavail * budget.bsize > required + BigInt(RESERVE),
      "native disk budget would fall below 4 GiB reserve");
  }
  const dirname = path.join(stagingParent, ".incoming-" + randomBytes(16).toString("hex"));
  mkdirSync(dirname, { mode: 0o700 });
  try {
    for (const file of files) {
      const pathname = path.join(dirname, file.name);
      const fd = openSync(pathname, CREATE, 0o600);
      try {
        const hash = createHash("sha256");
        let offset = 0;
        while (offset < file.size) {
          const chunk = await reader.take(Math.min(BLOCK, file.size - offset));
          hash.update(chunk);
          for (let wrote = 0; wrote < chunk.length;) {
            const count = writeSync(fd, chunk, wrote, chunk.length - wrote);
            need(count > 0, "SSH sink made no progress");
            wrote += count;
          }
          offset += chunk.length;
        }
        fsyncSync(fd);
        need(fstatSync(fd, { bigint: true }).size === BigInt(file.size) &&
          hash.digest("hex") === file.sha256, "wire file hash or length mismatch");
      } finally { closeSync(fd); }
      const pinned = checkedFile(dirname, file.name);
      try {
        need(hashFile(pinned.fd, file.size) === file.sha256, "independent sink readback differs");
        checkAgain(pinned);
      } finally { closeSync(pinned.fd); }
    }
    await reader.end();
    syncDirectory(dirname);
    privateDirectory(stagingParent, requireRoot);
    return Object.freeze({ status: "UNTRUSTED_QUARANTINED", pendingDirectory: dirname,
      fileCount: files.length, manifestSha256: files[0].sha256,
      transferAuthorized: false, deployAuthorized: false });
  } catch (error) {
    rmSync(dirname, { recursive: true, force: true });
    throw error;
  }
}

/** The independently installed native host verifier is the only publisher. */
export async function publishVerifiedOfflineQuarantine({ pendingDirectory, stagingParent, manifestSha256 }) {
  need(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && !/microsoft|wsl/iu.test(os.release()),
  "native root receiver required");
  privateDirectory(stagingParent, true);
  need(typeof pendingDirectory === "string" && path.dirname(pendingDirectory) === stagingParent &&
    /^\.incoming-[a-f0-9]{32}$/u.test(path.basename(pendingDirectory)) && HASH.test(manifestSha256),
  "unowned quarantine path");
  privateDirectory(pendingDirectory, true);
  const { verifyTrustedHostOfflineCandidate } = await import(HOST_VERIFIER);
  const verified = await verifyTrustedHostOfflineCandidate({ candidateDirectory: pendingDirectory });
  need(verified.status === "INSPECTED_ONLY_RELEASE_BLOCKED" &&
    verified.deployAuthorized === false &&
    verified.verifiedManifestSha256 === manifestSha256,
  "remote owner/builder signatures or manifest binding refused");
  // Re-read the candidate after the expensive native Docker TAR inspection;
  // only files with immutable inode metadata can be published.
  for (const name of OFFLINE_WIRE_FILES) {
    const pinned = checkedFile(pendingDirectory, name);
    try { checkAgain(pinned); } finally { closeSync(pinned.fd); }
  }
  syncDirectory(pendingDirectory);
  const destination = path.join(stagingParent, "candidate-" + randomBytes(16).toString("hex"));
  renameSync(pendingDirectory, destination);
  try { syncDirectory(stagingParent); }
  catch {
    const error = new Error("published stage parent fsync uncertain; operator reconciliation required");
    error.code = "OFFLINE_REMOTE_STAGE_SYNC_UNCERTAIN";
    error.stagedDirectory = destination;
    throw error;
  }
  return destination;
}
