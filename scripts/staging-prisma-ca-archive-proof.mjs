/**
 * Offline, fail-closed inspection of the *daemon-supplied* TAR bytes emitted by:
 *   docker cp <created-container>:/app/ca -
 *
 * Proof scope: exact approved SHA-256 of one file plus its TAR header metadata,
 * as reported by the Docker daemon. This DOES NOT prove OCI provenance/signature,
 * that the daemon is trustworthy, certificate validity, or PostgreSQL TLS.
 *
 * Interface: node scripts/staging-prisma-ca-archive-proof.mjs <64-lowercase-hex-sha256>
 *            < Docker-CP-ARCHIVE.tar
 * Only stdout: STAGING_PRISMA_CA_ARCHIVE=PASS or BLOCK:STAGING_PRISMA_CA_ARCHIVE.
 * No archive data, filenames, exception messages or sensitive bytes are printed.
 */
import { createHash } from "node:crypto";

const BLOCK_BYTES = 512;
const MAX_ARCHIVE_BYTES = 1024 * 1024;
const MAX_CA_BYTES = 128 * 1024;
const DIRECTORY = "ca/";
const CA_FILE = "ca/staging-db-root.pem";
const PASS = "STAGING_PRISMA_CA_ARCHIVE=PASS";
const BLOCK = "BLOCK:STAGING_PRISMA_CA_ARCHIVE";

function reject() {
  throw new Error("rejected");
}

function allZero(bytes) {
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function textField(block, start, length) {
  const bytes = block.subarray(start, start + length);
  const terminator = bytes.indexOf(0);
  if (terminator < 0 || !allZero(bytes.subarray(terminator))) reject();
  const content = bytes.subarray(0, terminator);
  for (const byte of content) if (byte < 32 || byte > 126) reject();
  return content.toString("ascii");
}

function octalField(block, start, length, optional = false) {
  const raw = block.toString("latin1", start, start + length);
  if (optional && /^[\0 ]+$/u.test(raw)) return 0;
  // Reject base-256, signed, decimal, embedded NUL, whitespace within digits.
  if (!/^ *[0-7]+(?:\0[ \0]*|[ ]*)$/u.test(raw)) reject();
  const digits = raw.replace(/[\0 ]+$/gu, "").trimStart();
  const number = Number.parseInt(digits, 8);
  if (!Number.isSafeInteger(number) || number < 0) reject();
  return number;
}

function tarHeader(bytes) {
  if (bytes.length !== BLOCK_BYTES) reject();
  if (bytes.toString("latin1", 257, 263) !== "ustar\0" ||
      bytes.toString("latin1", 263, 265) !== "00") reject();
  // No path prefix, GNU/PAX extension, link target, or reserved trailing data.
  if (!allZero(bytes.subarray(345, 512)) ||
      textField(bytes, 157, 100) !== "") reject();
  const name = textField(bytes, 0, 100);
  const mode = octalField(bytes, 100, 8);
  const uid = octalField(bytes, 108, 8);
  const gid = octalField(bytes, 116, 8);
  const size = octalField(bytes, 124, 12);
  octalField(bytes, 136, 12); // mtime must also be a safe octal number.
  const recordedChecksum = octalField(bytes, 148, 8);
  let computedChecksum = 0;
  for (let i = 0; i < BLOCK_BYTES; i += 1) {
    computedChecksum += i >= 148 && i < 156 ? 32 : bytes[i];
  }
  if (recordedChecksum !== computedChecksum) reject();

  const uname = textField(bytes, 265, 32);
  const gname = textField(bytes, 297, 32);
  if (uid !== 0 || gid !== 0 ||
      (uname !== "" && uname !== "root") ||
      (gname !== "" && gname !== "root") ||
      octalField(bytes, 329, 8, true) !== 0 ||
      octalField(bytes, 337, 8, true) !== 0) reject();

  const type = bytes[156];
  if (name === DIRECTORY && type === 53 && mode === 0o755 && size === 0) {
    return { kind: "directory", size };
  }
  if (name === CA_FILE && (type === 48 || type === 0) &&
      mode === 0o444 && size > 0 && size <= MAX_CA_BYTES) {
    return { kind: "file", size };
  }
  reject();
}

/**
 * Incremental parser: buffers at most one 512-byte TAR header at a time;
 * hashes file data directly from incoming chunks, including bounded pipes.
 * Trailing TAR blocks must be zero; requires at least the standard two.
 */
class CaArchiveParser {
  constructor(expectedDigest) {
    if (!/^[a-f0-9]{64}$/u.test(expectedDigest ?? "")) reject();
    this.expectedDigest = expectedDigest;
    this.totalBytes = 0;
    this.header = Buffer.alloc(BLOCK_BYTES);
    this.headerUsed = 0;
    this.state = "header";
    this.entries = 0;
    this.eofBlocks = 0;
    this.remaining = 0;
    this.padding = 0;
    this.hash = createHash("sha256");
  }

  push(chunk) {
    if (!Buffer.isBuffer(chunk)) reject();
    this.totalBytes += chunk.length;
    if (!Number.isSafeInteger(this.totalBytes) ||
        this.totalBytes > MAX_ARCHIVE_BYTES) reject();

    let position = 0;
    while (position < chunk.length) {
      if (this.state === "header" || this.state === "eof") {
        const take = Math.min(BLOCK_BYTES - this.headerUsed, chunk.length - position);
        chunk.copy(this.header, this.headerUsed, position, position + take);
        this.headerUsed += take;
        position += take;
        if (this.headerUsed !== BLOCK_BYTES) continue;
        this.headerUsed = 0;

        if (this.state === "eof") {
          if (!allZero(this.header)) reject();
          this.eofBlocks += 1;
          continue;
        }
        if (allZero(this.header)) {
          this.state = "eof";
          this.eofBlocks = 1;
          continue;
        }
        const entry = tarHeader(this.header);
        if ((this.entries === 0 && entry.kind !== "directory") ||
            (this.entries === 1 && entry.kind !== "file") ||
            this.entries >= 2) reject();
        this.entries += 1;
        this.remaining = entry.size;
        this.padding = (BLOCK_BYTES - entry.size % BLOCK_BYTES) % BLOCK_BYTES;
        this.state = this.remaining > 0 ? "data" : "header";
        continue;
      }
      if (this.state === "data") {
        const take = Math.min(this.remaining, chunk.length - position);
        this.hash.update(chunk.subarray(position, position + take));
        position += take;
        this.remaining -= take;
        if (this.remaining === 0) this.state = this.padding > 0 ? "padding" : "header";
        continue;
      }
      if (this.state === "padding") {
        const take = Math.min(this.padding, chunk.length - position);
        if (!allZero(chunk.subarray(position, position + take))) reject();
        position += take;
        this.padding -= take;
        if (this.padding === 0) this.state = "header";
        continue;
      }
      reject();
    }
  }

  finish() {
    if (this.entries !== 2 || this.state !== "eof" ||
        this.headerUsed !== 0 || this.eofBlocks < 2 ||
        this.totalBytes % BLOCK_BYTES !== 0 ||
        this.hash.digest("hex") !== this.expectedDigest) reject();
  }
}

async function main() {
  try {
    if (process.argv.length !== 3) reject();
    const parser = new CaArchiveParser(process.argv[2]);
    for await (const chunk of process.stdin) parser.push(chunk);
    parser.finish();
    process.stdout.write(PASS + "\n");
  } catch {
    process.exitCode = 1;
    process.stdout.write(BLOCK + "\n");
  }
}

void main();
