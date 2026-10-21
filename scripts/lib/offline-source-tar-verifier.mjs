import { createHash } from "node:crypto";
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";

const MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024;
const TAR_BLOCK = 512;
const READ_BLOCK = 64 * 1024;

const RESERVED = new Set([".env", ".npmrc", ".dev.vars", ".ghcr-read-token", ".production.operator.json",
  ".virki-release", ".virki-production-host", "backups", "backup", "dumps", "releases",
  "current", "google takeout", "takeout", "gmail", "attachments", "secrets"]);
const DANGEROUS_SUFFIX = /\.(?:pem|key|p12|pfx|der|jks|keystore|zip|tar|tgz|mbox|log|sqlite3?|db|dump|bak|backup)(?:\.(?:gz|gzip|bz2|xz|zst|lz4))*$/iu;


function reject(reason) { throw new Error(`Offline bundle preparation rejected: ${reason}`); }


function sameStat(a, b) {
  return ["dev", "ino", "size", "nlink", "mtimeNs", "ctimeNs", "mode"].every((key) => a[key] === b[key]);
}


function sensitivePath(entry) {
  const name = entry.toLowerCase().replaceAll("\\", "/").replace(/\/+$/u, "");
  const segments = name.split("/");
  if (name === "infra/backups" || name === "infra/backups/.gitkeep") return false;
  return segments.some((segment) => RESERVED.has(segment) || segment.startsWith(".dev.vars.") ||
    (segment.startsWith(".env.") && segment !== ".env.example") ||
    /^mail-attachments?$/u.test(segment) || /^takeout(?:[-_.]|$)/u.test(segment)) ||
    (segments[0] === "infra" && segments[1] === "cloudflare" && name.endsWith(".json")) ||
    /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)$/iu.test(name) ||
    (DANGEROUS_SUFFIX.test(name) && !/^packages\/database\/prisma\/migrations\/[^/]+\/migration\.sql$/iu.test(name)) ||
    (/\.(?:sql|sqlite|db)(?:\.|$)/iu.test(name) &&
     !/^packages\/database\/prisma\/migrations\/[^/]+\/migration\.sql$/iu.test(name));
}

export function safeTreePath(entry) {
  return typeof entry === "string" && entry.length > 0 && entry.length < 4096 &&
    !entry.includes("\\") && !entry.includes("\r") && !entry.includes("\n") &&
    !entry.includes("\0") && entry.split("/").every((s) => s && s !== "." && s !== "..") &&
    !/^[a-zA-Z]:/u.test(entry) && !sensitivePath(entry);
}


// Strict read-only ustar/PAX subset. The format is parsed locally from the
// pinned inode; neither `tar -tf` nor the archive producer authenticates bytes.
// GNU sparse/longname/link entries, base-256 numbers, and arbitrary PAX keys
// are intentionally unsupported. No archive member is extracted or executed.
export function verifySourceTarAgainstGit(filename, expectedRevision, expectedObjects, expectedCommitTimestamp) {
  if (!Number.isSafeInteger(expectedCommitTimestamp) || expectedCommitTimestamp < 0) {
    reject("authenticated Git commit timestamp is required for source tar verification");
  }
  const pathStat = lstatSync(filename, { bigint: true });
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.nlink !== 1n ||
      pathStat.size < 1024n || pathStat.size > BigInt(MAX_ARCHIVE_BYTES) ||
      pathStat.size % BigInt(TAR_BLOCK) !== 0n) reject("source tar is not a bounded regular archive");
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const original = fstatSync(fd, { bigint: true });
    if (!sameStat(original, pathStat)) reject("source tar changed before verification");
    const length = Number(original.size);
    let position = 0;
    let totalMembers = 0;
    let localPath;
    let globalSeen = false;
    const archiveDigest = createHash("sha256");
    const seen = new Set();
    const small = Buffer.allocUnsafe(TAR_BLOCK);
    const chunk = Buffer.allocUnsafe(READ_BLOCK);
    const decode = new TextDecoder("utf-8", { fatal: true });

    function readExactly(size, buffer) {
      if (position + size > length) reject("truncated source tar member");
      let filled = 0;
      while (filled < size) {
        const n = readSync(fd, buffer, filled, size - filled, position);
        if (n <= 0) reject("truncated source tar read");
        archiveDigest.update(buffer.subarray(filled, filled + n));
        position += n;
        filled += n;
      }
    }
    function textField(buffer, start, end) {
      const slice = buffer.subarray(start, end);
      const nul = slice.indexOf(0);
      if (nul !== -1 && slice.subarray(nul).some((n) => n !== 0)) reject("tar text field has hidden bytes");
      return decode.decode(nul === -1 ? slice : slice.subarray(0, nul));
    }
    function octal(buffer, start, end) {
      const field = buffer.subarray(start, end).toString("ascii");
      if (!/^[ 0]*[0-7]+[\0 ]*$/u.test(field) && !/^[ 0]+[\0 ]*$/u.test(field)) {
        reject("unsupported tar numeric field");
      }
      const digits = field.replace(/^[ 0]+/u, "").replace(/[\0 ]+$/u, "");
      const value = digits ? parseInt(digits, 8) : 0;
      if (!Number.isSafeInteger(value)) reject("tar numeric value is excessive");
      return value;
    }
    function dataHash(size, expectedId) {
      const digest = createHash(expectedId.length === 40 ? "sha1" : "sha256");
      digest.update(Buffer.from(`blob ${size}\0`));
      let remaining = size;
      while (remaining > 0) {
        const n = Math.min(remaining, READ_BLOCK);
        readExactly(n, chunk);
        digest.update(chunk.subarray(0, n));
        remaining -= n;
      }
      if (digest.digest("hex") !== expectedId) reject("source tar blob content differs from Git");
    }
    function consumePadding(size) {
      const extra = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
      if (extra) {
        readExactly(extra, small);
        if (small.subarray(0, extra).some((n) => n !== 0)) reject("nonzero tar padding");
      }
    }
    function paxAttributes(size) {
      if (size <= 0 || size > 64 * 1024) reject("unsupported PAX payload length");
      const data = Buffer.alloc(size);
      readExactly(size, data);
      consumePadding(size);
      const attributes = new Map();
      let offset = 0;
      while (offset < data.length) {
        const space = data.indexOf(0x20, offset);
        if (space < 0 || space - offset > 6) reject("malformed PAX record length");
        const digits = data.toString("ascii", offset, space);
        if (!/^[1-9][0-9]*$/u.test(digits)) reject("malformed PAX length");
        const sizeOfRecord = Number(digits);
        if (!Number.isSafeInteger(sizeOfRecord) || sizeOfRecord < space - offset + 4 ||
            offset + sizeOfRecord > data.length || data[offset + sizeOfRecord - 1] !== 0x0a) {
          reject("invalid PAX record framing");
        }
        const body = decode.decode(data.subarray(space + 1, offset + sizeOfRecord - 1));
        const separator = body.indexOf("=");
        if (separator < 1 || attributes.has(body.slice(0, separator))) reject("duplicate or malformed PAX key");
        attributes.set(body.slice(0, separator), body.slice(separator + 1));
        offset += sizeOfRecord;
      }
      return attributes;
    }
    while (position < length) {
      readExactly(TAR_BLOCK, small);
      if (small.every((value) => value === 0)) {
        // Two terminating NUL blocks followed solely by zero padding.
        if (localPath || seen.size !== expectedObjects.size || totalMembers === 0) {
          reject("source tar ends with missing or pending members");
        }
        let remaining = length - position;
        if (remaining < TAR_BLOCK) reject("missing tar end-of-archive block");
        while (remaining > 0) {
          const n = Math.min(remaining, READ_BLOCK);
          readExactly(n, chunk);
          if (chunk.subarray(0, n).some((value) => value !== 0)) reject("trailing tar payload");
          remaining -= n;
        }
        if (!sameStat(original, fstatSync(fd, { bigint: true })) ||
            !sameStat(original, lstatSync(filename, { bigint: true }))) {
          reject("source tar metadata changed during verification");
        }
        return Object.freeze({ sha256: archiveDigest.digest("hex"), sizeBytes: length });
      }
      const suppliedChecksum = octal(small, 148, 156);
      let computed = 0;
      for (let i = 0; i < TAR_BLOCK; i += 1) {
        computed += i >= 148 && i < 156 ? 32 : small[i];
      }
      if (suppliedChecksum !== computed || textField(small, 257, 263) !== "ustar" ||
          textField(small, 263, 265) !== "00") reject("invalid ustar header or checksum");
      // All headers, including PAX metadata, must retain Git archive's
      // deterministic owner/group and commit timestamp. Root tar extraction
      // can otherwise apply attacker-selected ownership or modification time
      // even when each Git blob's contents and pathname match exactly.
      if (octal(small, 108, 116) !== 0 || octal(small, 116, 124) !== 0 ||
          textField(small, 265, 297) !== "root" || textField(small, 297, 329) !== "root" ||
          octal(small, 329, 337) !== 0 || octal(small, 337, 345) !== 0 ||
          octal(small, 136, 148) !== expectedCommitTimestamp ||
          small.subarray(500, 512).some((value) => value !== 0)) {
        reject("source tar owner or extraction metadata differs from canonical Git archive");
      }
      const mode = octal(small, 100, 108);
      const size = octal(small, 124, 136);
      const kind = String.fromCharCode(small[156]);
      const prefix = textField(small, 345, 500);
      const headerName = textField(small, 0, 100);
      const rawName = prefix ? `${prefix}/${headerName}` : headerName;
      if (!rawName || size > length - position) reject("invalid tar name or member size");
      if (kind === "g" || kind === "x") {
        if (kind === "g" && (globalSeen || totalMembers > 0 || localPath)) {
          reject("unexpected global PAX metadata");
        }
        if (kind === "x" && localPath !== undefined) reject("stacked local PAX metadata");
        const attributes = paxAttributes(size);
        if (kind === "g") {
          globalSeen = true;
          if (attributes.size !== 1 || attributes.get("comment") !== expectedRevision) {
            reject("untrusted global PAX metadata");
          }
        } else {
          if (attributes.size !== 1 || !safeTreePath(attributes.get("path"))) {
            reject("untrusted local PAX metadata");
          }
          localPath = attributes.get("path");
        }
        continue;
      }
      const entry = localPath ?? rawName.replace(/\/$/u, "");
      localPath = undefined;
      if (!safeTreePath(entry) || seen.has(entry)) reject("unknown, unsafe or duplicate tar member");
      const expected = expectedObjects.get(entry);
      if (!expected) reject("source tar contains a member missing from Git");
      if (textField(small, 157, 257) !== "") reject("tar link target is unsupported");
      if (expected.type === "tree") {
        if (kind !== "5" || size !== 0 || ![0o755, 0o775].includes(mode)) {
          reject("Git tree directory type or mode differs");
        }
      } else {
        const expectedMode = expected.mode === "100755" ? 0o755 : 0o644;
        // Git's archive default tar.umask=0002 gives 0664/0775 rather than
        // 0644/0755. Only group-write may vary; executable bits must match.
        if (!["0", "\0"].includes(kind) || ![expectedMode, expectedMode | 0o020].includes(mode)) {
          reject("Git blob file type or mode differs");
        }
        dataHash(size, expected.id);
      }
      consumePadding(size);
      seen.add(entry);
      totalMembers += 1;
      if (totalMembers > expectedObjects.size) reject("excess tar member count");
    }
    reject("source tar lacks final zero terminator");
  } finally { closeSync(fd); }
}
