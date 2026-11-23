import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import path from "node:path";

export const OWNER_APPROVAL_DOMAIN = Buffer.from("VIRKI_C1_C4_OWNER_APPROVAL_V1\0", "utf8");
export const CANONICAL_CONTEXT_NAMES = Object.freeze([
  "source",
  "dockerfile",
  "offline-npm-cacache",
  "offline-prisma-engines",
]);
// Aligned with C1 FSSyncSealedV15 (64<<20) and C4 VIRKI_OWNER_MAX_PAYLOAD_BYTES (64*1024*1024).
export const C1_MAX_CONTEXT_BYTES = 64 * 1024 * 1024;
export const SIGN_ACK_DENIED_STATUS = 22;

const SHA256_HEX = /^[0-9a-f]{64}$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const GIT_SHA = /^[0-9a-f]{40}$/u;
const NONCE_HEX = /^[0-9a-f]{32}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const BASE64_SIG = /^[A-Za-z0-9+/]{86}==$/u;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const FORBIDDEN_KEY_PROPS = new Set(["ownerPrivateKey", "secretKey", "privateKey", "privateKeyPem", "signingKey"]);

function fail(reason) {
  throw new Error(`C1->C4 integration contract refused: ${reason}`);
}

function demand(ok, reason) {
  if (!ok) fail(reason);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    if (typeof value === "number") demand(Number.isFinite(value), "non-finite number in canonical JSON");
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  demand(isPlainObject(value), "non-plain object in canonical JSON");
  demand(!Object.hasOwn(value, "toJSON"), "custom toJSON forbidden in canonical JSON");
  const out = {};
  for (const key of Object.keys(value).sort()) {
    demand(!FORBIDDEN_KEYS.has(key), `forbidden key ${key}`);
    out[key] = canonicalize(value[key]);
  }
  return out;
}

export function canonicalJsonBytes(value) {
  return Buffer.from(JSON.stringify(canonicalize(value)), "utf8");
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function hasUnsafePathChar(p) {
  for (let i = 0; i < p.length; i++) {
    const c = p.charCodeAt(i);
    if (c < 32 || c === 127 || p[i] === "\\" || p[i] === "*" || p[i] === "?" || p[i] === "[" || p[i] === "]") {
      return true;
    }
  }
  return false;
}

function validateRelPath(p, label) {
  demand(
    typeof p === "string" &&
      p.length > 0 &&
      p.length <= 512 &&
      !hasUnsafePathChar(p) &&
      !p.startsWith("/") &&
      !p.split("/").some((seg) => seg === "" || seg === "." || seg === ".."),
    `${label} contains invalid, wildcard, control, or traversal path`,
  );
}

function pathsOverlap(a, b) {
  return a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`);
}

const CONTEXT_STREAM_PREFIX = Buffer.from("virki-context-stream-v1\0", "utf8");
const CONTEXT_TREE_PREFIX = Buffer.from("buildkit-worker-local-context-v2\0", "utf8");
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

// Mirror the bounded, byte-oriented C4 V3 stream/tree verification instead of
// confusing a SHA of caller-provided arbitrary bytes with a BuildKit tree.
// This does not attest the producer, filesystem custody or any release right.
function verifyCanonicalContextStream(buf, name, expectedEntries, expectedTreeDigest) {
  let at = 0;
  const take = (count) => {
    demand(Number.isSafeInteger(count) && count >= 0 && count <= buf.length - at,
      `canonical context ${name} stream truncated or malformed`);
    const part = buf.subarray(at, at + count);
    at += count;
    return part;
  };
  const uint64 = () => {
    const value = take(8).readBigUInt64BE();
    demand(value <= BigInt(Number.MAX_SAFE_INTEGER), `canonical context ${name} has oversized field`);
    return Number(value);
  };
  const sizedBytes = () => take(uint64());
  demand(take(CONTEXT_STREAM_PREFIX.length).equals(CONTEXT_STREAM_PREFIX),
    `canonical context ${name} stream prefix invalid`);
  demand(sizedBytes().equals(Buffer.from(name, "utf8")),
    `canonical context ${name} stream name invalid`);

  const tree = createHash("sha256").update(CONTEXT_TREE_PREFIX);
  const seenPaths = new Set();
  const activeDirectories = [];
  let previousSegments = null;
  let previousWasDirectory = false;
  let entries = 0;
  while (at < buf.length) {
    const kind = take(1);
    demand(kind[0] === 0x44 || kind[0] === 0x4c || kind[0] === 0x46,
      `canonical context ${name} entry kind invalid`);
    const pathBytes = sizedBytes();
    // TextDecoder strips an initial UTF-8 BOM by default, silently changing
    // the pathname whose raw bytes are bound into the C1/C4 tree hash. Reject
    // this alias before decoding so the Node receipt and native C4 agree.
    demand(!(pathBytes.length >= 3 && pathBytes[0] === 0xef &&
      pathBytes[1] === 0xbb && pathBytes[2] === 0xbf),
    `canonical context ${name} entry path has leading UTF-8 BOM`);
    let relPath;
    try { relPath = UTF8_DECODER.decode(pathBytes); } catch { fail(`canonical context ${name} entry path is not UTF-8`); }
    validateRelPath(relPath, `canonical context ${name} entry path`);
    demand(!seenPaths.has(relPath), `canonical context ${name} entry path duplicated`);
    seenPaths.add(relPath);
    // BuildKit's producer uses Go filepath.WalkDir: parent directories must
    // precede their children, with depth-first traversal and byte-sorted
    // basenames. A digest of arbitrary tagged records is not proof of a
    // canonical FileSync context, even if its SHA-256 is self-consistent.
    const segments = relPath.split("/");
    const parent = segments.slice(0, -1).join("/");
    while (activeDirectories.length > 0 && activeDirectories.at(-1) !== parent) {
      activeDirectories.pop();
    }
    demand(parent === "" || activeDirectories.at(-1) === parent,
      `canonical context ${name} parent invalid`);
    if (previousSegments !== null) {
      let shared = 0;
      while (shared < segments.length && shared < previousSegments.length &&
        segments[shared] === previousSegments[shared]) shared++;
      if (shared === previousSegments.length) {
        demand(previousWasDirectory && segments.length === previousSegments.length + 1,
          `canonical context ${name} traversal invalid`);
      } else {
        demand(shared < segments.length &&
          Buffer.compare(Buffer.from(previousSegments[shared], "utf8"),
            Buffer.from(segments[shared], "utf8")) < 0,
        `canonical context ${name} traversal invalid`);
      }
    }
    if (kind[0] === 0x44) activeDirectories.push(relPath);
    previousSegments = segments;
    previousWasDirectory = kind[0] === 0x44;
    const mode = uint64();
    demand(mode <= 0o7777, `canonical context ${name} entry mode invalid`);
    const sized = (bytes) => {
      const length = Buffer.alloc(8);
      length.writeBigUInt64BE(BigInt(bytes.length));
      tree.update(length).update(bytes);
    };
    const rawMode = Buffer.alloc(8);
    rawMode.writeBigUInt64BE(BigInt(mode));
    tree.update(kind);
    sized(pathBytes);
    tree.update(rawMode);
    if (kind[0] !== 0x44) {
      const size = uint64();
      const payload = take(size);
      const sizeBytes = Buffer.alloc(8);
      sizeBytes.writeBigUInt64BE(BigInt(size));
      tree.update(sizeBytes);
      if (kind[0] === 0x4c) {
        demand(size > 0 && !payload.includes(0), `canonical context ${name} link invalid`);
        tree.update(payload);
      } else {
        tree.update(createHash("sha256").update(payload).digest());
      }
    }
    entries++;
    demand(entries <= expectedEntries, `canonical context ${name} entryCount mismatch`);
  }
  demand(entries === expectedEntries, `canonical context ${name} entryCount mismatch`);
  demand(`sha256:${tree.digest("hex")}` === expectedTreeDigest, `${name} treeDigest mismatch`);
}

/** 1. Build input & artifact provenance (C1/C4 64 MiB ceiling + 4 canonical contexts). */
export function verifyBuildInputProvenance(contract, contextBuffers = {}) {
  demand(isPlainObject(contract), "contract must be a plain object");
  demand(GIT_SHA.test(contract.c1BaseSha ?? ""), "invalid c1BaseSha");
  demand(GIT_SHA.test(contract.c4BaseSha ?? ""), "invalid c4BaseSha");
  demand(GIT_SHA.test(contract.sourceCommit ?? ""), "invalid sourceCommit");
  demand(SHA256_HEX.test(contract.buildPlanSha256 ?? ""), "invalid buildPlanSha256");
  demand(SHA256_HEX.test(contract.executablePolicySha256 ?? ""), "invalid executablePolicySha256");
  demand(SHA256_HEX.test(contract.fileSyncManifestSha256 ?? ""), "invalid fileSyncManifestSha256");
  demand(NONCE_HEX.test(contract.nonce ?? ""), "invalid nonce");
  demand(Number.isSafeInteger(contract.epoch) && contract.epoch >= 1, "invalid epoch");
  demand(contract.role === "runtime" || contract.role === "migrator", "invalid role");

  const contexts = contract.contexts;
  demand(Array.isArray(contexts) && contexts.length === CANONICAL_CONTEXT_NAMES.length, "must supply 4 canonical contexts");
  for (let i = 0; i < CANONICAL_CONTEXT_NAMES.length; i++) {
    const ctx = contexts[i];
    const expectedName = CANONICAL_CONTEXT_NAMES[i];
    demand(isPlainObject(ctx) && ctx.name === expectedName, `context[${i}] must be plain object ${expectedName}`);
    demand(SHA256_DIGEST.test(ctx.treeDigest ?? ""), `${expectedName} invalid treeDigest`);
    demand(SHA256_DIGEST.test(ctx.streamDigest ?? ""), `${expectedName} invalid streamDigest`);
    demand(
      Number.isSafeInteger(ctx.streamLength) && ctx.streamLength > 0 && ctx.streamLength <= C1_MAX_CONTEXT_BYTES,
      `${expectedName} streamLength out of 64 MiB bounds`,
    );
    demand(Number.isSafeInteger(ctx.entryCount) && ctx.entryCount >= 1, `${expectedName} invalid entryCount`);

    const buf = contextBuffers[expectedName];
    demand(Buffer.isBuffer(buf), `missing synthetic context bytes for ${expectedName}`);
    demand(buf.length === ctx.streamLength, `${expectedName} byte length mismatch`);
    demand(`sha256:${sha256Hex(buf)}` === ctx.streamDigest, `${expectedName} streamDigest mismatch`);
    verifyCanonicalContextStream(buf, expectedName, ctx.entryCount, ctx.treeDigest);
  }
}

/** 2. FileSync manifest & ignore-rule consistency. */
export function verifyFileSyncManifestConsistency(manifest, expectedManifestSha256) {
  demand(isPlainObject(manifest), "fileSyncManifest must be a plain object");
  demand(manifest.ignoreSource === "dockerfile-local" || manifest.ignoreSource === "root-dockerignore", "invalid ignoreSource");
  demand(SHA256_HEX.test(manifest.ignoreRulesSha256 ?? ""), "invalid ignoreRulesSha256");
  demand(Array.isArray(manifest.includedPaths) && manifest.includedPaths.length > 0, "includedPaths must be non-empty");
  demand(Array.isArray(manifest.excludedPaths), "excludedPaths must be an array");

  const included = [];
  const includedSet = new Set();
  for (const p of manifest.includedPaths) {
    validateRelPath(p, "includedPaths");
    demand(!includedSet.has(p), `duplicate includedPath: ${p}`);
    includedSet.add(p);
    included.push(p);
  }
  const excludedSet = new Set();
  for (const p of manifest.excludedPaths) {
    validateRelPath(p, "excludedPaths");
    demand(!excludedSet.has(p), `duplicate excludedPath: ${p}`);
    for (const inc of included) {
      demand(!pathsOverlap(inc, p), `ignore-rule conflict: ${inc} overlaps excluded ${p}`);
    }
    excludedSet.add(p);
  }

  const digest = sha256Hex(canonicalJsonBytes({
    ignoreSource: manifest.ignoreSource,
    ignoreRulesSha256: manifest.ignoreRulesSha256,
    includedPaths: [...included].sort(),
    excludedPaths: [...excludedSet].sort(),
  }));
  demand(SHA256_HEX.test(expectedManifestSha256 ?? "") && digest === expectedManifestSha256, "fileSyncManifestSha256 mismatch");
  return digest;
}

/** 3. Output identity & non-publishing receipt verification. */
export function verifyOutputAndReceipt(output) {
  demand(isPlainObject(output), "output must be a plain object");
  demand(SHA256_DIGEST.test(output.outputImageId ?? ""), "invalid outputImageId");
  demand(SHA256_DIGEST.test(output.ociManifestDigest ?? ""), "invalid ociManifestDigest");
  demand(output.exporterMode === "staged-nonpublishing", "unsafe exporterMode: publishing/store must remain disabled");
  demand(isPlainObject(output.exporterFlags) &&
    output.exporterFlags.store === false &&
    output.exporterFlags.push === false &&
    output.exporterFlags.pushByDigest === false &&
    output.exporterFlags.unpack === false, "exporterFlags must disable store/push/unpack");
  demand(output.workerReceiptPairAdmitted === false, "workerReceiptPairAdmitted must remain false");
  demand(output.deployAuthorized === false, "deployAuthorized must remain false");
  demand(isPlainObject(output.workerReceipt), "missing workerReceipt");
  demand(typeof output.workerReceipt.workerIdentity === "string" && output.workerReceipt.workerIdentity.length > 0, "invalid workerIdentity");
  demand(SHA256_HEX.test(output.workerReceipt.receiptSha256 ?? ""), "invalid receiptSha256");
}

/** 7. Identity & key custody separation. */
export function verifyIdentityCustodySeparation(custody) {
  demand(isPlainObject(custody), "custody must be a plain object");
  for (const key of Object.keys(custody)) {
    demand(!FORBIDDEN_KEY_PROPS.has(key), `private key material forbidden in custody (${key})`);
  }
  for (const field of ["ownerUid", "ownerGid", "buildkitDaemonUid", "buildkitDaemonGid", "workerUid", "workerGid"]) {
    const val = custody[field];
    demand(Number.isSafeInteger(val) && val > 0 && val <= 0xffffffff && val !== 65534, `${field} must be a non-root/non-nobody uint32`);
  }
  demand(custody.ownerUid !== custody.buildkitDaemonUid, "ownerUid and buildkitDaemonUid must be distinct");
  demand(custody.ownerUid !== custody.workerUid, "ownerUid and workerUid must be distinct");
  demand(custody.buildkitDaemonUid !== custody.workerUid, "buildkitDaemonUid and workerUid must be distinct");
  demand(custody.ownerGid !== custody.buildkitDaemonGid, "ownerGid and buildkitDaemonGid must be distinct");
  demand(custody.ownerGid !== custody.workerGid, "ownerGid and workerGid must be distinct");
  demand(custody.buildkitDaemonGid !== custody.workerGid, "buildkitDaemonGid and workerGid must be distinct");
  demand(custody.keyCustodyMode === "isolated-spki-pin", "keyCustodyMode must be isolated-spki-pin");
}

/** 4. Cryptographic owner-authorization contract (domain-separated Ed25519 + SPKI pin + revocations). */
export function verifyOwnerAuthorizationEnvelope({ contractDigestHex, approval, policy }) {
  demand(SHA256_HEX.test(contractDigestHex ?? ""), "invalid contractDigestHex");
  demand(isPlainObject(approval), "approval must be a plain object");
  demand(isPlainObject(policy), "policy must be a plain object");
  demand(KEY_ID.test(approval.keyId ?? ""), "invalid approval.keyId");
  demand(BASE64_SIG.test(approval.signatureBase64 ?? ""), "invalid approval.signatureBase64");
  demand(approval.contractSha256 === contractDigestHex, "approval.contractSha256 mismatch");

  demand(Array.isArray(policy.revokedKeyIds), "policy.revokedKeyIds must be an array");
  demand(Array.isArray(policy.revokedPinsSha256), "policy.revokedPinsSha256 must be an array");
  const revokedIds = new Set(policy.revokedKeyIds);
  const revokedPins = new Set();
  for (const pin of policy.revokedPinsSha256) {
    demand(SHA256_HEX.test(pin ?? ""), "invalid revokedPinsSha256 entry");
    revokedPins.add(pin);
  }
  demand(!revokedIds.has(approval.keyId), "owner keyId is revoked");

  demand(isPlainObject(policy.owner) && policy.owner.keyId === approval.keyId, "approval keyId does not match pinned owner policy");
  demand(SHA256_HEX.test(policy.owner.pinSha256 ?? ""), "invalid policy.owner.pinSha256");
  demand(!revokedPins.has(policy.owner.pinSha256), "owner SPKI pin is revoked");
  demand(typeof policy.owner.publicKeyPem === "string" &&
    !/PRIVATE KEY/u.test(policy.owner.publicKeyPem), "private key PEM forbidden in policy.owner");

  const pubKey = createPublicKey(policy.owner.publicKeyPem);
  demand(pubKey.type === "public" && pubKey.asymmetricKeyType === "ed25519", "owner key must be public Ed25519");
  const actualPin = sha256Hex(pubKey.export({ type: "spki", format: "der" }));
  demand(actualPin === policy.owner.pinSha256, "owner SPKI pin mismatch");

  const msg = Buffer.concat([OWNER_APPROVAL_DOMAIN, Buffer.from(contractDigestHex, "utf8")]);
  const ok = verify(null, msg, pubKey, Buffer.from(approval.signatureBase64, "base64"));
  demand(ok, "owner Ed25519 signature verification failed");
}

function anchorDigest(anchorSha) {
  return sha256Hex(Buffer.from(`VIRKI_C1_C4_ANCHOR:${anchorSha}`, "utf8"));
}

function fsyncParentDir(filePath) {
  if (process.platform === "win32") return;
  const dirFd = openSync(path.dirname(filePath), constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0));
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

function writeAllSync(fd, buf) {
  let offset = 0;
  while (offset < buf.length) {
    const written = writeSync(fd, buf, offset, buf.length - offset);
    demand(written > 0, "short write on auth state");
    offset += written;
  }
}

function writeAtomicState(filePath, nextState) {
  // A successful rename is not necessarily a durable commit until its parent
  // directory fsync succeeds. Previously an EIO at that final fsync returned
  // an error yet allowed a different authorization transition on restart.
  // Persist an independent fail-closed intent BEFORE touching the state. A
  // crash or ambiguous fsync keeps the marker and requires manual reconciliation.
  const pendingPath = `${filePath}.pending`;
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
  const pendingFd = openSync(pendingPath, flags, 0o600);
  try {
    fsyncSync(pendingFd);
  } finally {
    closeSync(pendingFd);
  }
  fsyncParentDir(filePath);

  const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  const fd = openSync(tmpPath, flags, 0o600);
  try {
    const data = canonicalJsonBytes(nextState);
    writeAllSync(fd, data);
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    try { unlinkSync(tmpPath); } catch (_cleanupErr) { void _cleanupErr; }
    throw err;
  }
  closeSync(fd);
  renameSync(tmpPath, filePath);
  fsyncParentDir(filePath);
  unlinkSync(pendingPath);
  try {
    fsyncParentDir(filePath);
  } catch (error) {
    // An unlink followed by an ambiguous directory fsync may already have
    // removed the only crash-recovery fence. Restore and sync it before
    // allowing any new transaction to inspect this state. If the filesystem
    // cannot persist this marker, fail rather than manufacture durability.
    try {
      const restoreFd = openSync(pendingPath, flags, 0o600);
      try {
        fsyncSync(restoreFd);
      } finally {
        closeSync(restoreFd);
      }
      fsyncParentDir(filePath);
    } catch (restoreError) {
      throw new AggregateError([error, restoreError],
        "C1->C4 ambiguous final intent fsync: durable recovery fence unavailable", { cause: restoreError });
    }
    throw error;
  }
}

function assertNoAmbiguousStateTransition(filePath) {
  try {
    // lstat, not exists: a dangling symlink or other substituted marker is
    // itself a reason to refuse, never evidence that the intent is absent.
    lstatSync(`${filePath}.pending`);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  fail("ambiguous auth state transition pending manual reconciliation");
}

function withAuthStateLock(filePath, fn) {
  const lockPath = `${filePath}.lock`;
  if (process.platform === "linux") {
    // Keep one stable inode; the kernel releases the lock when the last FD closes.
    const fd = openSync(lockPath, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
    try {
      const st = fstatSync(fd);
      demand(st.isFile() && st.nlink === 1 && st.uid === process.getuid() && (st.mode & 0o077) === 0, "auth state lock must be a private regular file");
      execFileSync("/usr/bin/flock", ["--exclusive", "--timeout", "5", "3"], { stdio: ["ignore", "ignore", "pipe", fd], timeout: 6000 });
      return fn();
    } finally {
      closeSync(fd);
    }
  }

  // Non-Linux development has no kernel flock; refuse abandoned locks rather than guess ownership.
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
  const deadline = performance.now() + 5000;
  let fd;
  for (;;) {
    try {
      fd = openSync(lockPath, flags, 0o600);
      break;
    } catch (err) {
      if (err?.code !== "EEXIST" || performance.now() >= deadline) throw err;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  try {
    return fn();
  } finally {
    closeSync(fd);
    unlinkSync(lockPath);
  }
}

/** 5 & 6. Persistent hash-chained state, recovery fencing, and anti-rollback witness. */
export function initAnchoredAuthState(filePath, anchorSha) {
  demand(GIT_SHA.test(anchorSha ?? ""), "anchorSha must be a 40-char lowercase git SHA");
  const initial = {
    version: 1,
    anchorSha,
    currentEpoch: 1,
    sequenceFloor: 0,
    faulted: false,
    headEntrySha256: anchorDigest(anchorSha),
    entries: [],
  };
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
  const fd = openSync(filePath, flags, 0o600);
  try {
    const data = canonicalJsonBytes(initial);
    writeAllSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncParentDir(filePath);
  return initial;
}

export function loadAndVerifyAuthState(filePath) {
  assertNoAmbiguousStateTransition(filePath);
  const fd = openSync(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  let raw;
  try {
    const st = fstatSync(fd);
    demand(st.isFile() && st.nlink === 1, "auth state must be a regular non-linked file");
    raw = readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
  assertNoAmbiguousStateTransition(filePath);
  const state = JSON.parse(raw);
  demand(isPlainObject(state) && state.version === 1 && GIT_SHA.test(state.anchorSha ?? ""), "invalid auth state header");
  demand(typeof state.faulted === "boolean", "missing faulted flag");
  demand(Number.isSafeInteger(state.currentEpoch) && state.currentEpoch >= 1, "invalid state.currentEpoch");
  demand(Array.isArray(state.entries), "state.entries must be an array");

  let expectedPrev = anchorDigest(state.anchorSha);
  let lastSeq = 0;
  let maxEpoch = 1;
  const preparedNonces = new Set();
  const activeScopes = new Map();
  for (const entry of state.entries) {
    demand(isPlainObject(entry), "auth state entry must be an object");
    demand(entry.prevEntrySha256 === expectedPrev, "auth state hash chain broken");
    demand(Number.isSafeInteger(entry.sequence) && entry.sequence === lastSeq + 1, "auth state sequence gap");
    demand(Number.isSafeInteger(entry.epoch) && entry.epoch >= maxEpoch && entry.epoch <= state.currentEpoch, "auth state epoch out of bounds");
    demand(entry.status === "PREPARED" || entry.status === "ABORTED" || entry.status === "EPOCH_ADVANCE", "invalid auth state entry status");
    demand(NONCE_HEX.test(entry.nonce ?? ""), "invalid auth state entry nonce");
    demand(SHA256_HEX.test(entry.contractSha256 ?? ""), "invalid auth state entry contractSha256");

    if (entry.status === "PREPARED") {
      demand(!preparedNonces.has(entry.nonce), "auth state nonce replay");
      preparedNonces.add(entry.nonce);
      activeScopes.set(`${entry.epoch}:${entry.nonce}`, entry.contractSha256);
    } else if (entry.status === "ABORTED") {
      const key = `${entry.epoch}:${entry.nonce}`;
      demand(activeScopes.get(key) === entry.contractSha256, "ABORTED without matching active PREPARED scope");
      activeScopes.delete(key);
    }

    const recomputed = sha256Hex(canonicalJsonBytes({
      prevEntrySha256: entry.prevEntrySha256,
      sequence: entry.sequence,
      epoch: entry.epoch,
      nonce: entry.nonce,
      contractSha256: entry.contractSha256,
      status: entry.status,
    }));
    demand(recomputed === entry.entrySha256, "auth state entry digest tampered");
    expectedPrev = entry.entrySha256;
    lastSeq = entry.sequence;
    maxEpoch = entry.epoch;
  }
  demand(state.currentEpoch === maxEpoch || state.entries.length === 0, "currentEpoch mismatches hash-chained epoch history");
  demand(state.headEntrySha256 === expectedPrev && state.sequenceFloor === lastSeq, "auth state head/sequence mismatch");
  return state;
}

export function appendAuthStateTransition(filePath, { epoch, nonce, contractSha256, status }) {
  return withAuthStateLock(filePath, () => {
    const state = loadAndVerifyAuthState(filePath);
    demand(!state.faulted, "auth state is faulted; mutations fenced");
    demand(epoch === state.currentEpoch, "stale or future epoch");
    demand(status === "PREPARED" || status === "ABORTED", "only non-authorizing PREPARED/ABORTED transitions permitted");
    demand(NONCE_HEX.test(nonce ?? ""), "invalid nonce");
    demand(SHA256_HEX.test(contractSha256 ?? ""), "invalid contractSha256");

    if (status === "PREPARED") {
      demand(!state.entries.some((e) => e.status === "PREPARED" && e.nonce === nonce), "auth state nonce replay");
    } else {
      const prepared = state.entries.some((e) => e.status === "PREPARED" && e.epoch === epoch && e.nonce === nonce && e.contractSha256 === contractSha256);
      const alreadyAborted = state.entries.some((e) => e.status === "ABORTED" && e.epoch === epoch && e.nonce === nonce);
      demand(prepared && !alreadyAborted, "ABORTED requires active matching PREPARED entry");
    }

    const sequence = state.sequenceFloor + 1;
    const prevEntrySha256 = state.headEntrySha256;
    const entrySha256 = sha256Hex(canonicalJsonBytes({ prevEntrySha256, sequence, epoch, nonce, contractSha256, status }));
    const nextState = {
      ...state,
      sequenceFloor: sequence,
      headEntrySha256: entrySha256,
      entries: [...state.entries, { prevEntrySha256, sequence, epoch, nonce, contractSha256, status, entrySha256 }],
    };
    writeAtomicState(filePath, nextState);
    return nextState;
  });
}

export function recoverAuthStateWithEpochFence(filePath) {
  return withAuthStateLock(filePath, () => {
    const state = loadAndVerifyAuthState(filePath);
    demand(!state.faulted, "faulted auth state cannot be recovered without operator reconciliation");
    const nextEpoch = state.currentEpoch + 1;
    const sequence = state.sequenceFloor + 1;
    const prevEntrySha256 = state.headEntrySha256;
    const nonce = "0".repeat(32);
    const contractSha256 = "0".repeat(64);
    const status = "EPOCH_ADVANCE";
    const entrySha256 = sha256Hex(canonicalJsonBytes({ prevEntrySha256, sequence, epoch: nextEpoch, nonce, contractSha256, status }));
    const fenced = {
      ...state,
      currentEpoch: nextEpoch,
      sequenceFloor: sequence,
      headEntrySha256: entrySha256,
      entries: [...state.entries, { prevEntrySha256, sequence, epoch: nextEpoch, nonce, contractSha256, status, entrySha256 }],
    };
    writeAtomicState(filePath, fenced);
    return fenced;
  });
}

export function verifyAntiRollbackWitness(state, witness) {
  demand(isPlainObject(witness), "witness must be a plain object");
  demand(Number.isSafeInteger(witness.minEpoch) && witness.minEpoch >= 1, "invalid witness.minEpoch");
  demand(Number.isSafeInteger(witness.minSequence) && witness.minSequence >= 0, "invalid witness.minSequence");
  demand(SHA256_HEX.test(witness.expectedHeadSha256 ?? ""), "invalid witness.expectedHeadSha256");
  demand(state.currentEpoch >= witness.minEpoch, "rollback detected: epoch behind witness");
  demand(state.sequenceFloor >= witness.minSequence, "rollback detected: sequence behind witness");
  const digestAtMinSeq = witness.minSequence === 0
    ? anchorDigest(state.anchorSha)
    : state.entries[witness.minSequence - 1]?.entrySha256;
  demand(digestAtMinSeq === witness.expectedHeadSha256, "rollback/fork detected: head digest mismatch at witness sequence");
}

export function computeBoundContractDigest({ contract, output, custody }) {
  return sha256Hex(canonicalJsonBytes({
    contract,
    outputBinding: {
      outputImageId: output.outputImageId,
      ociManifestDigest: output.ociManifestDigest,
      exporterMode: output.exporterMode,
      receiptSha256: output.workerReceipt.receiptSha256,
    },
    custodyBinding: {
      ownerUid: custody.ownerUid,
      ownerGid: custody.ownerGid,
      buildkitDaemonUid: custody.buildkitDaemonUid,
      buildkitDaemonGid: custody.buildkitDaemonGid,
      workerUid: custody.workerUid,
      workerGid: custody.workerGid,
      keyCustodyMode: custody.keyCustodyMode,
    },
  }));
}

export function evaluateC1ToC4IntegrationCandidate({
  contract,
  contextBuffers,
  fileSyncManifest,
  output,
  custody,
  approval,
  policy,
  stateFilePath,
  witness,
}) {
  verifyBuildInputProvenance(contract, contextBuffers);
  const manifestSha = verifyFileSyncManifestConsistency(fileSyncManifest, contract.fileSyncManifestSha256);
  verifyOutputAndReceipt(output);
  verifyIdentityCustodySeparation(custody);
  const contractDigestHex = computeBoundContractDigest({ contract, output, custody });
  verifyOwnerAuthorizationEnvelope({ contractDigestHex, approval, policy });

  const state = loadAndVerifyAuthState(stateFilePath);
  demand(!state.faulted, "auth state is faulted");
  demand(contract.epoch === state.currentEpoch, "contract epoch does not match active state epoch");
  demand(contract.sourceCommit === state.anchorSha, "contract sourceCommit does not match state anchorSha");
  const hasPrepared = state.entries.some((e) => e.status === "PREPARED" && e.epoch === contract.epoch && e.nonce === contract.nonce && e.contractSha256 === contractDigestHex);
  const isAborted = state.entries.some((e) => e.status === "ABORTED" && e.epoch === contract.epoch && e.nonce === contract.nonce);
  demand(hasPrepared && !isAborted, "contract has no active PREPARED authorization scope");

  verifyAntiRollbackWitness(state, witness);
  return Object.freeze({
    status: "DEFENSIVE_VERIFIED_NON_AUTHORIZING",
    deployAuthorized: false,
    workerReceiptPairAdmitted: false,
    signAckStatus: SIGN_ACK_DENIED_STATUS,
    contractSha256: contractDigestHex,
    fileSyncManifestSha256: manifestSha,
    epoch: state.currentEpoch,
    sequenceFloor: state.sequenceFloor,
    headEntrySha256: state.headEntrySha256,
  });
}
