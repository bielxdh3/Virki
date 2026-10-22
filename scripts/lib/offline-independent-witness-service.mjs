import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import {
  closeSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync,
  readFileSync, readdirSync, realpathSync, unlinkSync, writeSync,
} from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Disposable Linux witness only. No release or Docker authorization is granted.
export const WITNESS_CAS_DOMAIN = "VIRKI_OFFLINE_INDEPENDENT_WITNESS_CAS_V1";
export const WITNESS_READ_DOMAIN = "VIRKI_OFFLINE_INDEPENDENT_WITNESS_HEAD_V1";
export const GENESIS_HEAD = "0".repeat(40);
export const GENESIS_RECEIPT = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const MAX_EVENTS = 4096;
const CAS_FIELDS = [
  "version", "domain", "challenge", "requestId", "hostIdentitySha256", "ledgerIdSha256",
  "expectedSequence", "expectedHeadSha", "expectedReceiptSha256", "nextHeadSha", "transitionSha256",
];
const AUTHORIZED_CAS_FIELDS = [...CAS_FIELDS, "ownerExpiresAt", "ownerSignature"];
const OWNER_CAS_PREFIX = Buffer.from("Virki/offline-independent-witness/owner-cas-v1\0");
const HEAD_FIELDS = ["version", "domain", "challenge", "hostIdentitySha256", "ledgerIdSha256"];
const RECEIPT_FIELDS = [
  "version", "domain", "challenge", "requestId", "hostIdentitySha256", "ledgerIdSha256",
  "sequence", "priorHeadSha", "headSha", "previousReceiptSha256", "transitionSha256",
  "issuedAt", "expiresAt",
];
const READ_FIELDS = [
  "version", "domain", "challenge", "hostIdentitySha256", "ledgerIdSha256",
  "sequence", "headSha", "receiptSha256", "issuedAt", "expiresAt",
];

function requireWitness(ok, explanation) {
  if (!ok) throw new Error(`Independent witness refused: ${explanation}`);
}

function exactFields(value, fields) {
  requireWitness(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field)), "invalid protocol fields");
}

const digest = (value) => createHash("sha256").update(value).digest("hex");
const receiptHash = (message, signature) => digest(JSON.stringify({ message, signature }));

function verifyPrivateFile(file) {
  requireWitness(isAbsolute(file), "key path must be absolute");
  const stats = lstatSync(file);
  requireWitness(stats.isFile() && !stats.isSymbolicLink() && stats.uid === process.getuid() &&
    (stats.mode & 0o077) === 0, "signer key must be owner-controlled regular file (0600)");
  return readFileSync(file);
}

function verifyPrivateDirectory(path) {
  requireWitness(isAbsolute(path), "store paths must be absolute");
  const stats = lstatSync(path);
  requireWitness(stats.isDirectory() && !stats.isSymbolicLink() &&
    stats.uid === process.getuid() && (stats.mode & 0o077) === 0,
  "witness directory requires owner-only permissions (0700)");
}

function isWithin(path, parent) {
  return path === parent || path.startsWith(`${parent}${sep}`);
}

function auditReceipt(message, signature, key) {
  exactFields(message, RECEIPT_FIELDS);
  requireWitness(message.version === 1 && message.domain === WITNESS_CAS_DOMAIN &&
    HEX64.test(message.challenge) && HEX64.test(message.requestId) &&
    HEX64.test(message.hostIdentitySha256) && HEX64.test(message.ledgerIdSha256) &&
    HEX40.test(message.priorHeadSha) && HEX40.test(message.headSha) &&
    HEX64.test(message.previousReceiptSha256) && HEX64.test(message.transitionSha256) &&
    Number.isSafeInteger(message.sequence) && message.sequence > 0 && message.sequence <= MAX_EVENTS &&
    Number.isSafeInteger(message.issuedAt) && Number.isSafeInteger(message.expiresAt) &&
    message.expiresAt === message.issuedAt + 30 && B64.test(signature) &&
    Buffer.from(signature, "base64").toString("base64") === signature &&
    verify(null, Buffer.from(JSON.stringify(message)), key, Buffer.from(signature, "base64")),
  "invalid signed history receipt");
}

export function verifyIndependentWitnessCasReceipt({ receipt, publicKeyPem, pinSha256, request,
  nowSeconds = Math.floor(Date.now() / 1000) }) {
  const key = createPublicKey(publicKeyPem);
  requireWitness(key.asymmetricKeyType === "ed25519" && HEX64.test(pinSha256) &&
    digest(key.export({ format: "der", type: "spki" })) === pinSha256, "invalid verifier pin");
  exactFields(receipt, ["message", "signature", "receiptSha256"]);
  auditReceipt(receipt.message, receipt.signature, key);
  exactFields(request, AUTHORIZED_CAS_FIELDS);
  const m = receipt.message;
  requireWitness(m.challenge === request.challenge && m.requestId === request.requestId &&
    m.hostIdentitySha256 === request.hostIdentitySha256 && m.ledgerIdSha256 === request.ledgerIdSha256 &&
    m.sequence === request.expectedSequence + 1 && m.priorHeadSha === request.expectedHeadSha &&
    m.headSha === request.nextHeadSha && m.previousReceiptSha256 === request.expectedReceiptSha256 &&
    m.transitionSha256 === request.transitionSha256 &&
    Number.isSafeInteger(nowSeconds) && m.issuedAt <= nowSeconds &&
    nowSeconds < m.expiresAt && m.issuedAt >= nowSeconds - 30 &&
    receiptHash(m, receipt.signature) === receipt.receiptSha256, "CAS proof mismatch");
  return Object.freeze({
    sequence: m.sequence, headSha: m.headSha, receiptSha256: receipt.receiptSha256,
    witnessCasAuthorized: false, dockerLoadAuthorized: false, deployAuthorized: false,
  });
}

function buildReceipt(message, key) {
  const signature = sign(null, Buffer.from(JSON.stringify(message)), key).toString("base64");
  return { message, signature, receiptSha256: receiptHash(message, signature) };
}

function canonicalRequest(value, allowed, domain, host, ledger) {
  exactFields(value, allowed);
  requireWitness(value.version === 1 && value.domain === domain && HEX64.test(value.challenge) &&
    value.hostIdentitySha256 === host && value.ledgerIdSha256 === ledger,
  "scope, challenge or protocol mismatch");
}

export function ownerWitnessCasSigningBytes(request) {
  const body = {};
  for (const field of CAS_FIELDS) body[field] = request[field];
  body.ownerExpiresAt = request.ownerExpiresAt;
  return Buffer.concat([OWNER_CAS_PREFIX, Buffer.from(JSON.stringify(body))]);
}

export class IndependentOfflineWitness {
  constructor({ directory, anchorDirectory, keyFile, expectedKeyPinSha256,
    ownerPublicKeyFile, expectedOwnerKeyPinSha256,
    hostIdentitySha256, ledgerIdSha256, repositoryDirectory } = {}) {
    requireWitness(process.platform === "linux" && process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE === "1",
      "Linux disposable fixture is required");
    requireWitness(HEX64.test(hostIdentitySha256) && HEX64.test(ledgerIdSha256) &&
      HEX64.test(expectedKeyPinSha256), "invalid operator-pinned witness identity");
    for (const folder of [directory, anchorDirectory]) verifyPrivateDirectory(folder);
    const store = realpathSync(directory);
    const anchors = realpathSync(anchorDirectory);
    const signer = realpathSync(keyFile);
    const ownerKeyFile = realpathSync(ownerPublicKeyFile);
    requireWitness(store !== anchors && !isWithin(store, anchors) && !isWithin(anchors, store),
      "anchor and database directories must be distinct");
    if (repositoryDirectory) {
      const repository = realpathSync(repositoryDirectory);
      requireWitness(!isWithin(store, repository) && !isWithin(anchors, repository) &&
        !isWithin(signer, repository) && !isWithin(ownerKeyFile, repository),
      "witness authority must live outside repository");
    }
    const privateKey = createPrivateKey(verifyPrivateFile(keyFile));
    requireWitness(privateKey.asymmetricKeyType === "ed25519", "Ed25519 signing key required");
    const publicKey = createPublicKey(privateKey);
    const actualPin = digest(publicKey.export({ format: "der", type: "spki" }));
    requireWitness(actualPin === expectedKeyPinSha256, "witness signer does not match operator pin");
    requireWitness(HEX64.test(expectedOwnerKeyPinSha256), "independent owner signer pin missing");
    const ownerPublicKey = createPublicKey(verifyPrivateFile(ownerPublicKeyFile));
    requireWitness(ownerPublicKey.asymmetricKeyType === "ed25519" &&
      digest(ownerPublicKey.export({ format: "der", type: "spki" })) === expectedOwnerKeyPinSha256 &&
      expectedOwnerKeyPinSha256 !== actualPin && ownerKeyFile !== signer,
    "distinct independently pinned owner authorization key required");
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.ownerPublicKey = ownerPublicKey;
    this.ownerKeyPin = expectedOwnerKeyPinSha256;
    this.anchorDirectory = anchors;
    // Never publish partially written receipt bytes under a final anchor name.
    // Scratch files can be abandoned on crash and have no authority.
    this.anchorStagingDirectory = resolve(anchors, ".staging");
    try { mkdirSync(this.anchorStagingDirectory, { mode: 0o700 }); }
    catch (error) { if (error.code !== "EEXIST") throw error; }
    verifyPrivateDirectory(this.anchorStagingDirectory);
    this.hostIdentitySha256 = hostIdentitySha256;
    this.ledgerIdSha256 = ledgerIdSha256;
    this.db = new DatabaseSync(resolve(store, "witness.sqlite"), { timeout: 5000 });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");
    this.db.exec("CREATE TABLE IF NOT EXISTS scope (id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, ledger TEXT NOT NULL, signer TEXT NOT NULL, owner TEXT NOT NULL)");
    this.db.exec("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, challenge TEXT UNIQUE NOT NULL, message TEXT NOT NULL, signature TEXT NOT NULL)");
    this.db.prepare("INSERT OR IGNORE INTO scope(id,host,ledger,signer,owner) VALUES(1,?,?,?,?)")
      .run(hostIdentitySha256, ledgerIdSha256, actualPin, expectedOwnerKeyPinSha256);
    this.withExclusiveSnapshot(() => this.audit());
  }

  withExclusiveSnapshot(action) {
    this.db.exec("BEGIN IMMEDIATE");
    let success = false;
    try {
      const result = action();
      this.db.exec("COMMIT");
      success = true;
      return result;
    } finally {
      if (!success) this.db.exec("ROLLBACK");
    }
  }

  audit(candidateHeadSha) {
    const info = this.db.prepare("PRAGMA integrity_check").get();
    requireWitness(info.integrity_check === "ok", "SQLite integrity verification failed");
    const meta = this.db.prepare("SELECT * FROM scope").all();
    requireWitness(meta.length === 1 && meta[0].host === this.hostIdentitySha256 &&
      meta[0].ledger === this.ledgerIdSha256 &&
      meta[0].signer === digest(this.publicKey.export({ type: "spki", format: "der" })) &&
      meta[0].owner === this.ownerKeyPin,
    "store signer/scope mismatch");
    let head = GENESIS_HEAD;
    let receiptSha256 = GENESIS_RECEIPT;
    let sequence = 0;
    const records = this.db.prepare("SELECT * FROM events ORDER BY seq ASC").all();
    requireWitness(records.length <= MAX_EVENTS, "history exceeds bound");
    const seenHeads = new Set([GENESIS_HEAD]);
    const seenRequests = new Set();
    for (const record of records) {
      const message = JSON.parse(record.message);
      requireWitness(JSON.stringify(message) === record.message, "noncanonical stored receipt");
      auditReceipt(message, record.signature, this.publicKey);
      requireWitness(record.seq === sequence + 1 && message.sequence === record.seq &&
        record.request_id === message.requestId && record.challenge === message.challenge &&
        message.hostIdentitySha256 === this.hostIdentitySha256 &&
        message.ledgerIdSha256 === this.ledgerIdSha256 &&
        message.priorHeadSha === head && message.previousReceiptSha256 === receiptSha256 &&
        !seenHeads.has(message.headSha) && !seenRequests.has(message.requestId),
      "nonmonotonic, forked or replayed witness history");
      seenHeads.add(message.headSha);
      seenRequests.add(message.requestId);
      sequence = message.sequence;
      head = message.headSha;
      receiptSha256 = receiptHash(message, record.signature);
    }
    requireWitness(candidateHeadSha === undefined || !seenHeads.has(candidateHeadSha),
      "replayed transition head");
    this.verifyAnchors(records);
    return { sequence, headSha: head, receiptSha256 };
  }

  verifyAnchors(records) {
    const names = readdirSync(this.anchorDirectory).filter((name) => name !== ".staging").sort();
    requireWitness(names.length <= records.length, "rollback: durable anchor ahead of database");
    for (let index = 0; index < names.length; index += 1) {
      const name = this.anchorName(index + 1);
      requireWitness(names[index] === name, "missing or unexpected durable anchor");
      const file = resolve(this.anchorDirectory, name);
      const stats = lstatSync(file);
      requireWitness(stats.isFile() && !stats.isSymbolicLink(), "invalid anchor file");
      const record = records[index];
      const source = readFileSync(file, "utf8");
      const expected = JSON.stringify({
        sequence: index + 1,
        receiptSha256: receiptHash(JSON.parse(record.message), record.signature),
      });
      requireWitness(source === expected, "rollback, replacement or corrupted anchor");
    }
    // A crash after SQLite COMMIT but before anchoring is recoverable: every
    // missing tail record was already independently signed and committed.
    for (let index = names.length; index < records.length; index += 1) {
      const record = records[index];
      this.writeAnchor(index + 1, receiptHash(JSON.parse(record.message), record.signature));
    }
  }

  anchorName(sequence) {
    return `${String(sequence).padStart(8, "0")}.receipt`;
  }

  writeAnchor(sequence, hash) {
    const file = resolve(this.anchorDirectory, this.anchorName(sequence));
    const encoded = Buffer.from(JSON.stringify({ sequence, receiptSha256: hash }));
    const staging = resolve(this.anchorStagingDirectory,
      `${this.anchorName(sequence)}.${randomBytes(16).toString("hex")}.tmp`);
    let fd;
    try {
      fd = openSync(staging, "wx", 0o600);
      let offset = 0;
      while (offset < encoded.length) {
        const sliceLength = process.env.VIRKI_DISPOSABLE_WITNESS_FAULT === "partialAnchor" ? 4 : encoded.length - offset;
        const count = writeSync(fd, encoded, offset, sliceLength);
        requireWitness(count > 0, "unable to persist durable anchor");
        offset += count;
        if (process.env.VIRKI_DISPOSABLE_WITNESS_FAULT === "partialAnchor") process.exit(76);
      }
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      try {
        linkSync(staging, file); // no-replace atomic publication on Linux
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        requireWitness(readFileSync(file, "utf8") === encoded.toString("utf8"),
          "conflicting durable anchor");
      }
    } finally {
      if (fd !== undefined) closeSync(fd);
      try { unlinkSync(staging); } catch { /* crash debris is non-authorizing */ }
    }
    const dirFd = openSync(this.anchorDirectory, "r");
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
    const scratchFd = openSync(this.anchorStagingDirectory, "r");
    try { fsyncSync(scratchFd); } finally { closeSync(scratchFd); }
  }

  cas(request) {
    canonicalRequest(request, AUTHORIZED_CAS_FIELDS, WITNESS_CAS_DOMAIN,
      this.hostIdentitySha256, this.ledgerIdSha256);
    requireWitness(HEX64.test(request.requestId) && HEX40.test(request.expectedHeadSha) &&
      HEX40.test(request.nextHeadSha) && HEX64.test(request.expectedReceiptSha256) &&
      HEX64.test(request.transitionSha256) &&
      Number.isSafeInteger(request.expectedSequence) && request.expectedSequence >= 0 &&
      request.expectedSequence < MAX_EVENTS, "invalid CAS predecessor or proposal");
    const now = Math.floor(Date.now() / 1000);
    requireWitness(Number.isSafeInteger(request.ownerExpiresAt) &&
      request.ownerExpiresAt > now && request.ownerExpiresAt <= now + 30 &&
      typeof request.ownerSignature === "string" && B64.test(request.ownerSignature) &&
      Buffer.from(request.ownerSignature, "base64").toString("base64") === request.ownerSignature &&
      verify(null, ownerWitnessCasSigningBytes(request), this.ownerPublicKey,
        Buffer.from(request.ownerSignature, "base64")),
    "independent owner-approved CAS signature missing, expired or invalid");
    this.db.exec("BEGIN IMMEDIATE");
    let committed = false;
    let receipt;
    try {
      const head = this.audit(request.nextHeadSha);
      requireWitness(request.expectedSequence === head.sequence &&
        request.expectedHeadSha === head.headSha &&
        request.expectedReceiptSha256 === head.receiptSha256 &&
        request.nextHeadSha !== head.headSha,
      "stale expected state or replayed transition");
      const issuedAt = Math.floor(Date.now() / 1000);
      const message = {
        version: 1, domain: WITNESS_CAS_DOMAIN, challenge: request.challenge,
        requestId: request.requestId, hostIdentitySha256: request.hostIdentitySha256,
        ledgerIdSha256: request.ledgerIdSha256, sequence: head.sequence + 1,
        priorHeadSha: head.headSha, headSha: request.nextHeadSha,
        previousReceiptSha256: head.receiptSha256,
        transitionSha256: request.transitionSha256, issuedAt, expiresAt: issuedAt + 30,
      };
      receipt = buildReceipt(message, this.privateKey);
      this.db.prepare("INSERT INTO events(seq,request_id,challenge,message,signature) VALUES(?,?,?,?,?)")
        .run(message.sequence, message.requestId, message.challenge,
          JSON.stringify(message), receipt.signature);
      if (process.env.VIRKI_DISPOSABLE_WITNESS_FAULT === "beforeCommit") process.exit(74);
      this.db.exec("COMMIT");
      committed = true;
    } finally {
      if (!committed) this.db.exec("ROLLBACK");
    }
    if (process.env.VIRKI_DISPOSABLE_WITNESS_FAULT === "afterCommitBeforeAnchor") process.exit(73);
    this.writeAnchor(receipt.message.sequence, receipt.receiptSha256);
    if (process.env.VIRKI_DISPOSABLE_WITNESS_FAULT === "afterAnchor") process.exit(75);
    return receipt;
  }

  read(request) {
    canonicalRequest(request, HEAD_FIELDS, WITNESS_READ_DOMAIN,
      this.hostIdentitySha256, this.ledgerIdSha256);
    // A stable SQLite writer snapshot prevents seeing a new anchor against an
    // old event list during concurrent CAS across separate witness processes.
    const head = this.withExclusiveSnapshot(() => this.audit());
    const issuedAt = Math.floor(Date.now() / 1000);
    return buildReceipt({
      version: 1, domain: WITNESS_READ_DOMAIN, challenge: request.challenge,
      hostIdentitySha256: request.hostIdentitySha256, ledgerIdSha256: request.ledgerIdSha256,
      ...head, issuedAt, expiresAt: issuedAt + 30,
    }, this.privateKey);
  }

  close() { this.db.close(); }
}

export function verifyIndependentWitnessHead({ receipt, publicKeyPem, pinSha256, request,
  minimumSequence = 0, minimumReceiptSha256, nowSeconds = Math.floor(Date.now() / 1000) }) {
  const key = createPublicKey(publicKeyPem);
  requireWitness(key.asymmetricKeyType === "ed25519" && HEX64.test(pinSha256) &&
    digest(key.export({ type: "spki", format: "der" })) === pinSha256, "invalid read public key pin");
  exactFields(request, HEAD_FIELDS);
  exactFields(receipt, ["message", "signature", "receiptSha256"]);
  const { message, signature } = receipt;
  exactFields(message, READ_FIELDS);
  requireWitness(message.version === 1 && message.domain === WITNESS_READ_DOMAIN &&
    message.challenge === request.challenge && message.hostIdentitySha256 === request.hostIdentitySha256 &&
    message.ledgerIdSha256 === request.ledgerIdSha256 &&
    HEX40.test(message.headSha) && HEX64.test(message.receiptSha256) &&
    Number.isSafeInteger(message.sequence) && message.sequence >= minimumSequence &&
    Number.isSafeInteger(nowSeconds) && message.issuedAt <= nowSeconds &&
    nowSeconds < message.expiresAt && message.issuedAt >= nowSeconds - 30 &&
    message.expiresAt === message.issuedAt + 30 &&
    (!minimumReceiptSha256 || message.receiptSha256 === minimumReceiptSha256) &&
    B64.test(signature) && verify(null, Buffer.from(JSON.stringify(message)), key,
      Buffer.from(signature, "base64")) &&
    receipt.receiptSha256 === receiptHash(message, signature), "stale or forged witness read");
  return Object.freeze({ ...message, witnessCasAuthorized: false,
    dockerLoadAuthorized: false, deployAuthorized: false });
}
