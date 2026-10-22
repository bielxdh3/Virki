import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import {
  closeSync, fsyncSync, linkSync, lstatSync, openSync,
  readFileSync, readdirSync, realpathSync, unlinkSync, writeSync,
} from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Disposable Linux witness only. No release or Docker authorization is granted.
export const WITNESS_CAS_DOMAIN = "VIRKI_OFFLINE_INDEPENDENT_WITNESS_CAS_V1";
export const WITNESS_READ_DOMAIN = "VIRKI_OFFLINE_INDEPENDENT_WITNESS_HEAD_V1";
export const WITNESS_OWNER_CAS_DOMAIN = "VIRKI_OFFLINE_INDEPENDENT_WITNESS_OWNER_CAS_V1";
export const GENESIS_HEAD = "0".repeat(40);
export const GENESIS_RECEIPT = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const MAX_EVENTS = 4096;
const ANCHOR_FILE = /^[0-9]{8}\.receipt$/u;
const ANCHOR_TEMP = /^\.[0-9]{8}\.receipt\.[0-9a-f]{32}\.tmp$/u;
const CAS_OWNER_FIELDS = [
  "version", "domain", "challenge", "requestId", "hostIdentitySha256", "ledgerIdSha256",
  "expectedSequence", "expectedHeadSha", "expectedReceiptSha256", "nextHeadSha", "transitionSha256",
  "ownerExpiresAt",
];
const CAS_FIELDS = [...CAS_OWNER_FIELDS, "ownerSignature"];
const HEAD_FIELDS = ["version", "domain", "challenge", "hostIdentitySha256", "ledgerIdSha256"];
const RECEIPT_FIELDS = [
  "version", "domain", "challenge", "requestId", "hostIdentitySha256", "ledgerIdSha256",
  "sequence", "priorHeadSha", "headSha", "previousReceiptSha256", "transitionSha256",
  "ownerSignature", "ownerSignatureSha256", "ownerExpiresAt", "issuedAt", "expiresAt",
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

// The owner must authenticate the exact CAS transition independently of the
// witness receipt signer. Keep a stable field order and domain separator.
export function independentWitnessOwnerCasSigningBytes(request) {
  const body = Object.fromEntries(CAS_OWNER_FIELDS.map((field) => [field, request[field]]));
  return Buffer.from(`${WITNESS_OWNER_CAS_DOMAIN}\0${JSON.stringify(body)}`);
}

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

function checkOwnerSignature(message, ownerKey) {
  const reconstructed = {
    version: message.version, domain: message.domain, challenge: message.challenge,
    requestId: message.requestId, hostIdentitySha256: message.hostIdentitySha256,
    ledgerIdSha256: message.ledgerIdSha256, expectedSequence: message.sequence - 1,
    expectedHeadSha: message.priorHeadSha,
    expectedReceiptSha256: message.previousReceiptSha256,
    nextHeadSha: message.headSha, transitionSha256: message.transitionSha256,
    ownerExpiresAt: message.ownerExpiresAt,
  };
  return B64.test(message.ownerSignature) &&
    Buffer.from(message.ownerSignature, "base64").toString("base64") === message.ownerSignature &&
    message.ownerSignatureSha256 === digest(message.ownerSignature) &&
    verify(null, independentWitnessOwnerCasSigningBytes(reconstructed), ownerKey,
      Buffer.from(message.ownerSignature, "base64"));
}

function auditReceipt(message, signature, key, ownerKey) {
  exactFields(message, RECEIPT_FIELDS);
  requireWitness(message.version === 1 && message.domain === WITNESS_CAS_DOMAIN &&
    HEX64.test(message.challenge) && HEX64.test(message.requestId) &&
    HEX64.test(message.hostIdentitySha256) && HEX64.test(message.ledgerIdSha256) &&
    HEX40.test(message.priorHeadSha) && HEX40.test(message.headSha) &&
    HEX64.test(message.previousReceiptSha256) && HEX64.test(message.transitionSha256) &&
    HEX64.test(message.ownerSignatureSha256) &&
    Number.isSafeInteger(message.sequence) && message.sequence > 0 && message.sequence <= MAX_EVENTS &&
    Number.isSafeInteger(message.issuedAt) && Number.isSafeInteger(message.expiresAt) &&
    Number.isSafeInteger(message.ownerExpiresAt) && message.issuedAt < message.ownerExpiresAt &&
    message.ownerExpiresAt <= message.issuedAt + 30 &&
    message.expiresAt === message.issuedAt + 30 && B64.test(signature) &&
    Buffer.from(signature, "base64").toString("base64") === signature &&
    verify(null, Buffer.from(JSON.stringify(message)), key, Buffer.from(signature, "base64")) &&
    checkOwnerSignature(message, ownerKey),
  "invalid signed history receipt");
}

export function verifyIndependentWitnessCasReceipt({ receipt, publicKeyPem, pinSha256,
  ownerPublicKeyPem, ownerPinSha256, request,
  nowSeconds = Math.floor(Date.now() / 1000) }) {
  const key = createPublicKey(publicKeyPem);
  const ownerKey = createPublicKey(ownerPublicKeyPem);
  requireWitness(key.asymmetricKeyType === "ed25519" && HEX64.test(pinSha256) &&
    digest(key.export({ format: "der", type: "spki" })) === pinSha256, "invalid verifier pin");
  requireWitness(ownerKey.asymmetricKeyType === "ed25519" && HEX64.test(ownerPinSha256) &&
    digest(ownerKey.export({ format: "der", type: "spki" })) === ownerPinSha256 &&
    ownerPinSha256 !== pinSha256, "invalid pinned CAS owner key");
  exactFields(receipt, ["message", "signature", "receiptSha256"]);
  auditReceipt(receipt.message, receipt.signature, key, ownerKey);
  exactFields(request, CAS_FIELDS);
  const m = receipt.message;
  requireWitness(m.challenge === request.challenge && m.requestId === request.requestId &&
    m.hostIdentitySha256 === request.hostIdentitySha256 && m.ledgerIdSha256 === request.ledgerIdSha256 &&
    m.sequence === request.expectedSequence + 1 && m.priorHeadSha === request.expectedHeadSha &&
    m.headSha === request.nextHeadSha && m.previousReceiptSha256 === request.expectedReceiptSha256 &&
    m.transitionSha256 === request.transitionSha256 &&
    m.ownerSignature === request.ownerSignature &&
    m.ownerExpiresAt === request.ownerExpiresAt &&
    Number.isSafeInteger(nowSeconds) && m.issuedAt <= nowSeconds &&
    nowSeconds < m.expiresAt && nowSeconds < m.ownerExpiresAt &&
    m.issuedAt >= nowSeconds - 30 &&
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

export class IndependentOfflineWitness {
  constructor({ directory, anchorDirectory, keyFile, expectedKeyPinSha256,
    ownerPublicKeyFile, expectedOwnerPinSha256,
    hostIdentitySha256, ledgerIdSha256, repositoryDirectory } = {}) {
    requireWitness(process.platform === "linux" && process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE === "1",
      "Linux disposable fixture is required");
    requireWitness(HEX64.test(hostIdentitySha256) && HEX64.test(ledgerIdSha256) &&
      HEX64.test(expectedKeyPinSha256) && HEX64.test(expectedOwnerPinSha256),
    "invalid operator-pinned witness and owner identities");
    for (const folder of [directory, anchorDirectory]) verifyPrivateDirectory(folder);
    const store = realpathSync(directory);
    const anchors = realpathSync(anchorDirectory);
    const signer = realpathSync(keyFile);
    const ownerFile = realpathSync(ownerPublicKeyFile);
    requireWitness(store !== anchors && !isWithin(store, anchors) && !isWithin(anchors, store),
      "anchor and database directories must be distinct");
    if (repositoryDirectory) {
      const repository = realpathSync(repositoryDirectory);
      requireWitness(!isWithin(store, repository) && !isWithin(anchors, repository) &&
        !isWithin(signer, repository) && !isWithin(ownerFile, repository),
      "witness authority must live outside repository");
    }
    const privateKey = createPrivateKey(verifyPrivateFile(keyFile));
    requireWitness(privateKey.asymmetricKeyType === "ed25519", "Ed25519 signing key required");
    const publicKey = createPublicKey(privateKey);
    const actualPin = digest(publicKey.export({ format: "der", type: "spki" }));
    requireWitness(actualPin === expectedKeyPinSha256, "witness signer does not match operator pin");
    const ownerKey = createPublicKey(verifyPrivateFile(ownerPublicKeyFile));
    requireWitness(ownerKey.asymmetricKeyType === "ed25519" &&
      digest(ownerKey.export({ format: "der", type: "spki" })) === expectedOwnerPinSha256 &&
      expectedOwnerPinSha256 !== actualPin,
    "owner verification key must be independently pinned and different from signer");
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.ownerKey = ownerKey;
    this.ownerPin = expectedOwnerPinSha256;
    this.anchorDirectory = anchors;
    this.hostIdentitySha256 = hostIdentitySha256;
    this.ledgerIdSha256 = ledgerIdSha256;
    this.db = new DatabaseSync(resolve(store, "witness.sqlite"), { timeout: 5000 });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");
    this.db.exec("CREATE TABLE IF NOT EXISTS scope (id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, ledger TEXT NOT NULL, signer TEXT NOT NULL, owner TEXT NOT NULL)");
    this.db.exec("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, challenge TEXT UNIQUE NOT NULL, message TEXT NOT NULL, signature TEXT NOT NULL)");
    this.db.prepare("INSERT OR IGNORE INTO scope(id,host,ledger,signer,owner) VALUES(1,?,?,?,?)")
      .run(hostIdentitySha256, ledgerIdSha256, actualPin, expectedOwnerPinSha256);
    this.withAuditLock(() => this.audit());
  }

  // A read lock alone is insufficient: another process may COMMIT a new
  // SQLite head while this process inspects anchors for an older snapshot.
  // BEGIN IMMEDIATE fences writers through both the SQL and anchor checks.
  withAuditLock(action) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = action();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  audit(candidateHeadSha) {
    const info = this.db.prepare("PRAGMA integrity_check").get();
    requireWitness(info.integrity_check === "ok", "SQLite integrity verification failed");
    const meta = this.db.prepare("SELECT * FROM scope").all();
    requireWitness(meta.length === 1 && meta[0].host === this.hostIdentitySha256 &&
      meta[0].ledger === this.ledgerIdSha256 &&
      meta[0].signer === digest(this.publicKey.export({ type: "spki", format: "der" })) &&
      meta[0].owner === this.ownerPin,
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
      auditReceipt(message, record.signature, this.publicKey, this.ownerKey);
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
    const names = [];
    for (const entry of readdirSync(this.anchorDirectory)) {
      if (ANCHOR_TEMP.test(entry)) {
        // A kill before publication leaves a disposable staging inode.
        // Never mistake it for an independently committed durable anchor.
        const stats = lstatSync(resolve(this.anchorDirectory, entry));
        requireWitness(stats.isFile() && !stats.isSymbolicLink() &&
          stats.uid === process.getuid() && (stats.mode & 0o077) === 0,
        "invalid temporary anchor");
        continue;
      }
      requireWitness(ANCHOR_FILE.test(entry), "missing or unexpected durable anchor");
      names.push(entry);
    }
    names.sort();
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
    // Write and fsync an invisible staging inode. Hard-linking into the
    // canonical name is atomic and refuses to replace another publisher's
    // anchor; rename() would silently overwrite a conflicting permanent one.
    const temp = resolve(this.anchorDirectory,
      `.${this.anchorName(sequence)}.${randomBytes(16).toString("hex")}.tmp`);
    let fd;
    let staged = false;
    try {
      fd = openSync(temp, "wx", 0o600);
      staged = true;
      let offset = 0;
      while (offset < encoded.length) {
        const count = writeSync(fd, encoded, offset, encoded.length - offset);
        requireWitness(count > 0, "unable to persist durable anchor");
        offset += count;
      }
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      try {
        linkSync(temp, file);
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        requireWitness(readFileSync(file, "utf8") === encoded.toString("utf8"),
          "conflicting durable anchor");
      }
      this.fsyncAnchorDirectory();
    } finally {
      if (fd !== undefined) closeSync(fd);
      if (staged) {
        unlinkSync(temp);
        this.fsyncAnchorDirectory();
      }
    }
  }

  fsyncAnchorDirectory() {
    const dirFd = openSync(this.anchorDirectory, "r");
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  }

  cas(request) {
    canonicalRequest(request, CAS_FIELDS, WITNESS_CAS_DOMAIN,
      this.hostIdentitySha256, this.ledgerIdSha256);
    requireWitness(B64.test(request.ownerSignature) &&
      Buffer.from(request.ownerSignature, "base64").toString("base64") === request.ownerSignature &&
      verify(null, independentWitnessOwnerCasSigningBytes(request), this.ownerKey,
        Buffer.from(request.ownerSignature, "base64")),
    "unauthenticated CAS owner request");
    const ownerNow = Math.floor(Date.now() / 1000);
    requireWitness(Number.isSafeInteger(request.ownerExpiresAt) &&
      ownerNow < request.ownerExpiresAt && request.ownerExpiresAt <= ownerNow + 30,
    "expired or excessive CAS owner authorization");
    requireWitness(HEX64.test(request.requestId) && HEX40.test(request.expectedHeadSha) &&
      HEX40.test(request.nextHeadSha) && HEX64.test(request.expectedReceiptSha256) &&
      HEX64.test(request.transitionSha256) &&
      Number.isSafeInteger(request.expectedSequence) && request.expectedSequence >= 0 &&
      request.expectedSequence < MAX_EVENTS, "invalid CAS predecessor or proposal");
    this.db.exec("BEGIN IMMEDIATE");
    let committed = false;
    let receipt;
    try {
      requireWitness(Math.floor(Date.now() / 1000) < request.ownerExpiresAt,
        "CAS owner authorization expired while waiting for SQLite lock");
      const head = this.audit(request.nextHeadSha);
      requireWitness(request.expectedSequence === head.sequence &&
        request.expectedHeadSha === head.headSha &&
        request.expectedReceiptSha256 === head.receiptSha256 &&
        request.nextHeadSha !== head.headSha,
      "stale expected state or replayed transition");
      const issuedAt = Math.floor(Date.now() / 1000);
      requireWitness(issuedAt < request.ownerExpiresAt,
        "CAS owner authorization expired before commit");
      const message = {
        version: 1, domain: WITNESS_CAS_DOMAIN, challenge: request.challenge,
        requestId: request.requestId, hostIdentitySha256: request.hostIdentitySha256,
        ledgerIdSha256: request.ledgerIdSha256, sequence: head.sequence + 1,
        priorHeadSha: head.headSha, headSha: request.nextHeadSha,
        previousReceiptSha256: head.receiptSha256,
        transitionSha256: request.transitionSha256,
        ownerSignature: request.ownerSignature,
        ownerSignatureSha256: digest(request.ownerSignature),
        ownerExpiresAt: request.ownerExpiresAt, issuedAt, expiresAt: issuedAt + 30,
      };
      receipt = buildReceipt(message, this.privateKey);
      this.db.prepare("INSERT INTO events(seq,request_id,challenge,message,signature) VALUES(?,?,?,?,?)")
        .run(message.sequence, message.requestId, message.challenge,
          JSON.stringify(message), receipt.signature);
      if (process.env.VIRKI_DISPOSABLE_WITNESS_FAULT === "beforeCommit") process.exit(74);
      requireWitness(Math.floor(Date.now() / 1000) < request.ownerExpiresAt,
        "CAS owner authorization expired before SQLite COMMIT");
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
    const head = this.withAuditLock(() => this.audit());
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
