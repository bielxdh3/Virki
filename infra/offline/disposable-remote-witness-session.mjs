import { createHash, createPublicKey, randomBytes, verify, X509Certificate } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync,
  readFileSync, readdirSync, realpathSync, statSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import {
  GENESIS_HEAD, GENESIS_RECEIPT, WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN,
  independentWitnessOwnerCasSigningBytes, verifyIndependentWitnessCasReceipt,
  verifyIndependentWitnessHead,
} from "../../scripts/lib/offline-independent-witness-service.mjs";

// Experimental protocol boundary. There is no production entrypoint or host
// trust-root installer. The TLS client does connect to a REAL authenticated
// local test server, but never accepts a production endpoint.
const CONSENT_DOMAIN = "VIRKI_OFFLINE_REMOTE_WITNESS_CONSENT_V1";
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const CONSENT_FIELDS = [
  "version", "domain", "endpointHost", "endpointPort", "tlsServerSpkiSha256",
  "tlsClientSpkiSha256", "witnessSignerSpkiSha256", "ownerSignerSpkiSha256", "hostIdentitySha256",
  "ledgerIdSha256", "casRequestSha256", "genesisSha256", "expiresAt",
];
const CAS_FIELDS = [
  "version", "domain", "challenge", "requestId", "hostIdentitySha256", "ledgerIdSha256",
  "expectedSequence", "expectedHeadSha", "expectedReceiptSha256", "nextHeadSha",
  "transitionSha256", "ownerExpiresAt", "ownerSignature",
];
const GENESIS_FIELDS = ["version", "sequence", "headSha", "receiptSha256", "previousDigest", "receipt"];
const COMMITTED_FIELDS = [...GENESIS_FIELDS, "consent", "consentSignature", "intentSha256"];
const INTENT_FIELDS = ["version", "sequence", "consentSha256", "casRequestSha256", "previousDigest"];
const FINISH_FIELDS = ["version", "sequence", "checkpointSha256"];
const REFUSED = "Disposable remote witness refused; independent operator reconciliation required";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value), "utf8");
const same = (v, fields) => v !== null && typeof v === "object" && !Array.isArray(v) &&
  JSON.stringify(Object.keys(v)) === JSON.stringify(fields);
const ensure = (v) => { if (!v) throw new Error(REFUSED); };
const pad = (n) => String(n).padStart(8, "0");

export function independentRemoteWitnessConsentSigningBytes(consent) {
  ensure(same(consent, CONSENT_FIELDS));
  return Buffer.from(CONSENT_DOMAIN + "\0" + JSON.stringify(consent));
}

function pinKey(pem, pin) {
  ensure(typeof pem === "string" && pem.length <= 4096 && HEX64.test(pin));
  const key = createPublicKey(pem);
  ensure(key.asymmetricKeyType === "ed25519" &&
    hash(key.export({ type: "spki", format: "der" })) === pin);
  return key;
}

function parseConsent(input) {
  const { consent, consentSignature, ownerPublicKeyPem, witnessPublicKeyPem,
    casRequest, tlsClientCertPem, tlsClientKeyPem } = input;
  ensure(typeof input.checkpointDirectory === "string" &&
    input.ownerRootPinFile === path.join(
      path.dirname(input.checkpointDirectory), "owner-root-pin.json"));
  // In the fixture, this is separately provisioned by the test operator, not
  // copied from the signed consent. Native production must replace this with
  // an independently installed and measured root of trust.
  const rootPin = readPrivate(path.dirname(input.ownerRootPinFile),
    path.basename(input.ownerRootPinFile)).value;
  ensure(same(rootPin, ["version", "ownerSignerSpkiSha256"]) &&
    rootPin.version === 1 && HEX64.test(rootPin.ownerSignerSpkiSha256) &&
    rootPin.ownerSignerSpkiSha256.length === 64);
  ensure(same(consent, CONSENT_FIELDS) && same(casRequest, CAS_FIELDS));
  const c = Object.freeze({ ...consent });
  const request = Object.freeze({ ...casRequest });
  ensure(c.version === 1 && c.domain === CONSENT_DOMAIN &&
    c.endpointHost === "localhost" && Number.isSafeInteger(c.endpointPort) &&
    c.endpointPort >= 1024 && c.endpointPort <= 65535 &&
    [c.tlsServerSpkiSha256, c.tlsClientSpkiSha256, c.witnessSignerSpkiSha256, c.ownerSignerSpkiSha256,
      c.hostIdentitySha256, c.ledgerIdSha256, c.casRequestSha256, c.genesisSha256]
      .every((v) => HEX64.test(v)) &&
    Number.isSafeInteger(c.expiresAt) && Math.floor(Date.now() / 1000) < c.expiresAt &&
    c.expiresAt <= Math.floor(Date.now() / 1000) + 60 &&
    typeof tlsClientCertPem === "string" && tlsClientCertPem.length < 8192 &&
    typeof tlsClientKeyPem === "string" && tlsClientKeyPem.length < 8192 &&
    B64.test(consentSignature));
  const clientCertificate = new X509Certificate(tlsClientCertPem);
  ensure(hash(clientCertificate.publicKey.export({ type: "spki", format: "der" })) ===
    c.tlsClientSpkiSha256);
  ensure(rootPin.ownerSignerSpkiSha256 === c.ownerSignerSpkiSha256);
  const owner = pinKey(ownerPublicKeyPem, rootPin.ownerSignerSpkiSha256);
  pinKey(witnessPublicKeyPem, c.witnessSignerSpkiSha256);
  ensure(c.ownerSignerSpkiSha256 !== c.witnessSignerSpkiSha256 &&
    verify(null, independentRemoteWitnessConsentSigningBytes(c), owner,
      Buffer.from(consentSignature, "base64")) &&
    hash(canonical(request)) === c.casRequestSha256 &&
    request.version === 1 && request.domain === WITNESS_CAS_DOMAIN &&
    request.hostIdentitySha256 === c.hostIdentitySha256 &&
    request.ledgerIdSha256 === c.ledgerIdSha256 &&
    HEX64.test(request.challenge) && HEX64.test(request.requestId) &&
    HEX64.test(request.transitionSha256) && HEX64.test(request.expectedReceiptSha256) &&
    HEX40.test(request.expectedHeadSha) && HEX40.test(request.nextHeadSha) &&
    Number.isSafeInteger(request.expectedSequence) && request.expectedSequence >= 0 &&
    Number.isSafeInteger(request.ownerExpiresAt) &&
    Math.floor(Date.now() / 1000) < request.ownerExpiresAt &&
    request.ownerExpiresAt <= Math.floor(Date.now() / 1000) + 30 &&
    B64.test(request.ownerSignature) &&
    verify(null, independentWitnessOwnerCasSigningBytes(request), owner,
      Buffer.from(request.ownerSignature, "base64")));
  // Capture all strings used across asynchronous HEAD/CAS boundaries. The
  // caller must not switch certificates, keys or owner consent after HEAD.
  return Object.freeze({
    consent: c, request, consentSignature,
    ownerPublicKeyPem, witnessPublicKeyPem, tlsClientCertPem, tlsClientKeyPem,
  });
}

function directory(input) {
  ensure(process.platform === "linux" &&
    process.env.VIRKI_DISPOSABLE_REMOTE_WITNESS === "1" &&
    typeof input === "string" && path.isAbsolute(input) &&
    path.basename(input) === "checkpoint" &&
    /^virki-witness-transport-fixture-[a-zA-Z0-9]{6}$/u.test(
      path.basename(path.dirname(input))) &&
    path.dirname(path.dirname(input)) === realpathSync.native(os.tmpdir()) &&
    realpathSync.native(input) === input);
  const stats = lstatSync(input);
  const parent = lstatSync(path.dirname(input));
  ensure(stats.isDirectory() && !stats.isSymbolicLink() &&
    stats.uid === process.getuid() && (stats.mode & 0o777) === 0o700 &&
    parent.isDirectory() && !parent.isSymbolicLink() &&
    parent.uid === process.getuid() && (parent.mode & 0o777) === 0o700);
  const fd = openSync(input, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const pinned = { pathname: input, fd, anchor: `/proc/self/fd/${fd}` };
  try {
    assertPinnedDirectory(pinned);
    return pinned;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function assertPinnedDirectory(pinned) {
  ensure(process.platform === "linux" && pinned?.fd >= 0 &&
    typeof pinned.pathname === "string" &&
    realpathSync.native(pinned.pathname) === pinned.pathname);
  const fdStat = fstatSync(pinned.fd, { bigint: true });
  const named = lstatSync(pinned.pathname, { bigint: true });
  const parent = lstatSync(path.dirname(pinned.pathname), { bigint: true });
  ensure(fdStat.isDirectory() && named.isDirectory() &&
    !named.isSymbolicLink() && fdStat.dev === named.dev &&
    fdStat.ino === named.ino &&
    fdStat.uid === BigInt(process.getuid()) &&
    named.uid === fdStat.uid &&
    (fdStat.mode & 0o777n) === 0o700n &&
    (named.mode & 0o777n) === 0o700n &&
    parent.isDirectory() && !parent.isSymbolicLink() &&
    parent.uid === BigInt(process.getuid()) &&
    (parent.mode & 0o777n) === 0o700n);
}

function readPrivate(dir, name) {
  const filename = path.join(dir, name);
  const original = lstatSync(filename, { bigint: true });
  ensure(original.isFile() && !original.isSymbolicLink() && original.nlink === 1n &&
    original.uid === BigInt(process.getuid()) && (original.mode & 0o777n) === 0o600n &&
    original.size > 0n && original.size <= 16384n);
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd, { bigint: true });
    ensure(original.dev === opened.dev && original.ino === opened.ino &&
      original.size === opened.size);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const current = lstatSync(filename, { bigint: true });
    ensure(bytes.length === Number(original.size) &&
      after.ino === original.ino && current.ino === original.ino &&
      after.mtimeNs === original.mtimeNs && current.ctimeNs === original.ctimeNs);
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(decoded);
    ensure(JSON.stringify(value) === decoded);
    return { value, digest: hash(bytes) };
  } finally { closeSync(fd); }
}

function createDurable(dir, name, value) {
  const bytes = canonical(value);
  ensure(bytes.length > 0 && bytes.length <= 16384);
  const rootBefore = statSync(dir, { bigint: true });
  const target = path.join(dir, name);
  const fd = openSync(target,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    let at = 0;
    while (at < bytes.length) {
      const count = writeSync(fd, bytes, at, bytes.length - at);
      ensure(count > 0);
      at += count;
    }
    fsyncSync(fd);
    const opened = fstatSync(fd, { bigint: true });
    const named = lstatSync(target, { bigint: true });
    ensure(opened.isFile() && named.isFile() && !named.isSymbolicLink() &&
      opened.dev === named.dev && opened.ino === named.ino &&
      opened.uid === BigInt(process.getuid()) && opened.nlink === 1n &&
      (opened.mode & 0o777n) === 0o600n &&
      opened.size === BigInt(bytes.length));
  } finally { closeSync(fd); }
  // dir is the private, already O_NOFOLLOW-verified /proc/self/fd/<N>
  // anchor, so that one kernel-owned symlink must be followed here.
  const directoryFd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  const rootAfter = statSync(dir, { bigint: true });
  ensure(rootBefore.ino === rootAfter.ino && rootBefore.dev === rootAfter.dev &&
    readPrivate(dir, name).digest === hash(bytes));
  return hash(bytes);
}

function ownerRequestFromReceipt(m) {
  // The receipt contains the signed CAS's canonical fields, but labels the
  // predecessor as priorHeadSha and the next SHA as headSha. Restore exactly
  // the owner-approved request before comparing to the historical intent.
  return {
    version: 1, domain: WITNESS_CAS_DOMAIN,
    challenge: m.challenge, requestId: m.requestId,
    hostIdentitySha256: m.hostIdentitySha256, ledgerIdSha256: m.ledgerIdSha256,
    expectedSequence: m.sequence - 1,
    expectedHeadSha: m.priorHeadSha,
    expectedReceiptSha256: m.previousReceiptSha256,
    nextHeadSha: m.headSha, transitionSha256: m.transitionSha256,
    ownerExpiresAt: m.ownerExpiresAt, ownerSignature: m.ownerSignature,
  };
}

function checkpoint(dir, consent, witnessPublicKeyPem, ownerPublicKeyPem,
  pendingIntent = null) {
  const names = readdirSync(dir);
  ensure(names.every((n) => /^(?:[0-9]{8}\.checkpoint|[0-9]{8}\.intent|[0-9]{8}\.complete)$/u.test(n)));
  const checks = names.filter((n) => n.endsWith(".checkpoint")).sort();
  ensure(checks.length > 0 && checks.length < 4096);
  let previous;
  let genesisDigest;
  for (let i = 0; i < checks.length; i++) {
    ensure(checks[i] === pad(i) + ".checkpoint");
    const next = readPrivate(dir, checks[i]);
    const c = next.value;
    ensure(same(c, i === 0 ? GENESIS_FIELDS : COMMITTED_FIELDS) &&
      c.version === 1 && c.sequence === i &&
      HEX40.test(c.headSha) && HEX64.test(c.receiptSha256) &&
      HEX64.test(c.previousDigest));
    if (i === 0) {
      ensure(next.digest === consent.genesisSha256 &&
        c.headSha === GENESIS_HEAD && c.receiptSha256 === GENESIS_RECEIPT &&
        c.previousDigest === "0".repeat(64) && c.receipt === null);
      genesisDigest = next.digest;
    } else {
      ensure(c.previousDigest === previous.digest && c.receipt !== null &&
        same(c.receipt, ["message", "signature", "receiptSha256"]));
      const m = c.receipt.message;
      const signer = pinKey(witnessPublicKeyPem, consent.witnessSignerSpkiSha256);
      const owner = pinKey(ownerPublicKeyPem, consent.ownerSignerSpkiSha256);
      ensure(m && m.version === 1 && m.domain === WITNESS_CAS_DOMAIN &&
        HEX64.test(m.challenge) && HEX64.test(m.requestId) &&
        m.hostIdentitySha256 === consent.hostIdentitySha256 &&
        m.ledgerIdSha256 === consent.ledgerIdSha256 &&
        m.sequence === i && m.headSha === c.headSha &&
        m.priorHeadSha === previous.value.headSha &&
        m.previousReceiptSha256 === previous.value.receiptSha256 &&
        HEX64.test(m.transitionSha256) && HEX40.test(m.headSha) &&
        B64.test(m.ownerSignature) &&
        m.ownerSignatureSha256 === hash(m.ownerSignature) &&
        Number.isSafeInteger(m.issuedAt) &&
        Number.isSafeInteger(m.ownerExpiresAt) &&
        Number.isSafeInteger(m.expiresAt) &&
        m.issuedAt < m.ownerExpiresAt &&
        m.ownerExpiresAt <= m.issuedAt + 30 &&
        m.expiresAt === m.issuedAt + 30 &&
        verify(null, independentWitnessOwnerCasSigningBytes({
          version: 1, domain: WITNESS_CAS_DOMAIN,
          challenge: m.challenge, requestId: m.requestId,
          hostIdentitySha256: m.hostIdentitySha256,
          ledgerIdSha256: m.ledgerIdSha256,
          expectedSequence: m.sequence - 1, expectedHeadSha: m.priorHeadSha,
          expectedReceiptSha256: m.previousReceiptSha256,
          nextHeadSha: m.headSha, transitionSha256: m.transitionSha256,
          ownerExpiresAt: m.ownerExpiresAt,
        }), owner, Buffer.from(m.ownerSignature, "base64")) &&
        c.receipt.receiptSha256 === c.receiptSha256 &&
        B64.test(c.receipt.signature) &&
        verify(null, canonical(m), signer,
          Buffer.from(c.receipt.signature, "base64")) &&
        c.receipt.receiptSha256 === hash(canonical({
          message: m, signature: c.receipt.signature,
        })));
      const intent = readPrivate(dir, pad(i) + ".intent");
      const completion = readPrivate(dir, pad(i) + ".complete");
      const historicalConsent = c.consent;
      ensure(same(intent.value, INTENT_FIELDS) && same(completion.value, FINISH_FIELDS) &&
        same(historicalConsent, CONSENT_FIELDS) &&
        intent.value.version === 1 && completion.value.version === 1 &&
        HEX64.test(intent.value.casRequestSha256) &&
        HEX64.test(intent.value.consentSha256) &&
        B64.test(c.consentSignature) &&
        historicalConsent.version === 1 && historicalConsent.domain === CONSENT_DOMAIN &&
        historicalConsent.endpointHost === "localhost" &&
        Number.isSafeInteger(historicalConsent.endpointPort) &&
        historicalConsent.endpointPort >= 1024 && historicalConsent.endpointPort <= 65535 &&
        Number.isSafeInteger(historicalConsent.expiresAt) &&
        m.issuedAt <= historicalConsent.expiresAt &&
        historicalConsent.genesisSha256 === genesisDigest &&
        historicalConsent.hostIdentitySha256 === consent.hostIdentitySha256 &&
        historicalConsent.ledgerIdSha256 === consent.ledgerIdSha256 &&
        historicalConsent.ownerSignerSpkiSha256 === consent.ownerSignerSpkiSha256 &&
        historicalConsent.witnessSignerSpkiSha256 === consent.witnessSignerSpkiSha256 &&
        [historicalConsent.tlsServerSpkiSha256, historicalConsent.tlsClientSpkiSha256]
          .every((pin) => HEX64.test(pin)) &&
        verify(null, independentRemoteWitnessConsentSigningBytes(historicalConsent),
          owner, Buffer.from(c.consentSignature, "base64")) &&
        hash(canonical(historicalConsent)) === intent.value.consentSha256 &&
        hash(canonical(ownerRequestFromReceipt(m))) === intent.value.casRequestSha256 &&
        historicalConsent.casRequestSha256 === intent.value.casRequestSha256 &&
        c.intentSha256 === intent.digest &&
        completion.value.sequence === i && completion.value.checkpointSha256 === next.digest &&
        intent.value.sequence === i && intent.value.previousDigest === previous.digest);
    }
    previous = next;
  }
  ensure(names.filter((n) => n.endsWith(".intent")).length === checks.length - 1 +
    (pendingIntent === null ? 0 : 1) &&
    names.filter((n) => n.endsWith(".complete")).length === checks.length - 1);
  if (pendingIntent !== null) {
    ensure(same(pendingIntent, ["sequence", "sha256"]) &&
      pendingIntent.sequence === checks.length && HEX64.test(pendingIntent.sha256));
    const intent = readPrivate(dir, pad(pendingIntent.sequence) + ".intent");
    ensure(intent.digest === pendingIntent.sha256 &&
      same(intent.value, INTENT_FIELDS) &&
      intent.value.version === 1 &&
      intent.value.sequence === pendingIntent.sequence &&
      intent.value.previousDigest === previous.digest);
  }
  return previous;
}

// One TLS handshake for each HEAD/CAS operation; both peers are reauthenticated.
// No bytes of protocol/owner approval leave the process before the TLS leaf
// certificate has passed its independent SPKI and DNS name checks.
async function exchange(consent, cert, key, action, request, beforeSend) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: "127.0.0.1", port: consent.endpointPort, servername: consent.endpointHost,
      cert, key, rejectUnauthorized: false,
    });
    let settled = false;
    let bytes = Buffer.alloc(0);
    const failure = () => {
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        socket.destroy();
        reject(new Error(REFUSED));
      }
    };
    // A single absolute deadline, not merely an inactivity timeout: a peer
    // cannot keep the session alive indefinitely with slow response trickles.
    const deadline = setTimeout(failure, 3000);
    socket.setTimeout(3000, failure);
    socket.on("error", failure);
    socket.on("secureConnect", () => {
      try {
        const peer = socket.getPeerCertificate(true);
        ensure(peer?.raw && peer.raw.length < 8192);
        const certificate = new X509Certificate(peer.raw);
        const now = Date.now();
        ensure(certificate.checkHost(consent.endpointHost) === consent.endpointHost &&
          Date.parse(certificate.validFrom) <= now && now < Date.parse(certificate.validTo) &&
          hash(certificate.publicKey.export({ type: "spki", format: "der" })) ===
            consent.tlsServerSpkiSha256);
        beforeSend?.();
        socket.write(canonical({ action, request }));
        socket.write("\n");
      } catch { failure(); }
    });
    socket.on("data", (part) => {
      if (bytes.length + part.length > 16384) return failure();
      bytes = Buffer.concat([bytes, part]);
    });
    socket.on("end", () => {
      if (settled) return;
      try {
        ensure(bytes.length > 1 && bytes.at(-1) === 10 &&
          bytes.subarray(0, -1).indexOf(10) === -1);
        const decoded = new TextDecoder("utf-8", { fatal: true })
          .decode(bytes.subarray(0, -1));
        const result = JSON.parse(decoded);
        ensure(JSON.stringify(result) === decoded);
        settled = true;
        clearTimeout(deadline);
        resolve(result);
      } catch { failure(); }
    });
    socket.on("close", () => { if (!settled) failure(); });
  });
}

function assertLiveCasConsent(consent, request) {
  const now = Math.floor(Date.now() / 1000);
  ensure(now < consent.expiresAt && now < request.ownerExpiresAt);
}

/** Local-only protocol implementation, with a persistent no-retry CAS intent. */
export async function createDisposableRemoteWitnessSession(input = {}) {
  try {
    const pinned = directory(input.checkpointDirectory);
    try {
    const root = pinned.anchor;
    const session = parseConsent(input);
    const { consent, request } = session;
    const previous = checkpoint(root, consent, session.witnessPublicKeyPem,
      session.ownerPublicKeyPem);
    const verifyUnchangedHistory = (pendingIntent = null) => {
      const current = checkpoint(root, consent, session.witnessPublicKeyPem,
        session.ownerPublicKeyPem, pendingIntent);
      ensure(current.digest === previous.digest);
    };
    const current = previous.value;
    ensure(request.expectedSequence === current.sequence &&
      request.expectedReceiptSha256 === current.receiptSha256 &&
      request.expectedHeadSha === current.headSha &&
      request.nextHeadSha !== current.headSha &&
      current.sequence < 4095);
    const headRequest = Object.freeze({
      version: 1, domain: WITNESS_READ_DOMAIN,
      challenge: randomBytes(32).toString("hex"),
      hostIdentitySha256: consent.hostIdentitySha256,
      ledgerIdSha256: consent.ledgerIdSha256,
    });
    const headReceipt = await exchange(consent, session.tlsClientCertPem,
      session.tlsClientKeyPem, "head", headRequest, () => assertPinnedDirectory(pinned));
    assertPinnedDirectory(pinned);
    verifyUnchangedHistory();
    assertLiveCasConsent(consent, request);
    const head = verifyIndependentWitnessHead({
      receipt: headReceipt, request: headRequest,
      publicKeyPem: session.witnessPublicKeyPem,
      pinSha256: consent.witnessSignerSpkiSha256,
      minimumSequence: current.sequence, minimumReceiptSha256: current.receiptSha256,
    });
    ensure(head.sequence === current.sequence && head.headSha === current.headSha);
    const n = current.sequence + 1;
    // Exclusive durable intent BEFORE issuing CAS. If the reply is missing or
    // any subsequent step fails, a future call refuses and cannot retry.
    const intentSha256 = createDurable(root, pad(n) + ".intent", {
      version: 1, sequence: n, consentSha256: hash(canonical(consent)),
      casRequestSha256: consent.casRequestSha256, previousDigest: previous.digest,
    });
    const pendingIntent = Object.freeze({ sequence: n, sha256: intentSha256 });
    assertPinnedDirectory(pinned);
    verifyUnchangedHistory(pendingIntent);
    assertLiveCasConsent(consent, request);
    const rawReceipt = await exchange(consent, session.tlsClientCertPem,
      session.tlsClientKeyPem, "cas", request, () => {
        assertPinnedDirectory(pinned);
        verifyUnchangedHistory(pendingIntent);
        assertLiveCasConsent(consent, request);
      });
    assertPinnedDirectory(pinned);
    verifyUnchangedHistory(pendingIntent);
    const checked = verifyIndependentWitnessCasReceipt({
      receipt: rawReceipt, request,
      publicKeyPem: session.witnessPublicKeyPem,
      pinSha256: consent.witnessSignerSpkiSha256,
      ownerPublicKeyPem: session.ownerPublicKeyPem,
      ownerPinSha256: consent.ownerSignerSpkiSha256,
    });
    ensure(checked.sequence === n && checked.headSha === request.nextHeadSha);
    const checkpointSha256 = createDurable(root, pad(n) + ".checkpoint", {
      version: 1, sequence: n, headSha: checked.headSha,
      receiptSha256: checked.receiptSha256,
      previousDigest: previous.digest, receipt: rawReceipt,
      consent, consentSignature: session.consentSignature, intentSha256,
    });
    assertPinnedDirectory(pinned);
    createDurable(root, pad(n) + ".complete", {
      version: 1, sequence: n, checkpointSha256,
    });
    assertPinnedDirectory(pinned);
    return Object.freeze({
      status: "EXTERNAL_TLS_WITNESS_DISPOSABLE_CHECKPOINT_ONLY",
      sequence: n, headSha: checked.headSha, receiptSha256: checked.receiptSha256,
      witnessCasAuthorized: false, transferAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false,
    });
    } finally {
      closeSync(pinned.fd);
    }
  } catch {
    // Never leak keys, certs, host information or transport error strings.
    throw new Error(REFUSED);
  }
}
