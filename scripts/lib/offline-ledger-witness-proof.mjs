import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

// Cryptographic READ proof for an independent witness, NOT a CAS transaction,
// release authorizer, health attestation, or production transport implementation.
// A fresh challenge is generated here; no caller-controlled nonce is accepted.
const DOMAIN = "VIRKI_OFFLINE_LEDGER_WITNESS_READ_V1";
const FIELDS = Object.freeze([
  "version", "domain", "challenge", "hostIdentitySha256", "ledgerSha256",
  "sequence", "headSha", "issuedAt", "expiresAt",
]);
const SHA256 = /^[a-f0-9]{64}$/u;
const SHA40 = /^[a-f0-9]{40}$/u;
const NONCE = /^[a-f0-9]{64}$/u;
const BASE64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const MAX_RESPONSE_BYTES = 4096;

function requireProof(value, why) {
  if (!value) throw new Error(`Offline ledger witness read refused: ${why}`);
}

function exactObject(value, keys) {
  requireProof(value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(keys), "unexpected proof fields");
}

function publicWitnessKey(keyPem, pinSha256) {
  requireProof(typeof keyPem === "string" && keyPem.length <= 4096 &&
    SHA256.test(pinSha256), "missing independent witness public key pin");
  const key = createPublicKey(keyPem);
  requireProof(key.asymmetricKeyType === "ed25519" &&
    createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex") === pinSha256,
  "witness key does not match independent pin");
  return key;
}

function parseResponse(raw) {
  requireProof(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= MAX_RESPONSE_BYTES,
    "signed witness response is missing or oversized");
  const source = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  const parsed = JSON.parse(source);
  exactObject(parsed, ["message", "signature"]);
  exactObject(parsed.message, FIELDS);
  requireProof(JSON.stringify(parsed) === source, "witness response is not canonical JSON");
  requireProof(typeof parsed.signature === "string" && BASE64_SIGNATURE.test(parsed.signature) &&
    Buffer.from(parsed.signature, "base64").toString("base64") === parsed.signature,
  "invalid witness signature encoding");
  return parsed;
}

/**
 * Standalone verifier for an already received independently signed witness
 * response. This is a non-authorizing proof of fresh READ alignment only.
 * Exact fields and byte encoding are part of the signed protocol.
 */
export function verifyIndependentOfflineLedgerWitnessRead({
  responseBytes, witnessPublicKeyPem, witnessPublicKeyPinSha256,
  expectedChallenge, hostIdentitySha256, ledgerSha256, sequence, headSha,
  nowSeconds = Math.floor(Date.now() / 1000),
} = {}) {
  requireProof(NONCE.test(expectedChallenge) && SHA256.test(hostIdentitySha256) &&
    SHA256.test(ledgerSha256) && SHA40.test(headSha) &&
    Number.isSafeInteger(sequence) && sequence >= 0 &&
    Number.isSafeInteger(nowSeconds) && nowSeconds > 0,
  "invalid expected witness read identity");
  const key = publicWitnessKey(witnessPublicKeyPem, witnessPublicKeyPinSha256);
  const { message, signature } = parseResponse(responseBytes);
  requireProof(message.version === 1 && message.domain === DOMAIN &&
    message.challenge === expectedChallenge &&
    message.hostIdentitySha256 === hostIdentitySha256 &&
    message.ledgerSha256 === ledgerSha256 &&
    message.sequence === sequence && message.headSha === headSha,
  "witness read is stale, crossed, rolled back or for another ledger");
  requireProof(Number.isSafeInteger(message.issuedAt) && Number.isSafeInteger(message.expiresAt) &&
    message.issuedAt <= nowSeconds && nowSeconds < message.expiresAt &&
    message.issuedAt >= nowSeconds - 30 && message.expiresAt <= message.issuedAt + 30,
  "witness response not freshly bounded");
  const payload = Buffer.from(JSON.stringify(message));
  requireProof(verify(null, payload, key, Buffer.from(signature, "base64")),
    "witness signature not independently authenticated");
  return Object.freeze({
    status: "INDEPENDENT_WITNESS_READ_MATCH_ONLY",
    sequence, headSha, ledgerSha256,
    witnessCasAuthorized: false, dockerLoadAuthorized: false, deployAuthorized: false,
  });
}

/**
 * Fixture-only fresh round trip. This requires a separately controlled witness
 * key and a transport; an injected transport alone can never authorize release.
 * Production must implement and audit authenticated witness CAS independently.
 */
export async function probeIndependentOfflineLedgerWitnessRead({
  exchange, ...expected
} = {}) {
  requireProof(process.env.VIRKI_DISPOSABLE_WITNESS_PROBE === "1" &&
    typeof exchange === "function", "fixture-only witness transport required");
  const challenge = randomBytes(32).toString("hex");
  const responseBytes = await exchange(Object.freeze({
    version: 1, domain: DOMAIN, challenge,
    hostIdentitySha256: expected.hostIdentitySha256,
    ledgerSha256: expected.ledgerSha256,
    sequence: expected.sequence, headSha: expected.headSha,
  }));
  return verifyIndependentOfflineLedgerWitnessRead({
    ...expected, expectedChallenge: challenge, responseBytes,
  });
}
