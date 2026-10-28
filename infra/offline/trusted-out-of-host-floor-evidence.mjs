import { createHash, createPublicKey, verify } from "node:crypto";
import {
  independentWitnessOwnerCasSigningBytes, verifyIndependentWitnessCasReceipt,
  verifyIndependentWitnessHead, WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN,
} from "../../scripts/lib/offline-independent-witness-service.mjs";

/*
 * Source-only, read-only contract for evidence from TWO different remote
 * principals: a CAS witness and an independently signing monotonic floor.
 * This does not connect to either service. Supplied pins are not installed
 * authority, and a valid-looking signature cannot establish off-host custody.
 * The native coordinator does not import this module; no successful result
 * authorizes a ledger attempt, Docker action, transfer or deployment.
 */
export const FLOOR_READ_DOMAIN = "VIRKI_OFFLINE_EXTERNAL_CUSTODY_FLOOR_V1";
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const PINS = [
  "ownerPublicKeyPem", "ownerPinSha256", "witnessPublicKeyPem",
  "witnessPinSha256", "floorPublicKeyPem", "floorPinSha256",
];
const SCOPE = ["hostIdentitySha256", "ledgerIdSha256"];
const HEAD = ["version", "domain", "challenge", ...SCOPE];
const FLOOR_REQUEST = [...HEAD, "phase", "casRequestSha256"];
const FLOOR_MESSAGE = [...FLOOR_REQUEST, "sequence", "headSha",
  "receiptSha256", "issuedAt", "expiresAt"];
const CAS_FIELDS = [
  "version", "domain", "challenge", "requestId", ...SCOPE,
  "expectedSequence", "expectedHeadSha", "expectedReceiptSha256",
  "nextHeadSha", "transitionSha256", "ownerExpiresAt", "ownerSignature",
];
const EXPECTED = [...SCOPE, "sequence", "headSha", "receiptSha256"];
const INPUT = [
  "phase", "pins", "expected", "casRequest", "casReceipt",
  "headRequest", "headReceipt", "floorRequest", "floorReceipt", "ack",
];
const DENIED = Object.freeze({
  status: "EXTERNAL_FLOOR_BLOCKED", ledgerAttemptAuthorized: false,
  witnessCasAuthorized: false, transferAuthorized: false,
  dockerLoadAuthorized: false, deployAuthorized: false,
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
const check = (value) => { if (!value) throw new Error("External floor evidence refused"); };
const exact = (value, fields) => check(
  value !== null && typeof value === "object" && !Array.isArray(value) &&
  JSON.stringify(Object.keys(value)) === JSON.stringify(fields));
const signature = (value) => {
  check(typeof value === "string" && B64.test(value) &&
    Buffer.from(value, "base64").toString("base64") === value);
  return Buffer.from(value, "base64");
};
function pinnedKey(pem, expected) {
  check(typeof pem === "string" && pem.length <= 4096 && HEX64.test(expected));
  const key = createPublicKey(pem);
  check(key.asymmetricKeyType === "ed25519" &&
    hash(key.export({ format: "der", type: "spki" })) === expected);
  return key;
}

/** Untrusted evidence cross-check; a successful status is never authority. */
export function inspectUntrustedExternalFloorEvidence(input = {}) {
  try {
    exact(input, INPUT);
    const { phase, pins, expected, casRequest, casReceipt, headRequest,
      headReceipt, floorRequest, floorReceipt, ack } = input;
    check(phase === "before" || phase === "after");
    exact(pins, PINS);
    exact(expected, EXPECTED);
    exact(headRequest, HEAD);
    exact(floorRequest, FLOOR_REQUEST);
    exact(floorReceipt, ["message", "signature"]);
    exact(floorReceipt.message, FLOOR_MESSAGE);
    exact(casRequest, CAS_FIELDS);
    check([pins.ownerPinSha256, pins.witnessPinSha256, pins.floorPinSha256]
      .every((v) => HEX64.test(v)) &&
      new Set([pins.ownerPinSha256, pins.witnessPinSha256, pins.floorPinSha256]).size === 3);
    const ownerKey = pinnedKey(pins.ownerPublicKeyPem, pins.ownerPinSha256);
    pinnedKey(pins.witnessPublicKeyPem, pins.witnessPinSha256);
    const floorKey = pinnedKey(pins.floorPublicKeyPem, pins.floorPinSha256);
    check([expected.hostIdentitySha256, expected.ledgerIdSha256,
      headRequest.challenge, casRequest.challenge, casRequest.requestId,
      casRequest.transitionSha256, expected.receiptSha256].every((v) => HEX64.test(v)) &&
      HEX40.test(expected.headSha) &&
      Number.isSafeInteger(expected.sequence) && expected.sequence >= 0 &&
      headRequest.version === 1 && headRequest.domain === WITNESS_READ_DOMAIN &&
      casRequest.version === 1 && casRequest.domain === WITNESS_CAS_DOMAIN &&
      casRequest.hostIdentitySha256 === expected.hostIdentitySha256 &&
      casRequest.ledgerIdSha256 === expected.ledgerIdSha256 &&
      headRequest.hostIdentitySha256 === expected.hostIdentitySha256 &&
      headRequest.ledgerIdSha256 === expected.ledgerIdSha256 &&
      casRequest.expectedSequence === expected.sequence &&
      casRequest.expectedHeadSha === expected.headSha &&
      casRequest.expectedReceiptSha256 === expected.receiptSha256 &&
      HEX40.test(casRequest.nextHeadSha) &&
      casRequest.nextHeadSha !== expected.headSha &&
      Number.isSafeInteger(casRequest.ownerExpiresAt) &&
      Math.floor(Date.now() / 1000) < casRequest.ownerExpiresAt &&
      verify(null, independentWitnessOwnerCasSigningBytes(casRequest),
        ownerKey, signature(casRequest.ownerSignature)));

    const requestHash = hash(Buffer.from(JSON.stringify(casRequest)));
    check(floorRequest.version === 1 && floorRequest.domain === FLOOR_READ_DOMAIN &&
      floorRequest.phase === phase &&
      floorRequest.challenge === headRequest.challenge &&
      floorRequest.hostIdentitySha256 === expected.hostIdentitySha256 &&
      floorRequest.ledgerIdSha256 === expected.ledgerIdSha256 &&
      floorRequest.casRequestSha256 === requestHash);
    const floor = floorReceipt.message;
    check(FLOOR_REQUEST.every((field) => floor[field] === floorRequest[field]) &&
      Number.isSafeInteger(floor.sequence) && floor.sequence >= 0 &&
      HEX40.test(floor.headSha) && HEX64.test(floor.receiptSha256) &&
      Number.isSafeInteger(floor.issuedAt) && Number.isSafeInteger(floor.expiresAt) &&
      floor.issuedAt <= Math.floor(Date.now() / 1000) &&
      Math.floor(Date.now() / 1000) < floor.expiresAt &&
      floor.issuedAt >= Math.floor(Date.now() / 1000) - 30 &&
      floor.expiresAt === floor.issuedAt + 30 &&
      verify(null, Buffer.from(FLOOR_READ_DOMAIN + "\0" + JSON.stringify(floor)),
        floorKey, signature(floorReceipt.signature)));

    const minimum = phase === "before" ? expected.sequence : expected.sequence + 1;
    const head = verifyIndependentWitnessHead({
      receipt: headReceipt, request: headRequest,
      publicKeyPem: pins.witnessPublicKeyPem, pinSha256: pins.witnessPinSha256,
      minimumSequence: minimum,
    });
    check(head.sequence === floor.sequence && head.headSha === floor.headSha &&
      head.receiptSha256 === floor.receiptSha256);
    if (phase === "before") {
      check(ack === "not-sent" && casReceipt === null &&
        floor.sequence === expected.sequence &&
        floor.headSha === expected.headSha &&
        floor.receiptSha256 === expected.receiptSha256);
    } else {
      // An ambiguous/lost ACK can mean the remote CAS committed, but cannot
      // be silently reconciled using a later HEAD or an uninstalled floor.
      check(ack === "confirmed" && casReceipt !== null);
      const acknowledged = verifyIndependentWitnessCasReceipt({
        receipt: casReceipt, request: casRequest,
        publicKeyPem: pins.witnessPublicKeyPem,
        pinSha256: pins.witnessPinSha256,
        ownerPublicKeyPem: pins.ownerPublicKeyPem,
        ownerPinSha256: pins.ownerPinSha256,
      });
      check(floor.sequence === expected.sequence + 1 &&
        floor.headSha === casRequest.nextHeadSha &&
        floor.receiptSha256 === acknowledged.receiptSha256 &&
        floor.issuedAt >= casReceipt.message.issuedAt);
    }
    return Object.freeze({
      status: "EXTERNAL_FLOOR_EVIDENCE_PREVIEW_ONLY",
      ledgerAttemptAuthorized: false, witnessCasAuthorized: false,
      transferAuthorized: false, dockerLoadAuthorized: false,
      deployAuthorized: false,
    });
  } catch { return DENIED; }
}
