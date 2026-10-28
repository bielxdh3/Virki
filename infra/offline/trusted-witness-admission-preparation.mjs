import { createHash, createPublicKey, verify } from "node:crypto";
import {
  independentWitnessOwnerCasSigningBytes, verifyIndependentWitnessHead,
  WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN,
} from "../../scripts/lib/offline-independent-witness-service.mjs";
import { validateOfflineLedgerTransition } from "../../scripts/lib/offline-release-ledger.mjs";
import { independentRemoteWitnessConsentSigningBytes } from "./disposable-remote-witness-session.mjs";
import { offlineWitnessLedgerTransitionDigest } from "./disposable-witness-ledger-reservation.mjs";

/*
 * READ-ONLY, NON-AUTHORIZING protocol preparation. This binds a proposed local
 * ledger attempt to owner-signed CAS and consent plus a signed witness HEAD.
 * It does NOT contact a witness, validate a native root installation, possess
 * a nonrollbackable floor, create a durable pre-CAS intent, or reserve a ledger.
 * In particular caller-supplied keys and pins are NEVER trusted host authority.
 *
 * The only networked W1 client is an explicitly disposable localhost fixture.
 * Production MUST refuse admission until a separately owner-installed native
 * authenticated remote session and durable intent + external floor exist.
 */
const DENIED = Object.freeze({
  status: "WITNESS_BINDING_BLOCKED", ledgerAttemptAuthorized: false,
  witnessCasAuthorized: false, dockerLoadAuthorized: false, deployAuthorized: false,
});
const HEX64 = /^[a-f0-9]{64}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const CAS_FIELDS = [
  "version", "domain", "challenge", "requestId", "hostIdentitySha256", "ledgerIdSha256",
  "expectedSequence", "expectedHeadSha", "expectedReceiptSha256", "nextHeadSha",
  "transitionSha256", "ownerExpiresAt", "ownerSignature",
];
const CONSENT_FIELDS = [
  "version", "domain", "endpointHost", "endpointPort", "tlsServerSpkiSha256",
  "tlsClientSpkiSha256", "witnessSignerSpkiSha256", "ownerSignerSpkiSha256",
  "hostIdentitySha256", "ledgerIdSha256", "casRequestSha256", "genesisSha256", "expiresAt",
];
const hash = (data) => createHash("sha256").update(data).digest("hex");
function demand(condition) { if (!condition) throw new Error("Witness admission preparation refused"); }
function exact(value, keys) {
  demand(value && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(keys));
}
function key(pem, pinned) {
  demand(typeof pem === "string" && pem.length <= 4096 && HEX64.test(pinned));
  const opened = createPublicKey(pem);
  demand(opened.asymmetricKeyType === "ed25519" &&
    hash(opened.export({ format: "der", type: "spki" })) === pinned);
  return opened;
}
function signature(value) {
  demand(typeof value === "string" && B64.test(value) &&
    Buffer.from(value, "base64").toString("base64") === value);
  return Buffer.from(value, "base64");
}

/**
 * Untrusted cryptographic cross-check ONLY. A successful result proves that
 * the provided bytes are internally consistent, never that their keys or
 * checkpoint came from an independent operator or current remote witness.
 * No function here can spend owner consent or issue a durable admission token.
 */
export function inspectUntrustedWitnessAdmissionPreparation(input = {}) {
  try {
    exact(input, ["ledgerRequest", "ledgerState", "checkpoint", "casRequest", "consent",
      "consentSignature", "headRequest", "headReceipt", "trust"]);
    const { ledgerRequest, ledgerState, checkpoint, casRequest, consent,
      consentSignature, headRequest, headReceipt, trust } = input;
    exact(trust, ["ownerPublicKeyPem", "ownerPinSha256", "witnessPublicKeyPem",
      "witnessPinSha256", "hostIdentitySha256", "ledgerIdSha256",
      "tlsServerSpkiSha256", "tlsClientSpkiSha256"]);
    demand([trust.ownerPinSha256, trust.witnessPinSha256, trust.hostIdentitySha256,
      trust.ledgerIdSha256, trust.tlsServerSpkiSha256, trust.tlsClientSpkiSha256]
      .every((value) => HEX64.test(value)) && trust.ownerPinSha256 !== trust.witnessPinSha256);
    const ownerKey = key(trust.ownerPublicKeyPem, trust.ownerPinSha256);
    key(trust.witnessPublicKeyPem, trust.witnessPinSha256);
    const transition = validateOfflineLedgerTransition(ledgerState, ledgerRequest);
    demand(transition.entries.length === ledgerRequest.sequence &&
      ledgerRequest.directory === "/var/lib/virki/offline-release");
    exact(checkpoint, ["sequence", "headSha", "receiptSha256"]);
    demand(Number.isSafeInteger(checkpoint.sequence) && checkpoint.sequence >= 0 &&
      checkpoint.sequence === ledgerState.entries.length &&
      HEX64.test(checkpoint.receiptSha256));

    exact(casRequest, CAS_FIELDS);
    const now = Math.floor(Date.now() / 1000);
    demand(casRequest.version === 1 && casRequest.domain === WITNESS_CAS_DOMAIN &&
      casRequest.hostIdentitySha256 === trust.hostIdentitySha256 &&
      casRequest.ledgerIdSha256 === trust.ledgerIdSha256 &&
      HEX64.test(casRequest.challenge) && HEX64.test(casRequest.requestId) &&
      casRequest.expectedSequence === checkpoint.sequence &&
      casRequest.expectedHeadSha === checkpoint.headSha &&
      casRequest.expectedReceiptSha256 === checkpoint.receiptSha256 &&
      casRequest.nextHeadSha === ledgerRequest.nextSha &&
      casRequest.transitionSha256 === offlineWitnessLedgerTransitionDigest(ledgerRequest) &&
      Number.isSafeInteger(casRequest.ownerExpiresAt) &&
      now < casRequest.ownerExpiresAt && casRequest.ownerExpiresAt <= now + 30 &&
      verify(null, independentWitnessOwnerCasSigningBytes(casRequest), ownerKey,
        signature(casRequest.ownerSignature)));

    exact(consent, CONSENT_FIELDS);
    demand(consent.version === 1 &&
      consent.domain === "VIRKI_OFFLINE_REMOTE_WITNESS_CONSENT_V1" &&
      typeof consent.endpointHost === "string" && consent.endpointHost.length > 0 &&
      consent.endpointHost.length <= 253 && Number.isSafeInteger(consent.endpointPort) &&
      consent.endpointPort >= 1024 && consent.endpointPort <= 65535 &&
      consent.ownerSignerSpkiSha256 === trust.ownerPinSha256 &&
      consent.witnessSignerSpkiSha256 === trust.witnessPinSha256 &&
      consent.tlsServerSpkiSha256 === trust.tlsServerSpkiSha256 &&
      consent.tlsClientSpkiSha256 === trust.tlsClientSpkiSha256 &&
      consent.hostIdentitySha256 === trust.hostIdentitySha256 &&
      consent.ledgerIdSha256 === trust.ledgerIdSha256 &&
      HEX64.test(consent.genesisSha256) &&
      consent.casRequestSha256 === hash(Buffer.from(JSON.stringify(casRequest))) &&
      Number.isSafeInteger(consent.expiresAt) && now < consent.expiresAt &&
      consent.expiresAt <= now + 60 &&
      verify(null, independentRemoteWitnessConsentSigningBytes(consent), ownerKey,
        signature(consentSignature)));

    demand(headRequest.version === 1 && headRequest.domain === WITNESS_READ_DOMAIN &&
      headRequest.hostIdentitySha256 === trust.hostIdentitySha256 &&
      headRequest.ledgerIdSha256 === trust.ledgerIdSha256 && HEX64.test(headRequest.challenge));
    const head = verifyIndependentWitnessHead({
      receipt: headReceipt, request: headRequest,
      publicKeyPem: trust.witnessPublicKeyPem, pinSha256: trust.witnessPinSha256,
      minimumSequence: checkpoint.sequence,
      minimumReceiptSha256: checkpoint.receiptSha256,
    });
    demand(head.sequence === checkpoint.sequence && head.headSha === checkpoint.headSha &&
      head.headSha === casRequest.expectedHeadSha);
    return Object.freeze({
      status: "CRYPTOGRAPHIC_BINDING_PREVIEW_ONLY",
      ledgerAttemptAuthorized: false, witnessCasAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false,
    });
  } catch { return DENIED; }
}
