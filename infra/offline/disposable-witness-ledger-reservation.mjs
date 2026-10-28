import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { validateOfflineLedgerTransition } from "../../scripts/lib/offline-release-ledger.mjs";
import {
  GENESIS_HEAD, GENESIS_RECEIPT, WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN,
  independentWitnessOwnerCasSigningBytes, verifyIndependentWitnessCasReceipt,
  verifyIndependentWitnessHead,
} from "../../scripts/lib/offline-independent-witness-service.mjs";

// A DISPOSABLE, NON-AUTHORIZING composition contract, NOT an installed release
// coordinator or authenticated remote witness client. In particular, supplying
// callbacks/public keys is NOT a production trust root. The real coordinator
// must remain disconnected until owner-provisioned independent remote custody,
// authenticated transport and durable checkpoint/reconciliation exist.
const DOMAIN = "VIRKI_OFFLINE_WITNESS_LEDGER_RESERVATION_V1";
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const CAS_FIELDS = [
  "version", "domain", "challenge", "requestId", "hostIdentitySha256", "ledgerIdSha256",
  "expectedSequence", "expectedHeadSha", "expectedReceiptSha256", "nextHeadSha",
  "transitionSha256", "ownerExpiresAt", "ownerSignature",
];
const LEDGER_FIELDS = [
  "directory", "manifestSha256", "priorSha", "nextSha", "nonce", "sequence", "approvalDigest",
];
const BLOCKED = "Disposable witnessed ledger reservation blocked";

function requireIt(ok) { if (!ok) throw new Error(BLOCKED); }
function exact(value, fields) {
  requireIt(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field)));
}
const digest = (data) => createHash("sha256").update(data).digest("hex");

/** Domain-separated digest of the EXACT ledger attempt, including its directory. */
export function offlineWitnessLedgerTransitionDigest(request) {
  exact(request, LEDGER_FIELDS);
  const entry = Object.fromEntries(LEDGER_FIELDS.map((field) => [field, request[field]]));
  return digest(Buffer.from(`${DOMAIN}\0${JSON.stringify(entry)}`));
}

/**
 * Verify an owner-authorized CAS against a fresh witness HEAD *before* invoking
 * any ledger reservation. No retry, reset, rollback or release authorization.
 * A CAS succeeded but local reservation failed (or the response was lost) is
 * an unreconciled, irreversible condition requiring external operator action.
 *
 * Only disposable tests may inject these callbacks. The remote identity,
 * independently held checkpoints and owner keys have no production provider.
 */
export async function reserveDisposableWitnessedLedgerAttempt(input) {
  try {
    requireIt(process.platform === "linux" &&
      process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE === "1");
    requireIt(input && typeof input === "object" && !Array.isArray(input));
    const {
      ledgerState, ledgerRequest, ownerCasRequest: unsafeCasRequest,
      scope: unsafeScope, keys: unsafeKeys, checkpoint: unsafeCheckpoint,
      readWitness, casWitness, reserveAttempt,
    } = input;
    requireIt(typeof readWitness === "function" && typeof casWitness === "function" &&
      typeof reserveAttempt === "function");
    exact(ledgerRequest, LEDGER_FIELDS);
    const accepted = Object.freeze({ ...ledgerRequest });
    // Snapshot all caller-supplied authority-bearing values BEFORE any await.
    // Otherwise a signer with another valid approval can swap the CAS target
    // between the HEAD read and CAS and consume witness state for the wrong SHA.
    exact(unsafeCasRequest, CAS_FIELDS);
    const ownerCasRequest = Object.freeze({ ...unsafeCasRequest });
    exact(unsafeScope, ["hostIdentitySha256", "ledgerIdSha256"]);
    const scope = Object.freeze({ ...unsafeScope });
    exact(unsafeKeys, ["publicKeyPem", "pinSha256", "ownerPublicKeyPem", "ownerPinSha256"]);
    const keys = Object.freeze({ ...unsafeKeys });
    exact(unsafeCheckpoint, ["sequence", "receiptSha256"]);
    const checkpoint = Object.freeze({ ...unsafeCheckpoint });
    const updated = validateOfflineLedgerTransition(ledgerState, accepted);
    const expectedState = JSON.stringify(ledgerState);
    const expectedEntry = updated.entries.at(-1);
    requireIt(expectedEntry.sequence === accepted.sequence &&
      expectedEntry.nextSha === accepted.nextSha);

    exact(scope, ["hostIdentitySha256", "ledgerIdSha256"]);
    requireIt(HEX64.test(scope.hostIdentitySha256) && HEX64.test(scope.ledgerIdSha256));
    exact(checkpoint, ["sequence", "receiptSha256"]);
    requireIt(Number.isSafeInteger(checkpoint.sequence) && checkpoint.sequence >= 0 &&
      checkpoint.sequence === ledgerState.entries.length && HEX64.test(checkpoint.receiptSha256) &&
      (checkpoint.sequence !== 0 || checkpoint.receiptSha256 === GENESIS_RECEIPT));
    exact(keys, ["publicKeyPem", "pinSha256", "ownerPublicKeyPem", "ownerPinSha256"]);
    requireIt(HEX64.test(keys.pinSha256) && HEX64.test(keys.ownerPinSha256) &&
      keys.pinSha256 !== keys.ownerPinSha256);
    const ownerKey = createPublicKey(keys.ownerPublicKeyPem);
    requireIt(ownerKey.asymmetricKeyType === "ed25519" &&
      digest(ownerKey.export({ format: "der", type: "spki" })) === keys.ownerPinSha256);
    exact(ownerCasRequest, CAS_FIELDS);
    const expectedHead = accepted.sequence === 1 ? GENESIS_HEAD : accepted.priorSha;
    requireIt(ownerCasRequest.version === 1 && ownerCasRequest.domain === WITNESS_CAS_DOMAIN &&
      HEX64.test(ownerCasRequest.challenge) && HEX64.test(ownerCasRequest.requestId) &&
      ownerCasRequest.hostIdentitySha256 === scope.hostIdentitySha256 &&
      ownerCasRequest.ledgerIdSha256 === scope.ledgerIdSha256 &&
      ownerCasRequest.expectedSequence === checkpoint.sequence &&
      ownerCasRequest.expectedHeadSha === expectedHead && HEX40.test(expectedHead) &&
      ownerCasRequest.expectedReceiptSha256 === checkpoint.receiptSha256 &&
      ownerCasRequest.nextHeadSha === accepted.nextSha &&
      ownerCasRequest.transitionSha256 === offlineWitnessLedgerTransitionDigest(accepted) &&
      Number.isSafeInteger(ownerCasRequest.ownerExpiresAt));
    const now = Math.floor(Date.now() / 1000);
    requireIt(now < ownerCasRequest.ownerExpiresAt && ownerCasRequest.ownerExpiresAt <= now + 30 &&
      typeof ownerCasRequest.ownerSignature === "string" &&
      /^[A-Za-z0-9+/]{86}==$/u.test(ownerCasRequest.ownerSignature) &&
      verify(null, independentWitnessOwnerCasSigningBytes(ownerCasRequest), ownerKey,
        Buffer.from(ownerCasRequest.ownerSignature, "base64")));

    const headRequest = Object.freeze({
      version: 1, domain: WITNESS_READ_DOMAIN, challenge: randomBytes(32).toString("hex"),
      hostIdentitySha256: scope.hostIdentitySha256, ledgerIdSha256: scope.ledgerIdSha256,
    });
    const headReceipt = await readWitness(headRequest);
    const head = verifyIndependentWitnessHead({
      receipt: headReceipt, request: headRequest,
      publicKeyPem: keys.publicKeyPem, pinSha256: keys.pinSha256,
      minimumSequence: checkpoint.sequence,
      minimumReceiptSha256: checkpoint.receiptSha256,
    });
    requireIt(head.sequence === checkpoint.sequence && head.headSha === expectedHead &&
      head.receiptSha256 === checkpoint.receiptSha256);
    const receipt = await casWitness(ownerCasRequest);
    const checked = verifyIndependentWitnessCasReceipt({
      receipt, request: ownerCasRequest, ...keys,
    });
    requireIt(checked.sequence === accepted.sequence && checked.headSha === accepted.nextSha &&
      JSON.stringify(ledgerState) === expectedState);
    // The ledger persistence primitive must independently revalidate the exact
    // state and acquire its own durable O_EXCL attempt lock. This fixture must
    // never silently retry a consumed witness CAS or clear an attempt lock.
    const attempt = await reserveAttempt(accepted);
    requireIt(attempt && attempt.status === "attempted" &&
      attempt.pendingSha === accepted.nextSha && attempt.sequence === accepted.sequence);
    return Object.freeze({
      status: "witnessed-attempt-disposable-only", pendingSha: accepted.nextSha,
      sequence: accepted.sequence, receiptSha256: checked.receiptSha256,
      witnessCasAuthorized: false, transferAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false,
    });
  } catch {
    // No sensitive errors, witness request or signing material are surfaced.
    throw new Error(BLOCKED);
  }
}
