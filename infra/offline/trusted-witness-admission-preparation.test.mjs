import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  GENESIS_HEAD, GENESIS_RECEIPT, WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN,
  independentWitnessOwnerCasSigningBytes,
} from "../../scripts/lib/offline-independent-witness-service.mjs";
import { independentRemoteWitnessConsentSigningBytes } from "./disposable-remote-witness-session.mjs";
import { offlineWitnessLedgerTransitionDigest } from "./disposable-witness-ledger-reservation.mjs";

const digest = (v) => createHash("sha256").update(v).digest("hex");
const pin = (key) => digest(key.export({ type: "spki", format: "der" }));
const publicPem = (key) => key.export({ type: "spki", format: "pem" });
const signed = (value, key) => sign(null, Buffer.from(JSON.stringify(value)), key).toString("base64");
const receipt = (message, key) => {
  const signature = signed(message, key);
  return { message, signature, receiptSha256: digest(JSON.stringify({ message, signature })) };
};

function fixture() {
  const now = Math.floor(Date.now() / 1000);
  const owner = generateKeyPairSync("ed25519");
  const witness = generateKeyPairSync("ed25519");
  const ledgerRequest = {
    directory: "/var/lib/virki/offline-release",
    manifestSha256: "a".repeat(64), priorSha: GENESIS_HEAD,
    nextSha: "b".repeat(40), nonce: "c".repeat(32), sequence: 1,
    approvalDigest: "d".repeat(64),
  };
  const ledgerState = { version: 1, anchorSha: GENESIS_HEAD, entries: [] };
  const checkpoint = { sequence: 0, headSha: GENESIS_HEAD, receiptSha256: GENESIS_RECEIPT };
  const host = "e".repeat(64), ledger = "f".repeat(64);
  const request = {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: "1".repeat(64), requestId: "2".repeat(64),
    hostIdentitySha256: host, ledgerIdSha256: ledger,
    expectedSequence: 0, expectedHeadSha: GENESIS_HEAD,
    expectedReceiptSha256: GENESIS_RECEIPT, nextHeadSha: ledgerRequest.nextSha,
    transitionSha256: offlineWitnessLedgerTransitionDigest(ledgerRequest), ownerExpiresAt: now + 25,
  };
  const casRequest = {
    ...request, ownerSignature: sign(null, independentWitnessOwnerCasSigningBytes(request),
      owner.privateKey).toString("base64"),
  };
  const consent = {
    version: 1, domain: "VIRKI_OFFLINE_REMOTE_WITNESS_CONSENT_V1",
    endpointHost: "localhost", endpointPort: 54321,
    tlsServerSpkiSha256: "3".repeat(64), tlsClientSpkiSha256: "4".repeat(64),
    witnessSignerSpkiSha256: pin(witness.publicKey), ownerSignerSpkiSha256: pin(owner.publicKey),
    hostIdentitySha256: host, ledgerIdSha256: ledger,
    casRequestSha256: digest(JSON.stringify(casRequest)), genesisSha256: "5".repeat(64),
    expiresAt: now + 30,
  };
  const headRequest = { version: 1, domain: WITNESS_READ_DOMAIN, challenge: "6".repeat(64),
    hostIdentitySha256: host, ledgerIdSha256: ledger };
  const headReceipt = receipt({
    ...headRequest, sequence: 0, headSha: GENESIS_HEAD, receiptSha256: GENESIS_RECEIPT,
    issuedAt: now, expiresAt: now + 30,
  }, witness.privateKey);
  const trust = {
    ownerPublicKeyPem: publicPem(owner.publicKey), ownerPinSha256: pin(owner.publicKey),
    witnessPublicKeyPem: publicPem(witness.publicKey), witnessPinSha256: pin(witness.publicKey),
    hostIdentitySha256: host, ledgerIdSha256: ledger,
    tlsServerSpkiSha256: consent.tlsServerSpkiSha256,
    tlsClientSpkiSha256: consent.tlsClientSpkiSha256,
  };
  return { ledgerRequest, ledgerState, checkpoint, casRequest, consent,
    consentSignature: sign(null, independentRemoteWitnessConsentSigningBytes(consent),
      owner.privateKey).toString("base64"), headRequest, headReceipt, trust };
}

async function prepare(input) {
  const { inspectUntrustedWitnessAdmissionPreparation } =
    await import("./trusted-witness-admission-preparation.mjs");
  return inspectUntrustedWitnessAdmissionPreparation(input);
}

const linuxOnly = { skip: process.platform !== "linux" ? "POSIX ledger binding requires Linux" : false };

test("signed owner consent and signed HEAD prove only binding, never trusted admission", linuxOnly, async () => {
  const result = await prepare(fixture());
  assert.equal(result.status, "CRYPTOGRAPHIC_BINDING_PREVIEW_ONLY");
  assert.equal(result.witnessCasAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.ledgerAttemptAuthorized, false);
  assert.equal(result.dockerLoadAuthorized, false);
});

test("coordinator derives the identical immutable ledger transition from actual checked signature bytes", async () => {
  const { deriveCheckedOfflineLedgerRequest } = await import("./trusted-release-coordinator.mjs");
  assert.equal(typeof deriveCheckedOfflineLedgerRequest, "function");
  const checked = fixture().ledgerRequest;
  const manifest = {
    source_sha: checked.nextSha, predecessor_sha: checked.priorSha,
    nonce: checked.nonce, sequence: checked.sequence,
  };
  const ownerSignature = Buffer.alloc(64, 0x42).toString("base64");
  const derived = deriveCheckedOfflineLedgerRequest({ manifest,
    verifiedManifestSha256: checked.manifestSha256,
    checkedSourceSha: checked.nextSha, checkedOwnerSignature: ownerSignature });
  const expectedApproval = digest(Buffer.concat([
    Buffer.from("VIRKI_OFFLINE_COORDINATOR_OWNER_APPROVAL_V1\0"),
    Buffer.from(checked.manifestSha256, "hex"), Buffer.from(ownerSignature, "base64"),
  ]));
  assert.deepEqual(derived, { ...checked, approvalDigest: expectedApproval });
  assert.ok(Object.isFrozen(derived));
  assert.throws(() => deriveCheckedOfflineLedgerRequest({ manifest: {
    ...manifest, source_sha: "f".repeat(40),
  }, verifiedManifestSha256: checked.manifestSha256,
  checkedSourceSha: checked.nextSha, checkedOwnerSignature: ownerSignature }));
});

test("arbitrary syntactically valid forged manifest hash and owner signature never enable coordinator admission", async () => {
  const { deriveCheckedOfflineLedgerRequest, coordinateTrustedOfflineRelease } =
    await import("./trusted-release-coordinator.mjs");
  const attempt = fixture().ledgerRequest;
  const forged = deriveCheckedOfflineLedgerRequest({
    manifest: { source_sha: attempt.nextSha, predecessor_sha: attempt.priorSha,
      nonce: attempt.nonce, sequence: attempt.sequence },
    verifiedManifestSha256: "0".repeat(64), checkedSourceSha: attempt.nextSha,
    checkedOwnerSignature: Buffer.alloc(64, 0x42).toString("base64"),
  });
  assert.equal(forged.manifestSha256, "0".repeat(64)); // Shape, NOT independent verification.
  const denied = await coordinateTrustedOfflineRelease({
    candidateDirectory: "/tmp/unauthenticated-candidate", ledgerRequest: forged,
  });
  assert.equal(denied.status, "blocked");
  assert.equal(denied.deployAuthorized, false);
});

test("missing independent witness, wrong revision, predecessor, sequence, or account/host scope refuse", linuxOnly, async () => {
  for (const mutation of [
    (v) => { delete v.headReceipt; },
    (v) => { v.ledgerRequest.nextSha = "9".repeat(40); },
    (v) => { v.ledgerRequest.priorSha = "7".repeat(40); },
    (v) => { v.ledgerRequest.sequence = 2; },
    (v) => { v.trust.hostIdentitySha256 = "9".repeat(64); },
    (v) => { v.trust.ledgerIdSha256 = "9".repeat(64); },
  ]) {
    const input = fixture(); mutation(input);
    assert.equal((await prepare(input)).status, "WITNESS_BINDING_BLOCKED");
  }
});

test("forged signer or tampered signed consent, replay, stale floor and stale signed HEAD refuse", linuxOnly, async () => {
  for (const mutation of [
    (v) => { v.consent.endpointPort += 1; },
    (v) => { v.casRequest.ownerSignature = "A".repeat(86) + "=="; },
    (v) => { v.trust.witnessPinSha256 = "0".repeat(64); },
    (v) => { v.checkpoint.sequence = 1; },
    (v) => { v.checkpoint.receiptSha256 = "8".repeat(64); },
    (v) => { v.headReceipt.message.challenge = "0".repeat(64); },
    (v) => { v.consent.expiresAt = 1; },
    (v) => { v.casRequest.ownerExpiresAt = 1; },
  ]) {
    const input = fixture(); mutation(input);
    assert.equal((await prepare(input)).status, "WITNESS_BINDING_BLOCKED");
  }
});

test("unverified CAS ACK, checkpoint path, signer override and transport hooks can never be promoted", linuxOnly, async () => {
  for (const [field, value] of [
    ["casReceipt", { message: { status: "committed" } }],
    ["checkpointPath", "/tmp/controlled-checkpoint"],
    ["operatorTrustRoot", "/tmp/controlled-owner-key"],
    ["transport", { head: () => {}, cas: () => {} }],
    ["trusted", true],
  ]) {
    const input = fixture(); input[field] = value;
    const result = await prepare(input);
    assert.equal(result.status, "WITNESS_BINDING_BLOCKED");
    assert.equal(result.witnessCasAuthorized, false);
    assert.equal(result.ledgerAttemptAuthorized, false);
    assert.equal(result.deployAuthorized, false);
  }
});

test("caller-provided signer keys cannot be passed to the installed coordinator as authority", async () => {
  const { coordinateTrustedOfflineRelease } = await import("./trusted-release-coordinator.mjs");
  const result = await coordinateTrustedOfflineRelease({ candidateDirectory: "/tmp/fake", ...fixture() });
  assert.equal(result.status, "blocked");
  assert.equal(result.deployAuthorized, false);
});
