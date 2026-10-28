import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN,
  independentWitnessOwnerCasSigningBytes,
} from "../../scripts/lib/offline-independent-witness-service.mjs";
import { inspectUntrustedExternalFloorEvidence, FLOOR_READ_DOMAIN } from "./trusted-out-of-host-floor-evidence.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const pem = (key) => key.export({ type: "spki", format: "pem" });
const pin = (key) => sha(key.export({ type: "spki", format: "der" }));
const sig = (value, key, domain = "") => sign(null,
  Buffer.from(domain ? domain + "\0" + JSON.stringify(value) : JSON.stringify(value)),
  key).toString("base64");
const receipt = (message, privateKey) => {
  const signature = sig(message, privateKey);
  return { message, signature, receiptSha256: sha(JSON.stringify({ message, signature })) };
};
const now = () => Math.floor(Date.now() / 1000);

function fixture() {
  const owner = generateKeyPairSync("ed25519");
  const witness = generateKeyPairSync("ed25519");
  const floor = generateKeyPairSync("ed25519");
  const keys = {
    ownerPublicKeyPem: pem(owner.publicKey), ownerPinSha256: pin(owner.publicKey),
    witnessPublicKeyPem: pem(witness.publicKey), witnessPinSha256: pin(witness.publicKey),
    floorPublicKeyPem: pem(floor.publicKey), floorPinSha256: pin(floor.publicKey),
  };
  const host = "a".repeat(64), ledger = "b".repeat(64);
  const old = "c".repeat(40), next = "d".repeat(40);
  const previousReceipt = "e".repeat(64);
  const base = { hostIdentitySha256: host, ledgerIdSha256: ledger };
  const unsigned = {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: "1".repeat(64),
    requestId: "2".repeat(64), ...base, expectedSequence: 3,
    expectedHeadSha: old, expectedReceiptSha256: previousReceipt,
    nextHeadSha: next, transitionSha256: "3".repeat(64),
    ownerExpiresAt: now() + 25,
  };
  const casRequest = { ...unsigned,
    ownerSignature: sign(null, independentWitnessOwnerCasSigningBytes(unsigned),
      owner.privateKey).toString("base64") };
  const afterMessage = {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: casRequest.challenge,
    requestId: casRequest.requestId, ...base, sequence: 4,
    priorHeadSha: old, headSha: next,
    previousReceiptSha256: previousReceipt,
    transitionSha256: casRequest.transitionSha256,
    ownerSignature: casRequest.ownerSignature,
    ownerSignatureSha256: sha(casRequest.ownerSignature),
    ownerExpiresAt: casRequest.ownerExpiresAt,
    issuedAt: now(), expiresAt: now() + 30,
  };
  const casReceipt = receipt(afterMessage, witness.privateKey);
  function input(phase = "before") {
    const after = phase === "after";
    const current = {
      sequence: after ? 4 : 3, headSha: after ? next : old,
      receiptSha256: after ? casReceipt.receiptSha256 : previousReceipt,
    };
    const headRequest = {
      version: 1, domain: WITNESS_READ_DOMAIN, challenge: "4".repeat(64),
      ...base,
    };
    const headReceipt = receipt({ ...headRequest, ...current, issuedAt: now(),
      expiresAt: now() + 30 }, witness.privateKey);
    const floorRequest = {
      version: 1, domain: FLOOR_READ_DOMAIN, challenge: headRequest.challenge,
      ...base, phase, casRequestSha256: sha(JSON.stringify(casRequest)),
    };
    const floorMessage = { ...floorRequest, ...current, issuedAt: now(),
      expiresAt: now() + 30 };
    const floorReceipt = { message: floorMessage,
      signature: sig(floorMessage, floor.privateKey, FLOOR_READ_DOMAIN) };
    return { phase, pins: keys, expected: {
      ...base, sequence: 3, headSha: old, receiptSha256: previousReceipt,
    }, casRequest, casReceipt: after ? casReceipt : null,
    headRequest, headReceipt, floorRequest, floorReceipt,
    ack: after ? "confirmed" : "not-sent" };
  }
  return { input, floor, witness, owner, casReceipt };
}

test("two independently signed challenge-bound HEAD+floor records are only evidence", () => {
  const { input } = fixture();
  const before = inspectUntrustedExternalFloorEvidence(input("before"));
  const after = inspectUntrustedExternalFloorEvidence(input("after"));
  assert.equal(before.status, "EXTERNAL_FLOOR_EVIDENCE_PREVIEW_ONLY");
  assert.equal(after.status, "EXTERNAL_FLOOR_EVIDENCE_PREVIEW_ONLY");
  for (const result of [before, after])
    assert.deepEqual([result.deployAuthorized, result.ledgerAttemptAuthorized,
      result.witnessCasAuthorized], [false, false, false]);
});

test("rollback, stale floor, and witness fork are rejected", () => {
  for (const mutate of [
    (x) => { x.floorReceipt.message.sequence -= 1; },
    (x) => { x.headReceipt.message.headSha = "f".repeat(40); },
    (x) => { x.floorReceipt.message.headSha = x.expected.headSha; },
    (x) => { x.floorReceipt.message.receiptSha256 = x.expected.receiptSha256; },
    (x) => { x.expected.sequence = 4; },
    (x) => { x.expected.headSha = "0".repeat(40); },
  ]) {
    const x = fixture().input("after"); mutate(x);
    assert.equal(inspectUntrustedExternalFloorEvidence(x).status, "EXTERNAL_FLOOR_BLOCKED");
  }
});

test("missing independent floor or borrowed witness/owner signing authority refuse", () => {
  for (const mutate of [
    (x) => { delete x.floorReceipt; },
    (x) => { x.pins.floorPinSha256 = x.pins.witnessPinSha256;
      x.pins.floorPublicKeyPem = x.pins.witnessPublicKeyPem; },
    (x) => { x.pins.floorPinSha256 = x.pins.ownerPinSha256;
      x.pins.floorPublicKeyPem = x.pins.ownerPublicKeyPem; },
    (x) => { x.floorReceipt.signature = "A".repeat(86) + "=="; },
    (x) => { x.floorReceipt.message.ledgerIdSha256 = "0".repeat(64); },
    (x) => { x.floorReceipt.message.challenge = "0".repeat(64); },
    (x) => { x.floorReceipt.message.expiresAt = 1; },
  ]) {
    const x = fixture().input("before"); mutate(x);
    assert.equal(inspectUntrustedExternalFloorEvidence(x).status, "EXTERNAL_FLOOR_BLOCKED");
  }
});

test("uncertain CAS acknowledgement never silently promotes a remote floor", () => {
  for (const ack of ["unknown", "lost", "timeout", "reconciled-by-caller"]) {
    const x = fixture().input("after"); x.ack = ack;
    assert.equal(inspectUntrustedExternalFloorEvidence(x).status, "EXTERNAL_FLOOR_BLOCKED");
  }
});

test("owner signature and signed receipt must match exact transition", () => {
  for (const mutate of [
    (x) => { x.casRequest.nextHeadSha = "f".repeat(40); },
    (x) => { x.casReceipt.receiptSha256 = "0".repeat(64); },
    (x) => { x.casReceipt.message.ownerSignature = "A".repeat(86) + "=="; },
    (x) => { x.casRequest.transitionSha256 = "f".repeat(64); },
    (x) => { x.floorRequest.casRequestSha256 = "f".repeat(64); },
  ]) {
    const x = fixture().input("after"); mutate(x);
    assert.equal(inspectUntrustedExternalFloorEvidence(x).status, "EXTERNAL_FLOOR_BLOCKED");
  }
});

test("caller cannot add a deploy authorization, transport or self-declared remote custody", () => {
  for (const mutation of ["deployAuthorized", "trustRootPath", "transport", "remoteHosted"]) {
    const x = fixture().input("before"); x[mutation] = true;
    assert.equal(inspectUntrustedExternalFloorEvidence(x).status, "EXTERNAL_FLOOR_BLOCKED");
  }
});
