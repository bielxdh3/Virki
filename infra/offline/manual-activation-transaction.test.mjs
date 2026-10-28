import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  MANUAL_ACTIVATION_STAGES, activationSigningBytes,
  previewManualActivationPrepare, previewManualActivationCommit,
} from "./manual-activation-transaction.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const owner = generateKeyPairSync("ed25519");
const witness = generateKeyPairSync("ed25519");
const spki = (key) => sha(key.export({ type: "spki", format: "der" }));
const keys = {
  ownerPublicKeyPem: owner.publicKey.export({ type: "spki", format: "pem" }),
  ownerPinSha256: spki(owner.publicKey),
  witnessPublicKeyPem: witness.publicKey.export({ type: "spki", format: "pem" }),
  witnessPinSha256: spki(witness.publicKey),
};
const hostIdentitySha256 = "a".repeat(64);
const manifestSha256 = "b".repeat(64);
const attemptId = "c".repeat(32);
const firstReceiptSha256 = "d".repeat(64);
const now = () => Math.floor(Date.now() / 1000);
const genesis = () => ({
  version: 1, attemptId, hostIdentitySha256, manifestSha256,
  sequence: 0, receiptSha256: firstReceiptSha256,
  completed: [], pending: null, previousDigest: "0".repeat(64),
});
const signed = (value, key) => ({ message: value, signature: sign(null,
  activationSigningBytes(value), key).toString("base64") });
function evidence(checkpoint, stage) {
  const current = now();
  return {
    keys, measuredHostIdentitySha256: hostIdentitySha256,
    ownerApproval: signed({
      version: 1, domain: "VIRKI_MANUAL_ACTIVATION_OWNER_STAGE_V1", attemptId,
      hostIdentitySha256, manifestSha256, stage,
      sequence: checkpoint.sequence + 1,
      previousDigest: sha(JSON.stringify(checkpoint)), expiresAt: current + 30,
    }, owner.privateKey),
    witnessHead: signed({
      version: 1, domain: "VIRKI_MANUAL_ACTIVATION_INDEPENDENT_HEAD_V1", attemptId,
      hostIdentitySha256, manifestSha256, sequence: checkpoint.sequence + 1,
      receiptSha256: sha(`${stage}:${checkpoint.sequence + 1}`),
      issuedAt: current, expiresAt: current + 30,
    }, witness.privateKey),
  };
}

test("RED: accepted transition is always a nonauthorizing preview with durable intent first", () => {
  const checkpoint = genesis();
  const first = previewManualActivationPrepare({ checkpoint, stage: MANUAL_ACTIVATION_STAGES[0],
    evidence: evidence(checkpoint, MANUAL_ACTIVATION_STAGES[0]) });
  assert.equal(first.status, "PREPARED_PREVIEW_ONLY");
  assert.equal(first.deployAuthorized, false);
  assert.equal(first.checkpoint.pending.stage, "fence-writers");
  assert.deepEqual(first.checkpoint.completed, []);
  assert.equal(previewManualActivationPrepare({ checkpoint: first.checkpoint,
    stage: MANUAL_ACTIVATION_STAGES[0], evidence: evidence(first.checkpoint, "fence-writers") }).status,
  "BLOCKED_MANUAL_ACTIVATION");
});

test("RED: no normal continuation across crash in migration, rollback or restore", () => {
  let checkpoint = genesis();
  for (const stage of MANUAL_ACTIVATION_STAGES.slice(0, 4)) {
    const proof = evidence(checkpoint, stage);
    const prepared = previewManualActivationPrepare({ checkpoint, stage, evidence: proof });
    assert.equal(prepared.status, "PREPARED_PREVIEW_ONLY");
    const committed = previewManualActivationCommit({ checkpoint: prepared.checkpoint,
      stage, evidence: proof, observed: { stage, result: "completed", snapshotSha256: sha(stage) } });
    assert.equal(committed.status, "COMMITTED_PREVIEW_ONLY");
    checkpoint = committed.checkpoint;
  }
  const migration = MANUAL_ACTIVATION_STAGES[4];
  const pending = previewManualActivationPrepare({ checkpoint, stage: migration,
    evidence: evidence(checkpoint, migration) }).checkpoint;
  assert.equal(pending.pending.stage, "migrate-live");
  for (const stage of ["migrate-live", "rollback-restore", "activate-runtime", "resume-writers"]) {
    assert.equal(previewManualActivationPrepare({ checkpoint: pending, stage,
      evidence: evidence(pending, stage) }).status, "BLOCKED_MANUAL_ACTIVATION");
  }
  assert.equal(previewManualActivationCommit({ checkpoint: pending, stage: migration,
    observed: { stage: migration, result: "unknown", snapshotSha256: sha(migration) } }).status,
  "BLOCKED_MANUAL_ACTIVATION");
});

test("RED: reject forged, expired, cross-host, reordered and replayed authority", () => {
  const checkpoint = genesis();
  const stage = MANUAL_ACTIVATION_STAGES[0];
  const original = evidence(checkpoint, stage);
  const call = (proof) => previewManualActivationPrepare({ checkpoint, stage, evidence: proof });
  assert.equal(call(original).status, "PREPARED_PREVIEW_ONLY");
  assert.equal(call({ ...original, measuredHostIdentitySha256: "f".repeat(64) }).status,
    "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(call({ ...original, ownerApproval: {
    ...original.ownerApproval, signature: sign(null, activationSigningBytes(original.ownerApproval.message),
      witness.privateKey).toString("base64") } }).status, "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(call({ ...original, ownerApproval: signed({
    ...original.ownerApproval.message, expiresAt: now() - 1,
  }, owner.privateKey) }).status, "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(call({ ...original, witnessHead: signed({
    ...original.witnessHead.message, sequence: 0,
  }, witness.privateKey) }).status, "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(call({ ...original, witnessHead: signed({
    ...original.witnessHead.message, hostIdentitySha256: "f".repeat(64),
  }, witness.privateKey) }).status, "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(previewManualActivationPrepare({ checkpoint,
    stage: "activate-runtime", evidence: original }).status, "BLOCKED_MANUAL_ACTIVATION");
});

test("RED: commit needs original immutable snapshot evidence and cannot invent rollback success", () => {
  const checkpoint = genesis();
  const stage = MANUAL_ACTIVATION_STAGES[0];
  const proof = evidence(checkpoint, stage);
  const prepared = previewManualActivationPrepare({ checkpoint, stage, evidence: proof });
  assert.equal(prepared.status, "PREPARED_PREVIEW_ONLY");
  assert.equal(previewManualActivationCommit({ checkpoint: prepared.checkpoint, stage,
    evidence: proof, observed: { stage, result: "completed", snapshotSha256: "no" } }).status,
  "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(previewManualActivationCommit({ checkpoint: checkpoint, stage,
    evidence: proof, observed: { stage, result: "completed", snapshotSha256: sha(stage) } }).status,
  "BLOCKED_MANUAL_ACTIVATION");
  const successful = previewManualActivationCommit({ checkpoint: prepared.checkpoint, stage,
    evidence: proof, observed: { stage, result: "completed", snapshotSha256: sha(stage) } });
  assert.equal(successful.status, "COMMITTED_PREVIEW_ONLY");
  assert.equal(successful.checkpoint.completed[0].stage, stage);
  assert.equal(successful.deployAuthorized, false);
});

test("RED: commit must reauthenticate signed host/owner/witness use-time material", () => {
  const checkpoint = genesis();
  const stage = MANUAL_ACTIVATION_STAGES[0];
  const proof = evidence(checkpoint, stage);
  const prepared = previewManualActivationPrepare({ checkpoint, stage, evidence: proof });
  const observed = { stage, result: "completed", snapshotSha256: sha(stage) };
  const attempt = (material) => previewManualActivationCommit({ checkpoint: prepared.checkpoint,
    stage, observed, evidence: material }).status;
  assert.equal(attempt(proof), "COMMITTED_PREVIEW_ONLY");
  assert.equal(previewManualActivationCommit({ checkpoint: prepared.checkpoint, stage, observed }).status,
    "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(attempt({ ...proof, measuredHostIdentitySha256: "e".repeat(64) }),
    "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(attempt({ ...proof, ownerApproval: signed({
    ...proof.ownerApproval.message, previousDigest: "f".repeat(64),
  }, owner.privateKey) }), "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(attempt({ ...proof, witnessHead: signed({
    ...proof.witnessHead.message, receiptSha256: "9".repeat(64),
  }, witness.privateKey) }), "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(attempt({ ...proof, ownerApproval: signed({
    ...proof.ownerApproval.message, expiresAt: now() - 1,
  }, owner.privateKey) }), "BLOCKED_MANUAL_ACTIVATION");
});
