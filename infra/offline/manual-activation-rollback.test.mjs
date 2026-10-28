import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  manualRollbackSigningBytes, previewManualRollbackReconciliation,
} from "./manual-activation-rollback.mjs";

const hash = (input) => createHash("sha256").update(input).digest("hex");
const owner = generateKeyPairSync("ed25519");
const witness = generateKeyPairSync("ed25519");
const keys = {
  ownerPublicKeyPem: owner.publicKey.export({ type: "spki", format: "pem" }),
  ownerPinSha256: hash(owner.publicKey.export({ type: "spki", format: "der" })),
  witnessPublicKeyPem: witness.publicKey.export({ type: "spki", format: "pem" }),
  witnessPinSha256: hash(witness.publicKey.export({ type: "spki", format: "der" })),
};
const stages = ["fence-writers", "verify-backup", "restore-clone", "migrate-clone"];
function checkpoint() {
  const original = { version: 1, attemptId: "a".repeat(32),
    hostIdentitySha256: "b".repeat(64), manifestSha256: "c".repeat(64),
    sequence: 4, receiptSha256: "d".repeat(64), completed: stages.map((stage) => ({
      stage, result: "completed", snapshotSha256: hash(stage),
    })), pending: null, previousDigest: "e".repeat(64) };
  original.pending = {
    stage: "migrate-live", sequence: 5,
    ownerApprovalSha256: "f".repeat(64), witnessReceiptSha256: "1".repeat(64),
    previousDigest: original.previousDigest,
  };
  return original;
}
function signed(message, privateKey) {
  return { message, signature: sign(null,
    manualRollbackSigningBytes(message), privateKey).toString("base64") };
}
function args(c = checkpoint()) {
  const now = Math.floor(Date.now() / 1000);
  const checkpointSha256 = hash(JSON.stringify(c));
  const baseline = {
    writerFenceSha256: hash(stages[0]), backupSha256: hash(stages[1]),
    restoredCloneSha256: hash(stages[2]),
  };
  return {
    checkpoint: c, baseline, measuredHostIdentitySha256: c.hostIdentitySha256, keys,
    ownerReconciliation: signed({
      version: 1, domain: "VIRKI_MANUAL_ROLLBACK_OWNER_RECONCILIATION_V1",
      attemptId: c.attemptId, hostIdentitySha256: c.hostIdentitySha256,
      manifestSha256: c.manifestSha256, checkpointSha256, ...baseline,
      reason: "ambiguous-live-migration", issuedAt: now, expiresAt: now + 30,
    }, owner.privateKey),
    witnessReconciliation: signed({
      version: 1, domain: "VIRKI_MANUAL_ROLLBACK_WITNESS_HEAD_V1",
      attemptId: c.attemptId, hostIdentitySha256: c.hostIdentitySha256,
      manifestSha256: c.manifestSha256, checkpointSha256,
      sequence: c.sequence + 1, receiptSha256: "2".repeat(64),
      issuedAt: now, expiresAt: now + 30,
    }, witness.privateKey),
  };
}

test("RED: interrupted live migration yields only isolated owner-reviewed rollback plan", () => {
  const result = previewManualRollbackReconciliation(args());
  assert.equal(result.status, "ROLLBACK_RECONCILIATION_PREVIEW_ONLY");
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.rollbackAuthorized, false);
  assert.deepEqual(result.requiredPhases, [
    "prove-writers-stopped", "recheck-original-backup", "restore-independent-rollback-clone",
    "compare-original-fingerprint", "restore-under-writer-fence",
    "verify-post-restore-fingerprint", "keep-externally-routed-services-stopped",
  ]);
});

test("RED: missing clone, changed backup and writer fence never authorize rollback", () => {
  const original = args();
  for (const key of Object.keys(original.baseline)) {
    const changed = { ...original, baseline: { ...original.baseline, [key]: "0".repeat(64) } };
    assert.equal(previewManualRollbackReconciliation(changed).status, "BLOCKED_MANUAL_ROLLBACK");
  }
  assert.equal(previewManualRollbackReconciliation({ ...original, checkpoint: {
    ...original.checkpoint, completed: original.checkpoint.completed.slice(0, 2), sequence: 2,
  } }).status, "BLOCKED_MANUAL_ROLLBACK");
});

test("RED: deny forged owner/witness, replay and host mismatch", () => {
  const original = args();
  assert.equal(previewManualRollbackReconciliation({ ...original,
    measuredHostIdentitySha256: "f".repeat(64) }).status, "BLOCKED_MANUAL_ROLLBACK");
  assert.equal(previewManualRollbackReconciliation({ ...original,
    ownerReconciliation: signed(original.ownerReconciliation.message, witness.privateKey),
  }).status, "BLOCKED_MANUAL_ROLLBACK");
  assert.equal(previewManualRollbackReconciliation({ ...original,
    witnessReconciliation: signed(original.witnessReconciliation.message, owner.privateKey),
  }).status, "BLOCKED_MANUAL_ROLLBACK");
  assert.equal(previewManualRollbackReconciliation({ ...original,
    witnessReconciliation: signed({ ...original.witnessReconciliation.message,
      sequence: 4 }, witness.privateKey),
  }).status, "BLOCKED_MANUAL_ROLLBACK");
  assert.equal(previewManualRollbackReconciliation({ ...original,
    ownerReconciliation: signed({ ...original.ownerReconciliation.message,
      expiresAt: Math.floor(Date.now() / 1000) - 1 }, owner.privateKey),
  }).status, "BLOCKED_MANUAL_ROLLBACK");
});

test("RED: completed routing or missing live-migration evidence cannot rollback silently", () => {
  const original = args();
  assert.equal(previewManualRollbackReconciliation({ ...original, checkpoint: {
    ...original.checkpoint, pending: null,
  } }).status, "BLOCKED_MANUAL_ROLLBACK");
  assert.equal(previewManualRollbackReconciliation({ ...original, checkpoint: {
    ...original.checkpoint, pending: { ...original.checkpoint.pending,
      stage: "resume-writers" },
  } }).status, "BLOCKED_MANUAL_ROLLBACK");
});
