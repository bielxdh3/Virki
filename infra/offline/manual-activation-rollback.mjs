import { createHash, createPublicKey, verify } from "node:crypto";

// Untrusted NON-AUTHORIZING reconciliation blueprint. A real native Linux
// owner-installed host supervisor would need a separately authenticated root
// installation, original PG backup + independently restored clone, stopped
// writer sockets, and an out-of-host monotonic owner-approved witness floor.
// Caller-supplied keys and witness JSON, even valid Ed25519 signatures, prove
// neither those origins nor that the physical database matches these digests.
// NO function here executes, restores, starts or permits Docker/PG/Cloudflare.
const OWNER_DOMAIN = "VIRKI_MANUAL_ROLLBACK_OWNER_RECONCILIATION_V1";
const WITNESS_DOMAIN = "VIRKI_MANUAL_ROLLBACK_WITNESS_HEAD_V1";
const SHA = /^[0-9a-f]{64}$/u;
const ATTEMPT = /^[0-9a-f]{32}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const PHASES = Object.freeze([
  "prove-writers-stopped", "recheck-original-backup", "restore-independent-rollback-clone",
  "compare-original-fingerprint", "restore-under-writer-fence",
  "verify-post-restore-fingerprint", "keep-externally-routed-services-stopped",
]);
const DENIED = Object.freeze({ status: "BLOCKED_MANUAL_ROLLBACK", deployAuthorized: false,
  rollbackAuthorized: false, dockerAuthorized: false });
const hash = (input) => createHash("sha256").update(input).digest("hex");
function insist(test) { if (!test) throw new Error("Manual rollback reconciliation blocked"); }
function exact(value, fields) {
  insist(value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(fields));
}
export function manualRollbackSigningBytes(message) {
  insist(message && typeof message === "object" && !Array.isArray(message) &&
    [OWNER_DOMAIN, WITNESS_DOMAIN].includes(message.domain));
  return Buffer.from(`${message.domain}\0${JSON.stringify(message)}`, "utf8");
}
function signer(pem, pin) {
  insist(typeof pem === "string" && pem.length > 0 && pem.length <= 4096 && SHA.test(pin));
  const key = createPublicKey(pem);
  insist(key.asymmetricKeyType === "ed25519" &&
    hash(key.export({ type: "spki", format: "der" })) === pin);
  return key;
}
function checkedSigned(proof, domain, publicKey, fields) {
  exact(proof, ["message", "signature"]);
  exact(proof.message, fields);
  insist(proof.message.domain === domain && typeof proof.signature === "string" &&
    B64.test(proof.signature) &&
    Buffer.from(proof.signature, "base64").toString("base64") === proof.signature &&
    verify(null, manualRollbackSigningBytes(proof.message), publicKey,
      Buffer.from(proof.signature, "base64")));
  return proof.message;
}

/** Evaluates *format and consistency* only; the result always denies authority. */
export function previewManualRollbackReconciliation(input = {}) {
  try {
    exact(input, ["checkpoint", "baseline", "measuredHostIdentitySha256", "keys",
      "ownerReconciliation", "witnessReconciliation"]);
    const { checkpoint: c, baseline, measuredHostIdentitySha256, keys,
      ownerReconciliation, witnessReconciliation } = input;
    exact(c, ["version", "attemptId", "hostIdentitySha256", "manifestSha256",
      "sequence", "receiptSha256", "completed", "pending", "previousDigest"]);
    insist(c.version === 1 && ATTEMPT.test(c.attemptId) &&
      [c.hostIdentitySha256, c.manifestSha256, c.receiptSha256, c.previousDigest]
        .every((value) => SHA.test(value)) &&
      c.hostIdentitySha256 === measuredHostIdentitySha256 &&
      Number.isSafeInteger(c.sequence) && c.sequence >= 4 && c.sequence <= 6 &&
      Array.isArray(c.completed) && c.completed.length === c.sequence);
    const stages = ["fence-writers", "verify-backup", "restore-clone", "migrate-clone",
      "migrate-live", "verify-private-health"];
    for (let i = 0; i < c.completed.length; i++) {
      const entry = c.completed[i];
      exact(entry, ["stage", "result", "snapshotSha256"]);
      insist(entry.stage === stages[i] && entry.result === "completed" &&
        SHA.test(entry.snapshotSha256));
    }
    exact(c.pending, ["stage", "sequence", "ownerApprovalSha256",
      "witnessReceiptSha256", "previousDigest"]);
    insist(c.pending.stage === ["migrate-live", "verify-private-health", "activate-runtime"][c.sequence - 4] &&
      c.pending.sequence === c.sequence + 1 &&
      [c.pending.ownerApprovalSha256, c.pending.witnessReceiptSha256,
        c.pending.previousDigest].every((value) => SHA.test(value)) &&
      c.pending.previousDigest === c.previousDigest);
    exact(baseline, ["writerFenceSha256", "backupSha256", "restoredCloneSha256"]);
    insist([baseline.writerFenceSha256, baseline.backupSha256,
      baseline.restoredCloneSha256].every((value) => SHA.test(value)) &&
      baseline.writerFenceSha256 === c.completed[0].snapshotSha256 &&
      baseline.backupSha256 === c.completed[1].snapshotSha256 &&
      baseline.restoredCloneSha256 === c.completed[2].snapshotSha256);

    exact(keys, ["ownerPublicKeyPem", "ownerPinSha256", "witnessPublicKeyPem",
      "witnessPinSha256"]);
    insist(keys.ownerPinSha256 !== keys.witnessPinSha256);
    const owner = signer(keys.ownerPublicKeyPem, keys.ownerPinSha256);
    const witness = signer(keys.witnessPublicKeyPem, keys.witnessPinSha256);
    const ownerMsg = checkedSigned(ownerReconciliation, OWNER_DOMAIN, owner,
      ["version", "domain", "attemptId", "hostIdentitySha256", "manifestSha256",
        "checkpointSha256", "writerFenceSha256", "backupSha256",
        "restoredCloneSha256", "reason", "issuedAt", "expiresAt"]);
    const witnessMsg = checkedSigned(witnessReconciliation, WITNESS_DOMAIN, witness,
      ["version", "domain", "attemptId", "hostIdentitySha256", "manifestSha256",
        "checkpointSha256", "sequence", "receiptSha256", "issuedAt", "expiresAt"]);
    const digest = hash(JSON.stringify(c));
    const now = Math.floor(Date.now() / 1000);
    const scope = (m) => m.version === 1 && m.attemptId === c.attemptId &&
      m.hostIdentitySha256 === c.hostIdentitySha256 &&
      m.manifestSha256 === c.manifestSha256 && m.checkpointSha256 === digest &&
      Number.isSafeInteger(m.issuedAt) && Number.isSafeInteger(m.expiresAt) &&
      now >= m.issuedAt && now < m.expiresAt &&
      m.issuedAt >= now - 30 && m.expiresAt === m.issuedAt + 30;
    insist(scope(ownerMsg) && scope(witnessMsg) &&
      ownerMsg.reason === "ambiguous-live-migration" &&
      ownerMsg.writerFenceSha256 === baseline.writerFenceSha256 &&
      ownerMsg.backupSha256 === baseline.backupSha256 &&
      ownerMsg.restoredCloneSha256 === baseline.restoredCloneSha256 &&
      witnessMsg.sequence === c.sequence + 1 &&
      SHA.test(witnessMsg.receiptSha256) &&
      witnessMsg.receiptSha256 !== c.receiptSha256);
    return Object.freeze({
      status: "ROLLBACK_RECONCILIATION_PREVIEW_ONLY",
      requiredPhases: PHASES, deployAuthorized: false,
      rollbackAuthorized: false, dockerAuthorized: false,
      limitations: "No independently installed keys, off-host floor, signed result custody, writer-fence or real PostgreSQL restoration proof",
    });
  } catch { return DENIED; }
}
