import { createHash, createPublicKey, verify } from "node:crypto";

// A nonauthorizing transaction contract for the separately owner-installed
// manual host driver. These functions NEVER invoke Docker, PostgreSQL, SSH or
// host commands and NEVER accept an authorization callback or a test escape to
// activate production. The caller's public keys, observations and checkpoint
// cannot establish independent owner/off-host custody. An installed root agent
// must authenticate those origins, atomically persist intent BEFORE the first
// side effect, and independently recheck at every use point.
export const MANUAL_ACTIVATION_STAGES = Object.freeze([
  "fence-writers", "verify-backup", "restore-clone", "migrate-clone",
  "migrate-live", "verify-private-health", "activate-runtime", "resume-writers",
]);
const OWNER_DOMAIN = "VIRKI_MANUAL_ACTIVATION_OWNER_STAGE_V1";
const WITNESS_DOMAIN = "VIRKI_MANUAL_ACTIVATION_INDEPENDENT_HEAD_V1";
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX32 = /^[0-9a-f]{32}$/u;
const ED25519 = /^[A-Za-z0-9+/]{86}==$/u;
const DENIED = Object.freeze({ status: "BLOCKED_MANUAL_ACTIVATION", deployAuthorized: false,
  dockerAuthorized: false, rollbackAuthorized: false });
const digest = (input) => createHash("sha256").update(input).digest("hex");

function demand(ok) {
  if (!ok) throw new Error("Manual native activation proof refused");
}
function exact(object, names) {
  demand(object !== null && typeof object === "object" && !Array.isArray(object) &&
    JSON.stringify(Object.keys(object)) === JSON.stringify(names));
}
function key(pem, pin) {
  demand(typeof pem === "string" && pem.length > 0 && pem.length <= 4096 && HEX64.test(pin));
  const parsed = createPublicKey(pem);
  demand(parsed.asymmetricKeyType === "ed25519" &&
    digest(parsed.export({ format: "der", type: "spki" })) === pin);
  return parsed;
}
function authenticated(record, expectedDomain, expectedKey) {
  exact(record, ["message", "signature"]);
  const { message, signature } = record;
  demand(message.domain === expectedDomain && typeof signature === "string" &&
    ED25519.test(signature) && Buffer.from(signature, "base64").toString("base64") === signature &&
    verify(null, activationSigningBytes(message), expectedKey, Buffer.from(signature, "base64")));
  return message;
}

/** Untrusted signing byte-format preview, domain-separated per stage. */
export function activationSigningBytes(message) {
  demand(message && typeof message === "object" && !Array.isArray(message) &&
    [OWNER_DOMAIN, WITNESS_DOMAIN].includes(message.domain));
  return Buffer.from(`${message.domain}\0${JSON.stringify(message)}`, "utf8");
}

function checkpointValid(c) {
  exact(c, ["version", "attemptId", "hostIdentitySha256", "manifestSha256",
    "sequence", "receiptSha256", "completed", "pending", "previousDigest"]);
  demand(c.version === 1 && HEX32.test(c.attemptId) && HEX64.test(c.hostIdentitySha256) &&
    HEX64.test(c.manifestSha256) && HEX64.test(c.receiptSha256) &&
    HEX64.test(c.previousDigest) && Array.isArray(c.completed) &&
    c.completed.length <= MANUAL_ACTIVATION_STAGES.length &&
    c.sequence === c.completed.length && Number.isSafeInteger(c.sequence));
  for (let i = 0; i < c.completed.length; i++) {
    const entry = c.completed[i];
    exact(entry, ["stage", "result", "snapshotSha256"]);
    demand(entry.stage === MANUAL_ACTIVATION_STAGES[i] &&
      entry.result === "completed" && HEX64.test(entry.snapshotSha256));
  }
  if (c.pending !== null) {
    exact(c.pending, ["stage", "sequence", "ownerApprovalSha256",
      "witnessReceiptSha256", "previousDigest"]);
    demand(c.completed.length < MANUAL_ACTIVATION_STAGES.length &&
      c.pending.stage === MANUAL_ACTIVATION_STAGES[c.completed.length] &&
      c.pending.sequence === c.sequence + 1 &&
      [c.pending.ownerApprovalSha256, c.pending.witnessReceiptSha256,
        c.pending.previousDigest].every((value) => HEX64.test(value)) &&
      c.pending.previousDigest === c.previousDigest);
  }
}

function verifySignedUsePoint(checkpoint, stage, evidence, prepared) {
  exact(evidence, ["keys", "measuredHostIdentitySha256", "ownerApproval", "witnessHead"]);
  exact(evidence.keys, ["ownerPublicKeyPem", "ownerPinSha256", "witnessPublicKeyPem",
    "witnessPinSha256"]);
  const { ownerPublicKeyPem, ownerPinSha256, witnessPublicKeyPem, witnessPinSha256 } = evidence.keys;
  demand(ownerPinSha256 !== witnessPinSha256 &&
    checkpoint.hostIdentitySha256 === evidence.measuredHostIdentitySha256);
  const owner = key(ownerPublicKeyPem, ownerPinSha256);
  const witness = key(witnessPublicKeyPem, witnessPinSha256);
  const signed = authenticated(evidence.ownerApproval, OWNER_DOMAIN, owner);
  exact(signed, ["version", "domain", "attemptId", "hostIdentitySha256",
    "manifestSha256", "stage", "sequence", "previousDigest", "expiresAt"]);
  const head = authenticated(evidence.witnessHead, WITNESS_DOMAIN, witness);
  exact(head, ["version", "domain", "attemptId", "hostIdentitySha256",
    "manifestSha256", "sequence", "receiptSha256", "issuedAt", "expiresAt"]);
  const now = Math.floor(Date.now() / 1000);
  const identical = (record) => record.version === 1 &&
    record.attemptId === checkpoint.attemptId &&
    record.hostIdentitySha256 === checkpoint.hostIdentitySha256 &&
    record.manifestSha256 === checkpoint.manifestSha256 &&
    record.sequence === checkpoint.sequence + 1;
  const predecessorSha = prepared ? checkpoint.pending.previousDigest :
    digest(JSON.stringify(checkpoint));
  demand(identical(signed) && identical(head) && signed.stage === stage &&
    signed.previousDigest === predecessorSha &&
    Number.isSafeInteger(signed.expiresAt) && now < signed.expiresAt &&
    signed.expiresAt <= now + 30 &&
    Number.isSafeInteger(head.issuedAt) && head.issuedAt <= now &&
    head.issuedAt >= now - 30 &&
    Number.isSafeInteger(head.expiresAt) && now < head.expiresAt &&
    head.expiresAt === head.issuedAt + 30 &&
    HEX64.test(head.receiptSha256) && head.receiptSha256 !== checkpoint.receiptSha256);
  if (prepared) {
    demand(digest(JSON.stringify(evidence.ownerApproval)) ===
      checkpoint.pending.ownerApprovalSha256 &&
      head.receiptSha256 === checkpoint.pending.witnessReceiptSha256);
  }
  return { head, previousDigest: predecessorSha };
}

/**
 * Preview admission for ONE transition. The native host must separately and
 * atomically bind both custody and the durable journal to this exact state.
 * A successful preview is never permission for a real deployment operation.
 */
export function previewManualActivationPrepare({ checkpoint, stage, evidence } = {}) {
  try {
    checkpointValid(checkpoint);
    demand(checkpoint.pending === null &&
      stage === MANUAL_ACTIVATION_STAGES[checkpoint.completed.length]);
    const { head, previousDigest } = verifySignedUsePoint(checkpoint, stage, evidence, false);
    const next = {
      ...checkpoint,
      pending: {
        stage, sequence: checkpoint.sequence + 1,
        ownerApprovalSha256: digest(JSON.stringify(evidence.ownerApproval)),
        witnessReceiptSha256: head.receiptSha256,
        previousDigest,
      },
      previousDigest,
    };
    return Object.freeze({ status: "PREPARED_PREVIEW_ONLY", checkpoint: next,
      deployAuthorized: false, dockerAuthorized: false, rollbackAuthorized: false });
  } catch { return DENIED; }
}

/**
 * A completed operation may be recorded only after durable observed evidence;
 * this pure preview deliberately cannot authenticate that observation. A
 * missing reply or a crash leaves pending != null and blocks all new steps.
 * Rollback is a separate owner-approved reconciliation, never an implicit
 * transition based on catching an error or restarting the same command.
 */
export function previewManualActivationCommit({ checkpoint, stage, observed, evidence } = {}) {
  try {
    checkpointValid(checkpoint);
    demand(checkpoint.pending !== null && checkpoint.pending.stage === stage);
    verifySignedUsePoint(checkpoint, stage, evidence, true);
    exact(observed, ["stage", "result", "snapshotSha256"]);
    demand(observed.stage === stage && observed.result === "completed" &&
      HEX64.test(observed.snapshotSha256));
    return Object.freeze({
      status: "COMMITTED_PREVIEW_ONLY", deployAuthorized: false,
      dockerAuthorized: false, rollbackAuthorized: false,
      checkpoint: {
        ...checkpoint, sequence: checkpoint.pending.sequence,
        receiptSha256: checkpoint.pending.witnessReceiptSha256,
        completed: [...checkpoint.completed, { ...observed }],
        pending: null, previousDigest: digest(JSON.stringify(checkpoint)),
      },
    });
  } catch { return DENIED; }
}
