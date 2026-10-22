import { createHash } from "node:crypto";
import { verifyOfflineReleaseAttestation } from "./offline-release-attestation.mjs";
import { validateOfflineLedgerTransition } from "./offline-release-ledger.mjs";
import { inspectUntrustedSourceGitForPreview } from "../../infra/offline/trusted-source-git.mjs";

// Local test/rehearsal composition ONLY. Every trust input is independently
// supplied by the disposable test harness. Never use the returned status as a
// release decision: no real restore, installed host trust, activation or
// deployment is established by these synthetic evidence checks.
const HASH = /^[0-9a-f]{64}$/u;
const RECEIPT_KEYS = Object.freeze([
  "version", "kind", "sourceSha", "status", "exitCode", "rawLogSha256", "predecessorSha",
]);
const INPUT_KEYS = Object.freeze([
  "manifestBytes", "signatures", "trustedKeys", "expected", "nowSeconds",
  "sourceGit", "backupRestore", "ledgerState",
]);

function refuse(reason) {
  throw new Error(`Offline release rehearsal refused: ${reason}`);
}

function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== keys.length ||
      keys.some((key) => !Object.hasOwn(value, key))) {
    refuse(`${label} has missing or unexpected fields`);
  }
}

function backupRestorePrerequisite({ receiptBytes, rawLogBytes }, sourceSha, predecessorSha, expectedDigest) {
  if (!Buffer.isBuffer(receiptBytes) || receiptBytes.length < 1 || receiptBytes.length > 16 * 1024 ||
      !Buffer.isBuffer(rawLogBytes) || rawLogBytes.length < 1 || rawLogBytes.length > 1024 * 1024) {
    refuse("backup-restore receipt or raw log is missing or oversized");
  }
  if (!HASH.test(expectedDigest) || createHash("sha256").update(receiptBytes).digest("hex") !== expectedDigest) {
    refuse("backup-restore receipt digest does not match independently supplied evidence");
  }
  let receipt;
  try {
    receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(receiptBytes));
  } catch {
    refuse("backup-restore receipt is invalid UTF-8 or JSON");
  }
  exact(receipt, RECEIPT_KEYS, "backup-restore receipt");
  if (receiptBytes.toString("utf8") !== JSON.stringify(receipt) ||
      receipt.version !== 1 || receipt.kind !== "backup-restore" ||
      receipt.status !== "PASS" || receipt.exitCode !== 0 ||
      receipt.sourceSha !== sourceSha || receipt.predecessorSha !== predecessorSha ||
      !HASH.test(receipt.rawLogSha256) ||
      createHash("sha256").update(rawLogBytes).digest("hex") !== receipt.rawLogSha256) {
    refuse("backup-restore receipt is unsuccessful, unbound or raw log differs");
  }
  // A local PASS receipt and matching log hash prove neither execution nor a
  // successful independent PostgreSQL restore. This remains a prerequisite.
}

/**
 * NON-AUTHORIZING rehearsal: verify synthetic signed release evidence against
 * caller-provided independent keys, Git object store + pinned SHA, restore
 * receipt and the existing ledger's pure transition validator. The ledger is
 * never opened, reserved, completed or mutated here; production stays blocked.
 * Requires Linux root for the existing read-only source Git preview contract.
 */
export async function rehearseOfflineReleaseLocally(input = {}) {
  exact(input, INPUT_KEYS, "rehearsal input");
  const { manifestBytes, signatures, trustedKeys, expected, nowSeconds,
    sourceGit, backupRestore, ledgerState } = input;
  if (!ledgerState || !Array.isArray(ledgerState.entries) ||
      !expected || expected.lastSequence !== ledgerState.entries.length) {
    refuse("ledger sequence is missing or inconsistent with supplied state");
  }

  const signed = verifyOfflineReleaseAttestation({
    manifestBytes, signatures, trustedKeys, expected, nowSeconds,
  });

  const gitSource = await inspectUntrustedSourceGitForPreview(sourceGit);
  if (gitSource.deployAuthorized !== false ||
      gitSource.sourceSha !== signed.sourceSha ||
      gitSource.archiveSha256 !== expected.sourceArchiveSha256 ||
      gitSource.archiveSizeBytes !== expected.sourceArchiveSizeBytes) {
    refuse("independent Git source or archive differs from signed release");
  }

  if (!backupRestore || typeof backupRestore !== "object") {
    refuse("backup-restore receipt and raw log are required");
  }
  exact(backupRestore, ["receiptBytes", "rawLogBytes"], "backup-restore prerequisites");
  backupRestorePrerequisite(backupRestore, signed.sourceSha, signed.predecessorSha,
    expected.backupRestoreSha256);

  const ledgerRequest = {
    // This is solely a normalized dummy field required by the pure validator.
    // No directory with this name is created, opened, locked or written.
    directory: "/var/lib/virki/rehearsal-never-record",
    manifestSha256: signed.manifestSha256,
    priorSha: signed.predecessorSha,
    nextSha: signed.sourceSha,
    nonce: signed.nonce,
    sequence: signed.sequence,
    approvalDigest: createHash("sha256").update(Buffer.from(signatures.owner, "base64")).digest("hex"),
  };
  let next;
  try {
    next = validateOfflineLedgerTransition(ledgerState, ledgerRequest);
  } catch (error) {
    refuse(`ledger transition rejected: ${error.message}`);
  }
  return Object.freeze({
    status: "LOCAL_REHEARSAL_ONLY_RELEASE_BLOCKED",
    deployAuthorized: false,
    sourceSha: signed.sourceSha,
    sequence: signed.sequence,
    manifestSha256: signed.manifestSha256,
    simulatedLedgerHeadSha: next.entries.at(-1).nextSha,
  });
}
