import { createHash, createPublicKey, verify } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync,
  readSync, realpathSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { validateOfflineLedgerTransition } from "../../scripts/lib/offline-release-ledger.mjs";
import { verifyIndependentWitnessCasReceipt } from "../../scripts/lib/offline-independent-witness-service.mjs";
import { offlineWitnessLedgerTransitionDigest } from "./disposable-witness-ledger-reservation.mjs";
import { inspectUntrustedExternalFloorEvidence } from "./trusted-out-of-host-floor-evidence.mjs";
import { activationSigningBytes } from "./manual-activation-transaction.mjs";

// Owner-installed local host gate only. A signed remote CAS receipt and an
// independently signed floor MUST both precede any host ledger/activation
// action. This module never invokes those actions or grants deployment.
// A real native root installer, independent off-host floor source, and host
// identity measurement remain separate owner-only prerequisites.
const TRUST = "/etc/virki/offline-witness-bridge.json";
const INTENTS = "/var/lib/virki/offline-witness-bridge";
const WSL_FIXTURE = /^\/dev\/shm\/virki-witness-bridge-fixture-[a-zA-Z0-9]{6,64}\/(?:owner-installed-trust\.json|intents)$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const HEX32 = /^[0-9a-f]{32}$/u;
const SIG = /^[A-Za-z0-9+/]{86}==$/u;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const refuse = () => { throw new Error("Host witness ledger/activation bridge refused"); };
function demand(value) { if (!value) refuse(); }
function exact(value, fields) {
  demand(value && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(fields));
}
function directoryOwned(folder) {
  demand(typeof folder === "string" && path.isAbsolute(folder) &&
    path.normalize(folder) === folder && realpathSync.native(folder) === folder);
  const s = lstatSync(folder);
  demand(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0 && s.gid === 0 &&
    (s.mode & 0o7777) === 0o700);
}
function safeFile(file, maxBytes) {
  demand(typeof file === "string" && path.isAbsolute(file) && path.normalize(file) === file);
  directoryOwned(path.dirname(file));
  const expected = lstatSync(file, { bigint: true });
  const allowed = (s) => s.isFile() && !s.isSymbolicLink() && s.uid === 0n && s.gid === 0n &&
    (s.mode & 0o7777n) === 0o600n && s.nlink === 1n && s.size > 0n &&
    s.size <= BigInt(maxBytes);
  const same = (a, b) => ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
  demand(allowed(expected));
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    demand(allowed(before) && same(expected, before));
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const count = readSync(fd, buffer, bytes, buffer.length - bytes, null);
      if (count === 0) break;
      bytes += count;
    }
    const after = fstatSync(fd, { bigint: true });
    demand(bytes === Number(before.size) && allowed(after) && same(before, after) &&
      same(after, lstatSync(file, { bigint: true })));
    return buffer.subarray(0, bytes);
  } finally { closeSync(fd); }
}
function readExactJson(file, maxBytes) {
  const data = safeFile(file, maxBytes);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
  const value = JSON.parse(text);
  demand(JSON.stringify(value) === text);
  return value;
}
function pinned(pem, pin) {
  demand(typeof pem === "string" && pem.length <= 4096 && HEX64.test(pin));
  const key = createPublicKey(pem);
  demand(key.asymmetricKeyType === "ed25519" &&
    sha(key.export({ format: "der", type: "spki" })) === pin);
  return key;
}
function trustedLocations(input) {
  demand(process.platform === "linux" && process.getuid?.() === 0);
  const fixture = process.env.VIRKI_DISPOSABLE_WITNESS_BRIDGE === "1" &&
    /wsl|microsoft/iu.test(os.release());
  if (fixture) {
    demand(WSL_FIXTURE.test(input.installedPolicyFile) && WSL_FIXTURE.test(input.intentDirectory) &&
      path.dirname(input.installedPolicyFile) === path.dirname(input.intentDirectory));
    directoryOwned(path.dirname(input.installedPolicyFile));
    return { policy: input.installedPolicyFile, intents: input.intentDirectory };
  }
  demand(!/wsl|microsoft/iu.test(os.release()) &&
    (input.installedPolicyFile === undefined || input.installedPolicyFile === TRUST) &&
    (input.intentDirectory === undefined || input.intentDirectory === INTENTS));
  return { policy: TRUST, intents: INTENTS };
}
function recordIntent(intents, input) {
  directoryOwned(intents);
  const bytes = Buffer.from(JSON.stringify(input));
  demand(bytes.length <= 4096);
  const target = path.join(intents, `${input.receiptSha256}.intent`);
  // Existing or partially written intent always blocks retry. No replacement,
  // unlink, timeout reset or rollback path is provided.
  const fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
    constants.O_NOFOLLOW, 0o600);
  try {
    for (let index = 0; index < bytes.length;) {
      const wrote = writeSync(fd, bytes, index, bytes.length - index);
      demand(wrote > 0);
      index += wrote;
    }
    fsyncSync(fd);
  } finally { closeSync(fd); }
  const dirFd = openSync(intents, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  demand(safeFile(target, 4096).equals(bytes));
}

/**
 * Record ONE nonauthorizing host intent after validating installed pins,
 * current host-owned manifest/ledger/activation checkpoint, exact owner CAS
 * receipt and independent challenge-bound floor. Normal native Linux reads
 * only fixed root-installed paths. Disposable WSL allows a strictly scoped
 * fixture path; no caller-provided key/pin can become authority.
 */
export function recordHostWitnessLedgerActivationBridge(input = {}) {
  try {
    exact(input, ["installedPolicyFile", "intentDirectory", "ledgerState", "ledgerRequest",
      "checkpoint", "stageApproval", "evidence"]);
    const locations = trustedLocations(input);
    const policy = readExactJson(locations.policy, 16384);
    const installedPolicyDigest = sha(JSON.stringify(policy));
    exact(policy, ["version", "hostIdentitySha256", "ledgerIdSha256", "manifestSha256",
      "manifestFile", "sourceSha", "ledgerDirectory", "activationCheckpointFile",
      "activationAttemptId", "expectedSequence", "expectedHeadSha", "expectedReceiptSha256",
      "ownerPublicKeyPem", "ownerPinSha256", "witnessPublicKeyPem", "witnessPinSha256",
      "floorPublicKeyPem", "floorPinSha256"]);
    demand(policy.version === 1 && HEX64.test(policy.hostIdentitySha256) &&
      HEX64.test(policy.ledgerIdSha256) && HEX64.test(policy.manifestSha256) &&
      HEX40.test(policy.sourceSha) && HEX32.test(policy.activationAttemptId) &&
      Number.isSafeInteger(policy.expectedSequence) && policy.expectedSequence >= 0 &&
      HEX40.test(policy.expectedHeadSha) && HEX64.test(policy.expectedReceiptSha256) &&
      new Set([policy.ownerPinSha256, policy.witnessPinSha256, policy.floorPinSha256]).size === 3);
    const ownerKey = pinned(policy.ownerPublicKeyPem, policy.ownerPinSha256);
    pinned(policy.witnessPublicKeyPem, policy.witnessPinSha256);
    pinned(policy.floorPublicKeyPem, policy.floorPinSha256);

    demand(sha(safeFile(policy.manifestFile, 1048576)) === policy.manifestSha256);
    demand(policy.ledgerDirectory === input.ledgerRequest.directory &&
      JSON.stringify(readExactJson(path.join(policy.ledgerDirectory, "ledger.json"), 1048576)) ===
        JSON.stringify(input.ledgerState));
    demand(JSON.stringify(readExactJson(policy.activationCheckpointFile, 32768)) ===
      JSON.stringify(input.checkpoint));

    const { ledgerRequest, ledgerState, checkpoint, evidence, stageApproval } = input;
    const updated = validateOfflineLedgerTransition(ledgerState, ledgerRequest);
    demand(updated.entries.length === ledgerRequest.sequence &&
      ledgerRequest.manifestSha256 === policy.manifestSha256 &&
      ledgerRequest.nextSha === policy.sourceSha &&
      ledgerRequest.sequence === policy.expectedSequence + 1 &&
      ledgerState.entries.length === policy.expectedSequence &&
      ledgerRequest.priorSha === policy.expectedHeadSha &&
      (policy.expectedSequence !== 0 || policy.expectedHeadSha === "0".repeat(40)));

    // This is the initial release admission. Later activation steps require
    // independently installed per-stage approval and durable journal logic.
    exact(checkpoint, ["version", "attemptId", "hostIdentitySha256", "manifestSha256",
      "sequence", "receiptSha256", "completed", "pending", "previousDigest"]);
    demand(checkpoint.version === 1 && checkpoint.sequence === 0 &&
      checkpoint.pending === null && Array.isArray(checkpoint.completed) &&
      checkpoint.completed.length === 0 && checkpoint.previousDigest === "0".repeat(64) &&
      checkpoint.hostIdentitySha256 === policy.hostIdentitySha256 &&
      checkpoint.manifestSha256 === policy.manifestSha256 &&
      checkpoint.attemptId === policy.activationAttemptId &&
      checkpoint.receiptSha256 === policy.expectedReceiptSha256);
    exact(stageApproval, ["message", "signature"]);
    const stage = stageApproval.message;
    exact(stage, ["version", "domain", "attemptId", "hostIdentitySha256",
      "manifestSha256", "stage", "sequence", "previousDigest", "expiresAt"]);
    const timestamp = Math.floor(Date.now() / 1000);
    demand(stage.version === 1 &&
      stage.domain === "VIRKI_MANUAL_ACTIVATION_OWNER_STAGE_V1" &&
      stage.stage === "fence-writers" &&
      stage.attemptId === checkpoint.attemptId && stage.hostIdentitySha256 === policy.hostIdentitySha256 &&
      stage.manifestSha256 === policy.manifestSha256 && stage.sequence === 1 &&
      stage.previousDigest === sha(JSON.stringify(checkpoint)) &&
      Number.isSafeInteger(stage.expiresAt) && timestamp < stage.expiresAt &&
      stage.expiresAt <= timestamp + 30 && SIG.test(stageApproval.signature) &&
      Buffer.from(stageApproval.signature, "base64").toString("base64") === stageApproval.signature &&
      verify(null, activationSigningBytes(stage), ownerKey,
        Buffer.from(stageApproval.signature, "base64")));

    demand(evidence?.phase === "after" && evidence.ack === "confirmed");
    exact(evidence.pins, ["ownerPublicKeyPem", "ownerPinSha256", "witnessPublicKeyPem",
      "witnessPinSha256", "floorPublicKeyPem", "floorPinSha256"]);
    for (const key of Object.keys(evidence.pins)) demand(evidence.pins[key] === policy[key]);
    demand(evidence.expected.hostIdentitySha256 === policy.hostIdentitySha256 &&
      evidence.expected.ledgerIdSha256 === policy.ledgerIdSha256 &&
      evidence.expected.sequence === policy.expectedSequence &&
      evidence.expected.headSha === policy.expectedHeadSha &&
      evidence.expected.receiptSha256 === policy.expectedReceiptSha256 &&
      evidence.casRequest.expectedSequence === policy.expectedSequence &&
      evidence.casRequest.expectedHeadSha === policy.expectedHeadSha &&
      evidence.casRequest.expectedReceiptSha256 === policy.expectedReceiptSha256 &&
      evidence.casRequest.nextHeadSha === policy.sourceSha &&
      evidence.casRequest.transitionSha256 === offlineWitnessLedgerTransitionDigest(ledgerRequest) &&
      evidence.casRequest.hostIdentitySha256 === policy.hostIdentitySha256 &&
      evidence.casRequest.ledgerIdSha256 === policy.ledgerIdSha256);
    demand(inspectUntrustedExternalFloorEvidence(evidence).status ===
      "EXTERNAL_FLOOR_EVIDENCE_PREVIEW_ONLY");
    const verified = verifyIndependentWitnessCasReceipt({
      receipt: evidence.casReceipt, request: evidence.casRequest,
      publicKeyPem: policy.witnessPublicKeyPem, pinSha256: policy.witnessPinSha256,
      ownerPublicKeyPem: policy.ownerPublicKeyPem, ownerPinSha256: policy.ownerPinSha256,
    });
    demand(verified.sequence === ledgerRequest.sequence && verified.headSha === policy.sourceSha &&
      verified.receiptSha256 === evidence.floorReceipt.message.receiptSha256);

    const intent = {
      version: 1, hostIdentitySha256: policy.hostIdentitySha256,
      ledgerIdSha256: policy.ledgerIdSha256, manifestSha256: policy.manifestSha256,
      sourceSha: policy.sourceSha, sequence: verified.sequence,
      receiptSha256: verified.receiptSha256, casRequestId: evidence.casRequest.requestId,
      casRequestSha256: sha(JSON.stringify(evidence.casRequest)),
      floorReceiptSha256: sha(JSON.stringify(evidence.floorReceipt)),
      activationAttemptId: checkpoint.attemptId, stage: stage.stage,
      stageApprovalSha256: sha(JSON.stringify(stageApproval)),
    };
    // Recheck the installed trust and the actual host state at the immediate
    // use point. A concurrent host writer must not invalidate the data read
    // before remote receipt verification and still receive a durable intent.
    demand(sha(JSON.stringify(readExactJson(locations.policy, 16384))) === installedPolicyDigest &&
      sha(safeFile(policy.manifestFile, 1048576)) === policy.manifestSha256 &&
      JSON.stringify(readExactJson(path.join(policy.ledgerDirectory, "ledger.json"), 1048576)) ===
        JSON.stringify(ledgerState) &&
      JSON.stringify(readExactJson(policy.activationCheckpointFile, 32768)) ===
        JSON.stringify(checkpoint));
    recordIntent(locations.intents, intent);
    return Object.freeze({ status: "BRIDGE_INTENT_RECORDED_NONAUTHORIZING",
      manifestSha256: intent.manifestSha256, sourceSha: intent.sourceSha,
      sequence: intent.sequence, receiptSha256: intent.receiptSha256,
      ledgerAttemptAuthorized: false, witnessCasAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false });
  } catch { refuse(); }
}
