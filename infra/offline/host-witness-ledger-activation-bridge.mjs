import { createHash, createPublicKey, verify } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync,
  readSync, realpathSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { isIP } from "node:net";
import { remoteWitnessHead } from "../../scripts/lib/offline-independent-witness-remote-client.mjs";
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
const TRANSPORT = "/etc/virki/offline-witness-transport.json";
const PROOF = "/etc/virki/offline-witness-proof.json";
// The optional owner-root level is exclusively for adversarial WSL fixtures:
// it permits testing an unprotected ancestor WITHOUT changing /dev/shm itself.
const WSL_FIXTURE = /^\/dev\/shm\/virki-witness-bridge-fixture-[a-zA-Z0-9]{6,64}(?:\/owner-root)?\/(?:owner-installed-trust\.json|intents)$/u;
const WSL_TRANSPORT = /^\/dev\/shm\/virki-witness-bridge-fixture-[a-zA-Z0-9]{6,64}(?:\/owner-root)?\/owner-installed-transport\.json$/u;
const WSL_PROOF = /^\/dev\/shm\/virki-witness-bridge-fixture-[a-zA-Z0-9]{6,64}(?:\/owner-root)?\/owner-installed-proof\.json$/u;
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
    path.normalize(folder) === folder && !folder.includes("\0") &&
    realpathSync.native(folder) === folder);
  // The private 0700 leaf can be renamed by an unprivileged user if ANY
  // ancestor is writable without sticky protection. Verify every component,
  // including /dev/shm (root-owned sticky) in disposable WSL fixtures.
  for (let current = folder;; current = path.dirname(current)) {
    const s = lstatSync(current, { bigint: true });
    demand(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0n && s.gid === 0n &&
      (current === folder ? (s.mode & 0o7777n) === 0o700n :
        (s.mode & 0o022n) === 0n || (s.mode & 0o1000n) !== 0n));
    if (current === path.dirname(current)) break;
  }
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
function recordIntent(intents, input, suffix = ".intent") {
  directoryOwned(intents);
  demand([".intent", ".confirmed"].includes(suffix) && HEX64.test(input.receiptSha256));
  const bytes = Buffer.from(JSON.stringify(input));
  demand(bytes.length <= 4096);
  const target = path.join(intents, `${input.receiptSha256}${suffix}`);
  const dirFd = openSync(intents, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const original = fstatSync(dirFd, { bigint: true });
    const sameDirectory = (s) => s.isDirectory() && !s.isSymbolicLink() &&
      ["dev", "ino", "uid", "gid", "mode"].every((key) => s[key] === original[key]);
    demand(sameDirectory(lstatSync(intents, { bigint: true })));
  // Existing or partially written intent always blocks retry. No replacement,
  // unlink, timeout reset or rollback path is provided.
  const fd = openSync(`/proc/self/fd/${dirFd}/${path.basename(target)}`,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
    constants.O_NOFOLLOW, 0o600);
  try {
    for (let index = 0; index < bytes.length;) {
      const wrote = writeSync(fd, bytes, index, bytes.length - index);
      demand(wrote > 0);
      index += wrote;
    }
    fsyncSync(fd);
  } finally { closeSync(fd); }
  fsyncSync(dirFd);
  demand(sameDirectory(fstatSync(dirFd, { bigint: true })) &&
    sameDirectory(lstatSync(intents, { bigint: true })));
  demand(safeFile(target, 4096).equals(bytes));
  } finally { closeSync(dirFd); }
}

function signedAuthorityFresh(input, issuedAt = Math.floor(Date.now() / 1000)) {
  const stageExpiry = input.stageApproval?.message?.expiresAt;
  const floorExpiry = input.evidence?.floorReceipt?.message?.expiresAt;
  const casExpiry = input.evidence?.casRequest?.ownerExpiresAt;
  return [stageExpiry, floorExpiry, casExpiry].every((expiry) =>
    Number.isSafeInteger(expiry) && issuedAt < expiry);
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
    demand(signedAuthorityFresh(input));
    recordIntent(locations.intents, intent);
    return Object.freeze({ status: "BRIDGE_INTENT_RECORDED_NONAUTHORIZING",
      manifestSha256: intent.manifestSha256, sourceSha: intent.sourceSha,
      sequence: intent.sequence, receiptSha256: intent.receiptSha256,
      ledgerAttemptAuthorized: false, witnessCasAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false });
  } catch { refuse(); }
}

/**
 * An owner-installed native route from a confirmed, independently signed CAS
 * and external floor to a fresh TLS 1.3 witness HEAD and durable host intent.
 * The nonauthorizing intent is fsynced before the network use point. If HEAD
 * times out, disagrees, or the host changes, the intent is permanently
 * uncertain and cannot be replayed as a new attempt.
 *
 * The remote CAS is deliberately NOT issued here: its private owner signer
 * belongs to a separate operator. No local fixture proves physical off-host
 * custody, and a live HEAD cannot itself establish a nonrollbackable floor.
 */
export async function recordHostWitnessLedgerActivationWithLiveWitness(input = {}) {
  exact(input, ["installedPolicyFile", "intentDirectory", "installedTransportFile",
    "ledgerState", "ledgerRequest", "checkpoint", "stageApproval", "evidence"]);
  const { installedTransportFile, ...bridgeInput } = input;
  const locations = trustedLocations(bridgeInput);
  const isFixture = locations.policy !== TRUST;
  demand(isFixture ? WSL_TRANSPORT.test(installedTransportFile) &&
    path.dirname(installedTransportFile) === path.dirname(locations.policy) :
    installedTransportFile === undefined || installedTransportFile === TRANSPORT);
  const transportFile = isFixture ? installedTransportFile : TRANSPORT;
  const policy = readExactJson(locations.policy, 16384);
  const policyDigest = sha(JSON.stringify(policy));
  const transport = readExactJson(transportFile, 8192);
  const transportDigest = sha(JSON.stringify(transport));
  exact(transport, ["version", "hostname", "port", "serverCertSha256",
    "caFile", "clientCertFile", "clientKeyFile"]);
  demand(transport.version === 1 && isIP(transport.hostname) !== 0 &&
    Number.isSafeInteger(transport.port) && transport.port >= 1 &&
    transport.port <= 65535 && HEX64.test(transport.serverCertSha256));
  // Production witness must be on another machine. Only disposable WSL tests
  // may bind loopback; no caller-selected network target is trusted.
  if (!isFixture) {
    demand(!/^(?:127\.|0\.|169\.254\.|22[4-9]\.|23\d\.|24\d\.|25\d\.|::|fe80:|ff)/iu.test(transport.hostname));
  }
  const config = {
    hostname: transport.hostname, port: transport.port,
    serverCertSha256: transport.serverCertSha256,
    ca: safeFile(transport.caFile, 16384),
    cert: safeFile(transport.clientCertFile, 16384),
    key: safeFile(transport.clientKeyFile, 16384),
    publicKeyPem: policy.witnessPublicKeyPem, pinSha256: policy.witnessPinSha256,
    ownerPublicKeyPem: policy.ownerPublicKeyPem, ownerPinSha256: policy.ownerPinSha256,
    hostIdentitySha256: policy.hostIdentitySha256, ledgerIdSha256: policy.ledgerIdSha256,
  };
  // This operation checks the exact owner CAS, distinct signed external floor,
  // host ledger, manifest and first activation-stage owner authorization, then
  // makes the receipt-scoped intent durable. It will refuse any repeat.
  const recorded = recordHostWitnessLedgerActivationBridge(bridgeInput);
  // Capture the exact verified authority before awaiting remote I/O; mutable
  // caller objects may not extend expiry or swap signed material afterward.
  const authorityUntil = Math.min(bridgeInput.stageApproval.message.expiresAt,
    bridgeInput.evidence.floorReceipt.message.expiresAt,
    bridgeInput.evidence.casRequest.ownerExpiresAt);
  const stageDigest = sha(JSON.stringify(bridgeInput.stageApproval));
  const floorDigest = sha(JSON.stringify(bridgeInput.evidence.floorReceipt));
  const casDigest = sha(JSON.stringify(bridgeInput.evidence.casRequest));
  const uncertain = () => Object.freeze({
    ...recorded, status: "BRIDGE_INTENT_LIVE_UNCERTAIN_NONAUTHORIZING",
    reconciliationRequired: true,
  });
  try {
    const head = await remoteWitnessHead(config, {
      minimumSequence: recorded.sequence,
      expectedHeadSha: recorded.sourceSha,
      minimumReceiptSha256: recorded.receiptSha256,
    });
    demand(Math.floor(Date.now() / 1000) < authorityUntil &&
      signedAuthorityFresh(bridgeInput) &&
      sha(JSON.stringify(bridgeInput.stageApproval)) === stageDigest &&
      sha(JSON.stringify(bridgeInput.evidence.floorReceipt)) === floorDigest &&
      sha(JSON.stringify(bridgeInput.evidence.casRequest)) === casDigest &&
      sha(JSON.stringify(readExactJson(locations.policy, 16384))) === policyDigest &&
      sha(JSON.stringify(readExactJson(transportFile, 8192))) === transportDigest &&
      sha(safeFile(policy.manifestFile, 1048576)) === policy.manifestSha256 &&
      JSON.stringify(readExactJson(path.join(policy.ledgerDirectory, "ledger.json"), 1048576)) ===
        JSON.stringify(bridgeInput.ledgerState) &&
      JSON.stringify(readExactJson(policy.activationCheckpointFile, 32768)) ===
        JSON.stringify(bridgeInput.checkpoint));
    const confirmation = {
      version: 1, receiptSha256: recorded.receiptSha256,
      hostIdentitySha256: policy.hostIdentitySha256, ledgerIdSha256: policy.ledgerIdSha256,
      manifestSha256: recorded.manifestSha256,
      transportSha256: transportDigest, liveHead: head.signedReceipt,
    };
    // Recheck the signed validity window at the last synchronous use point,
    // after all host-state reads, immediately before the O_EXCL sidecar.
    demand(Math.floor(Date.now() / 1000) < authorityUntil &&
      signedAuthorityFresh(bridgeInput));
    recordIntent(locations.intents, confirmation, ".confirmed");
    return Object.freeze({ ...recorded,
      status: "BRIDGE_INTENT_LIVE_CONFIRMED_NONAUTHORIZING",
      reconciliationRequired: false });
  } catch {
    // A remote request may have succeeded even if its reply was lost. The
    // already-fsynced .intent remains; no deletion or automatic retry exists.
    return uncertain();
  }
}

/** Owner-installed native operator entry: a fixed private proof file only. */
export async function recordInstalledHostWitnessManualIntent(args = []) {
  demand(Array.isArray(args) && process.platform === "linux" && process.getuid?.() === 0);
  const fixture = process.env.VIRKI_DISPOSABLE_WITNESS_BRIDGE === "1" &&
    /wsl|microsoft/iu.test(os.release());
  const source = fixture ? args[0] : PROOF;
  demand(fixture ? args.length === 1 && WSL_PROOF.test(source) :
    args.length === 0 && !/wsl|microsoft/iu.test(os.release()));
  const root = path.dirname(source);
  const installedPolicyFile = fixture ? path.join(root, "owner-installed-trust.json") : TRUST;
  const installedTransportFile = fixture ? path.join(root, "owner-installed-transport.json") : TRANSPORT;
  const intentDirectory = fixture ? path.join(root, "intents") : INTENTS;
  const proof = readExactJson(source, 32768);
  exact(proof, ["ledgerState", "ledgerRequest", "checkpoint", "stageApproval", "evidence"]);
  return recordHostWitnessLedgerActivationWithLiveWitness({
    installedPolicyFile, intentDirectory, installedTransportFile, ...proof,
  });
}
