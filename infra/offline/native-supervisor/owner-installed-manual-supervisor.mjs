import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  realpathSync, statfsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectNativeManualActivationSafety } from "../manual-native-activation-safety.mjs";
import { verifyIndependentWitnessHead, WITNESS_READ_DOMAIN } from
  "../../../scripts/lib/offline-independent-witness-service.mjs";
import { measureInstalledTrustedVerifierAtUseTime } from "../trusted-owner-installation.mjs";

// Read-only assembly of already available guards, not a new activation state
// machine or deployment executor. Native mode accepts ZERO authority-bearing
// parameters, and verifies its root-installed location before reading any
// independently provisioned source/witness/stage files. The WSL path below
// exercises disposable owner-owned files but can NEVER authorize an action.
const INSTALLED = "/usr/local/lib/virki/offline-release/infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs";
const NATIVE = Object.freeze({
  policy: "/etc/virki/manual-native-activation-policy.json",
  checkpoint: "/var/lib/virki/manual-native-activation/checkpoint.json",
  journal: "/var/lib/virki/manual-native-activation/journal",
  production: "/srv/virki",
  stage: "/etc/virki/manual-native-supervisor-stage.json",
  witness: "/etc/virki/manual-native-supervisor-witness-head.json",
  witnessPolicy: "/etc/virki/offline-witness-bridge.json",
  source: "/etc/virki/offline-source-commit.sha",
  installedPin: "/etc/virki/manual-native-supervisor.sha256",
});
const FIXTURE = /^\/dev\/shm\/virki-manual-safety-fixture-[a-zA-Z0-9_-]{6,64}$/u;
const SHA = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const deny = () => { throw new Error("Owner-installed manual native supervisor refused"); };
function check(ok) { if (!ok) deny(); }
function exact(object, fields) {
  check(object && typeof object === "object" && !Array.isArray(object) &&
    JSON.stringify(Object.keys(object)) === JSON.stringify(fields));
}
function same(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((name) => a[name] === b[name]);
}
function ownerDirectory(folder) {
  check(realpathSync.native(folder) === folder);
  for (let current = folder;; current = path.dirname(current)) {
    const s = lstatSync(current, { bigint: true });
    check(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0n && s.gid === 0n &&
      (current === folder ? (s.mode & 0o7777n) === 0o700n :
        ((s.mode & 0o022n) === 0n || (s.mode & 0o1000n) !== 0n)));
    if (current === path.dirname(current)) break;
  }
}
function fixedFile(filename, maxBytes = 32768, privateDirectory = true) {
  if (privateDirectory) ownerDirectory(path.dirname(filename));
  const before = lstatSync(filename, { bigint: true });
  check(before.isFile() && !before.isSymbolicLink() && before.uid === 0n &&
    before.gid === 0n && before.nlink === 1n &&
    (before.mode & 0o7777n) === 0o600n &&
    before.size > 0n && before.size <= BigInt(maxBytes));
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    check(same(before, fstatSync(fd, { bigint: true })));
    const bytes = readFileSync(fd);
    check(bytes.length === Number(before.size) &&
      same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(filename, { bigint: true })));
    return { bytes, identity: hash(bytes) };
  } finally { closeSync(fd); }
}
function json(filename, maxBytes = 32768) {
  const file = fixedFile(filename, maxBytes);
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(file.bytes));
  check(JSON.stringify(value) === file.bytes.toString("utf8"));
  return { value, identity: file.identity };
}
function paths(input) {
  check(process.platform === "linux" && process.arch === "x64" && process.getuid?.() === 0);
  const isWsl = /microsoft|wsl/iu.test(os.release());
  if (isWsl) {
    exact(input, ["fixtureRoot"]);
    const root = input.fixtureRoot;
    check(process.env.VIRKI_DISPOSABLE_NATIVE_ACTIVATION === "1" &&
      typeof root === "string" && FIXTURE.test(root) &&
      statfsSync("/dev/shm").type === 0x01021994);
    ownerDirectory(root);
    return Object.freeze({ fixture: true, policy: `${root}/owner-policy.json`,
      checkpoint: `${root}/checkpoint.json`, stage: `${root}/stage-proof.json`,
      witness: `${root}/witness-head.json`,
      witnessPolicy: `${root}/witness-bridge-policy.json`,
      source: `${root}/source-pin.sha`,
      production: `${root}/production` });
  }
  exact(input, []);
  const entry = fileURLToPath(import.meta.url);
  check(entry === INSTALLED && realpathSync.native(entry) === entry);
  // The executable and its transitive verifier closure must be measured under
  // independent owner-installed bootstrap custody. The audit pin is separate
  // from a candidate's manifest and cannot be passed by the caller.
  ownerDirectory(path.dirname(entry));
  const installed = fixedFile(entry, 2 * 1024 * 1024, false);
  ownerDirectory(path.dirname(NATIVE.installedPin));
  check(fixedFile(NATIVE.installedPin, 65).bytes.toString("ascii") ===
    `${installed.identity}\n`);
  const bootstrap = measureInstalledTrustedVerifierAtUseTime();
  check(bootstrap.status === "INSTALLED_VERIFIER_BYTES_MEASURED_ONLY" &&
    bootstrap.independentLedgerWitnessVerified === false);
  return Object.freeze({ ...NATIVE, fixture: false });
}

/**
 * No keys, source paths, authorization flags, witness callbacks, Docker/PG
 * executors, or data stores are accepted from the production caller. A valid
 * signature from a protected local file still cannot prove off-host custody or
 * a physically fenced writer, hence this API has no authorizing success.
 */
export function inspectInstalledManualSupervisorReadiness(input = {}) {
  try {
    const locations = paths(input);
    const { value: policy, identity: policyId } = json(locations.policy);
    const { value: checkpoint, identity: checkpointId } = json(locations.checkpoint);
    const { value: stageProof, identity: stageProofId } = json(locations.stage);
    const { value: witnessProof, identity: witnessId } = json(locations.witness);
    const { value: witnessPolicy, identity: witnessPolicyId } = json(locations.witnessPolicy);
    const pin = fixedFile(locations.source, 41).bytes.toString("ascii");
    check(REVISION.test(policy.candidateSha) && pin === `${policy.candidateSha}\n`);
    // The existing owner-installed witness bridge has its OWN immutable
    // source/host/ledger/owner/floor scope. A current signed witness HEAD
    // alone cannot be assigned to an arbitrary local activation or release.
    check(witnessPolicy.version === 1 &&
      SHA.test(witnessPolicy.ledgerIdSha256) &&
      witnessPolicy.hostIdentitySha256 === policy.hostIdentitySha256 &&
      witnessPolicy.manifestSha256 === policy.manifestSha256 &&
      witnessPolicy.sourceSha === policy.candidateSha &&
      witnessPolicy.activationAttemptId === policy.attemptId &&
      witnessPolicy.ownerPinSha256 === policy.ownerPinSha256 &&
      witnessPolicy.witnessPinSha256 === policy.witnessPinSha256 &&
      witnessPolicy.floorPinSha256 === policy.floorPinSha256);
    exact(witnessProof, ["version", "expectedSourceSha", "expectedReceiptSha256", "request", "receipt"]);
    check(witnessProof.version === 1 && witnessProof.expectedSourceSha === policy.candidateSha &&
      SHA.test(witnessProof.expectedReceiptSha256) &&
      witnessProof.request.domain === WITNESS_READ_DOMAIN &&
      witnessProof.request.hostIdentitySha256 === policy.hostIdentitySha256 &&
      witnessProof.request.ledgerIdSha256 === witnessPolicy.ledgerIdSha256 &&
      witnessProof.receipt.message.headSha === policy.candidateSha);
    const head = verifyIndependentWitnessHead({ receipt: witnessProof.receipt,
      request: witnessProof.request, publicKeyPem: policy.witnessPublicKeyPem,
      pinSha256: policy.witnessPinSha256,
      minimumSequence: 1, minimumReceiptSha256: witnessProof.expectedReceiptSha256 });
    check(head.headSha === policy.candidateSha && head.sequence >= 1 &&
      checkpoint.manifestSha256 === policy.manifestSha256 &&
      checkpoint.hostIdentitySha256 === policy.hostIdentitySha256 &&
      checkpoint.attemptId === policy.attemptId &&
      checkpoint.pending === null);
    // Reuse the existing complete journal, signed stage, maintenance, and PG
    // backup/clone preconditions. This call is deliberately nonauthorizing.
    const inspected = inspectNativeManualActivationSafety({
      policyFile: locations.policy, checkpointFile: locations.checkpoint,
      journalDirectory: policy.journalDirectory,
      productionRoot: locations.production, stage: stageProof.ownerApproval?.message?.stage,
      evidence: stageProof,
    });
    check(inspected.status === "LOCAL_NATIVE_ACTIVATION_EVIDENCE_ONLY" &&
      inspected.deployAuthorized === false && inspected.rollbackAuthorized === false &&
      inspected.witnessFloorVerified === false && inspected.databaseRollbackVerified === false);
    // Detect root-side replacement during the composed read-only checks;
    // no finite reread can replace an exclusive native owner lock at use.
    check([policyId, checkpointId, stageProofId, witnessId, witnessPolicyId].every((digest, index) =>
      digest === json([locations.policy, locations.checkpoint,
        locations.stage, locations.witness, locations.witnessPolicy][index]).identity) &&
      fixedFile(locations.source, 41).bytes.toString("ascii") === pin);
    return Object.freeze({ status: "HOST_SUPERVISOR_EVIDENCE_ONLY",
      sourceCommitPinMatched: true, signedWitnessHeadMatched: true,
      activationJournalMatched: true, nativeRootInstallerVerified: false,
      witnessFloorVerified: false, physicalWriterFenceVerified: false,
      nativePgRollbackVerified: false, deployAuthorized: false,
      rollbackAuthorized: false, resumeWritersAuthorized: false });
  } catch { deny(); }
}
