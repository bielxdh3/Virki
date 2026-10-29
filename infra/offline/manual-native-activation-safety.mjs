import { createHash, createPublicKey } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  realpathSync, statfsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { inspectDisposableManualActivationJournal } from "./manual-activation-journal.mjs";
import { MANUAL_ACTIVATION_STAGES, previewManualActivationPrepare } from
  "./manual-activation-transaction.mjs";
import { inspectProtectedManualPgRollback } from "./native-manual-pg-rollback-preflight.mjs";

// One read-only prerequisite for a future independently installed root driver.
// Never call Docker, PostgreSQL, host commands or arbitrary callbacks here.
// Evidence inspected here cannot establish *physical* quiescence, independent
// floor monotonicity or live DB health. No return value authorizes activation.
const NATIVE = Object.freeze({
  policyFile: "/etc/virki/manual-native-activation-policy.json",
  checkpointFile: "/var/lib/virki/manual-native-activation/checkpoint.json",
  journalDirectory: "/var/lib/virki/manual-native-activation/journal",
  productionRoot: "/srv/virki",
});
const SHA = /^[a-f0-9]{64}$/u;
const GIT = /^[a-f0-9]{40}$/u;
const ATTEMPT = /^[a-f0-9]{32}$/u;
const FIXTURE = /^\/dev\/shm\/virki-manual-safety-fixture-[a-zA-Z0-9_-]{6,64}$/u;
const JOURNAL = /^\/dev\/shm\/virki-manual-activation-fixture-[a-zA-Z0-9_-]{6,64}$/u;
const hash = (data) => createHash("sha256").update(data).digest("hex");
const demand = (ok) => { if (!ok) throw new Error("Native manual activation safety refused"); };
function exact(value, keys) {
  demand(value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(keys));
}
function secureDirectory(directory) {
  demand(typeof directory === "string" && path.isAbsolute(directory) &&
    path.normalize(directory) === directory && realpathSync.native(directory) === directory);
  const leaf = lstatSync(directory, { bigint: true });
  demand(leaf.isDirectory() && !leaf.isSymbolicLink() && leaf.uid === 0n &&
    leaf.gid === 0n && (leaf.mode & 0o7777n) === 0o700n);
  // An attacker-writable ancestor may rename a protected directory unless it
  // is sticky and the leaf is owned by root. Check every path component.
  for (let ancestor = path.dirname(directory);;) {
    const s = lstatSync(ancestor, { bigint: true });
    demand(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0n &&
      ((s.mode & 0o022n) === 0n || (s.mode & 0o1000n) !== 0n));
    if (ancestor === path.dirname(ancestor)) break;
    ancestor = path.dirname(ancestor);
  }
}
function secureBytes(filename, limit = 16384) {
  secureDirectory(path.dirname(filename));
  const before = lstatSync(filename, { bigint: true });
  const same = (a, b) => ["dev", "ino", "uid", "gid", "mode", "nlink", "size",
    "mtimeNs", "ctimeNs"].every((field) => a[field] === b[field]);
  demand(before.isFile() && !before.isSymbolicLink() && before.uid === 0n &&
    before.gid === 0n && before.nlink === 1n && (before.mode & 0o7777n) === 0o600n &&
    before.size > 0n && before.size <= BigInt(limit));
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    demand(same(before, fstatSync(fd, { bigint: true })));
    const bytes = readFileSync(fd);
    demand(bytes.length === Number(before.size) &&
      same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(filename, { bigint: true })));
    return { bytes, digest: hash(bytes) };
  } finally { closeSync(fd); }
}
function secureJson(filename, limit = 16384) {
  const file = secureBytes(filename, limit);
  const content = new TextDecoder("utf-8", { fatal: true }).decode(file.bytes);
  const value = JSON.parse(content);
  demand(content === JSON.stringify(value));
  return { value, digest: file.digest };
}
function verifyKey(pem, expectedPin) {
  demand(typeof pem === "string" && pem.length > 0 && pem.length < 4096 && SHA.test(expectedPin));
  const key = createPublicKey(pem);
  demand(key.asymmetricKeyType === "ed25519" &&
    hash(key.export({ format: "der", type: "spki" })) === expectedPin);
}
function mode(input) {
  demand(process.platform === "linux" && process.getuid?.() === 0);
  const wsl = /microsoft|wsl/iu.test(os.release());
  const fixture = wsl && process.env.VIRKI_DISPOSABLE_NATIVE_ACTIVATION === "1";
  if (!fixture) {
    demand(!wsl && Object.keys(NATIVE).every((name) => input[name] === NATIVE[name]));
    return NATIVE;
  }
  const dir = path.dirname(input.policyFile);
  demand(FIXTURE.test(dir) &&
    input.policyFile === path.join(dir, "owner-policy.json") &&
    input.checkpointFile === path.join(dir, "checkpoint.json") &&
    input.productionRoot === path.join(dir, "production") &&
    JOURNAL.test(input.journalDirectory) &&
    statfsSync("/dev/shm").type === 0x01021994);
  secureDirectory(dir);
  secureDirectory(input.productionRoot);
  secureDirectory(input.journalDirectory);
  return { ...input, fixture: true };
}
function installedPolicy(policy, paths) {
  exact(policy, ["version", "attemptId", "hostIdentitySha256", "manifestSha256",
    "ownerPublicKeyPem", "ownerPinSha256", "witnessPublicKeyPem", "witnessPinSha256",
    "floorPublicKeyPem", "floorPinSha256", "journalDirectory", "checkpointFile",
    "productionRoot", "candidateSha", "predecessorSha"]);
  demand(policy.version === 1 && ATTEMPT.test(policy.attemptId) &&
    SHA.test(policy.hostIdentitySha256) && SHA.test(policy.manifestSha256) &&
    GIT.test(policy.candidateSha) && GIT.test(policy.predecessorSha) &&
    policy.candidateSha !== policy.predecessorSha &&
    policy.journalDirectory === paths.journalDirectory &&
    policy.checkpointFile === paths.checkpointFile &&
    policy.productionRoot === paths.productionRoot &&
    new Set([policy.ownerPinSha256, policy.witnessPinSha256,
      policy.floorPinSha256]).size === 3);
  for (const role of ["owner", "witness", "floor"]) {
    verifyKey(policy[`${role}PublicKeyPem`], policy[`${role}PinSha256`]);
  }
}
function maintenanceMarker(root, revision) {
  const file = path.join(root, ".virki-maintenance");
  const data = new TextDecoder("utf-8", { fatal: true }).decode(secureBytes(file, 1024).bytes);
  // Match the production-server.sh maintenance marker, never pretend it
  // independently measures actual Docker writers or remote ingress.
  demand(new RegExp(`^revision=${revision}\\nstarted_at=\\d{4}-\\d\\d-\\d\\dT` +
    `\\d\\d:\\d\\d:\\d\\dZ\\n$`, "u").test(data));
}
function journalHead(directory, checkpoint) {
  const filename = `${String(checkpoint.sequence).padStart(8, "0")}.complete`;
  const record = secureJson(path.join(directory, filename), 32768);
  const names = checkpoint.sequence === 0 ? ["checkpoint"] : ["intentSha256", "checkpoint"];
  exact(record.value, names);
  // Checking only the journal sequence would permit a caller to replace an
  // uncommitted checkpoint with a fabricated checkpoint at the same sequence.
  demand(JSON.stringify(record.value.checkpoint) === JSON.stringify(checkpoint));
  return record.digest;
}

/**
 * Inspect signed, sequential local activation admission from root-owned files.
 * WSL fixtures can exercise journal behavior; native Linux deliberately cannot
 * pass until a separately audited, pinned, durable *native* journal, physical
 * writer fence, independent witness floor and PG execution adapter exist.
 */
export function inspectNativeManualActivationSafety(input = {}) {
  try {
    exact(input, ["policyFile", "checkpointFile", "journalDirectory",
      "productionRoot", "stage", "evidence"]);
    const paths = mode(input);
    const pinned = secureJson(paths.policyFile);
    installedPolicy(pinned.value, paths);
    const checkpoint = secureJson(paths.checkpointFile);
    const { value: c } = checkpoint;
    const policy = pinned.value;
    demand(c.version === 1 && c.attemptId === policy.attemptId &&
      c.hostIdentitySha256 === policy.hostIdentitySha256 &&
      c.manifestSha256 === policy.manifestSha256 &&
      c.pending === null && Number.isSafeInteger(c.sequence) &&
      MANUAL_ACTIVATION_STAGES[c.sequence] === input.stage);
    // Never accept caller-supplied pins or a substituted host measurement.
    exact(input.evidence, ["keys", "measuredHostIdentitySha256", "ownerApproval", "witnessHead"]);
    exact(input.evidence.keys, ["ownerPublicKeyPem", "ownerPinSha256",
      "witnessPublicKeyPem", "witnessPinSha256"]);
    demand(input.evidence.measuredHostIdentitySha256 === policy.hostIdentitySha256 &&
      ["owner", "witness"].every((role) =>
        input.evidence.keys[`${role}PublicKeyPem`] === policy[`${role}PublicKeyPem`] &&
        input.evidence.keys[`${role}PinSha256`] === policy[`${role}PinSha256`]));
    const journal = inspectDisposableManualActivationJournal({ directory: paths.journalDirectory });
    demand(journal.status === "DISPOSABLE_COMMITTED_NONAUTHORIZING" &&
      journal.sequence === c.sequence);
    const headDigest = journalHead(paths.journalDirectory, c);
    if (c.sequence > 0) maintenanceMarker(paths.productionRoot, policy.candidateSha);
    if (c.sequence >= 4) {
      const rollback = inspectProtectedManualPgRollback({
        productionRoot: paths.productionRoot,
        expectedNewSha: policy.candidateSha, expectedPredecessorSha: policy.predecessorSha,
      });
      demand(rollback.status === "PROTECTED_PG_ROLLBACK_EVIDENCE_ONLY" &&
        rollback.rollbackAuthorized === false &&
        (c.sequence < 5 || rollback.checkpointPhase === "VERIFIED"));
    }
    const preview = previewManualActivationPrepare({ checkpoint: c, stage: input.stage,
      evidence: input.evidence });
    demand(preview.status === "PREPARED_PREVIEW_ONLY" &&
      preview.deployAuthorized === false && preview.checkpoint.pending?.stage === input.stage);
    // Detect even root-side state replacement during independent proof checks.
    const latest = inspectDisposableManualActivationJournal({ directory: paths.journalDirectory });
    demand(secureJson(paths.policyFile).digest === pinned.digest &&
      secureJson(paths.checkpointFile).digest === checkpoint.digest &&
      latest.status === "DISPOSABLE_COMMITTED_NONAUTHORIZING" &&
      latest.sequence === c.sequence &&
      journalHead(paths.journalDirectory, c) === headDigest);
    return Object.freeze({ status: "LOCAL_NATIVE_ACTIVATION_EVIDENCE_ONLY",
      nextStage: input.stage, sequence: c.sequence + 1,
      stagePermitVerifiedAgainstInstalledPins: true,
      journalHistoryReadOnlyVerified: true,
      hostIdentityPhysicallyMeasured: false,
      writerFenceVerified: false, witnessFloorVerified: false,
      databaseRollbackVerified: false, privateHealthVerified: false,
      deployAuthorized: false, dockerAuthorized: false, rollbackAuthorized: false,
      resumeWritersAuthorized: false });
  } catch { throw new Error("Native manual activation safety refused"); }
}
