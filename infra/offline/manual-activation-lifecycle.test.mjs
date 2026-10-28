import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import test from "node:test";
import {
  MANUAL_ACTIVATION_STAGES, activationSigningBytes,
  previewManualActivationCommit, previewManualActivationPrepare,
} from "./manual-activation-transaction.mjs";
import {
  createDisposableManualActivationJournal, inspectDisposableManualActivationJournal,
  persistDisposableManualActivationIntent, persistDisposableManualActivationCompletion,
} from "./manual-activation-journal.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const opt = { skip: process.platform !== "linux" ||
  process.getuid?.() !== 0 || !/microsoft|wsl/iu.test(os.release()) };
const owner = generateKeyPairSync("ed25519");
const witness = generateKeyPairSync("ed25519");
const pem = (key) => key.publicKey.export({ type: "spki", format: "pem" });
const pin = (key) => sha(key.publicKey.export({ type: "spki", format: "der" }));
const keys = { ownerPublicKeyPem: pem(owner), ownerPinSha256: pin(owner),
  witnessPublicKeyPem: pem(witness), witnessPinSha256: pin(witness) };
const signature = (message, privateKey) => ({ message, signature: sign(null,
  activationSigningBytes(message), privateKey).toString("base64") });
function genesis() { return {
  version: 1, attemptId: "a".repeat(32), hostIdentitySha256: "b".repeat(64),
  manifestSha256: "c".repeat(64), sequence: 0,
  receiptSha256: "d".repeat(64), completed: [], pending: null,
  previousDigest: "0".repeat(64),
}; }
function proof(c, stage) {
  const now = Math.floor(Date.now() / 1000);
  return { keys, measuredHostIdentitySha256: c.hostIdentitySha256,
    ownerApproval: signature({
      version: 1, domain: "VIRKI_MANUAL_ACTIVATION_OWNER_STAGE_V1",
      attemptId: c.attemptId, hostIdentitySha256: c.hostIdentitySha256,
      manifestSha256: c.manifestSha256, stage, sequence: c.sequence + 1,
      previousDigest: sha(JSON.stringify(c)), expiresAt: now + 30,
    }, owner.privateKey),
    witnessHead: signature({
      version: 1, domain: "VIRKI_MANUAL_ACTIVATION_INDEPENDENT_HEAD_V1",
      attemptId: c.attemptId, hostIdentitySha256: c.hostIdentitySha256,
      manifestSha256: c.manifestSha256, sequence: c.sequence + 1,
      receiptSha256: sha(`${c.attemptId}:${stage}:${c.sequence + 1}`),
      issuedAt: now, expiresAt: now + 30,
    }, witness.privateKey) };
}
function fixture(run) {
  const directory = mkdtempSync("/dev/shm/virki-manual-activation-fixture-");
  chmodSync(directory, 0o700);
  try { return run(directory); } finally { rmSync(directory, { force: true, recursive: true }); }
}

test("RED: all eight protected stages persist ordered, durable intent and commit", opt, () => fixture((directory) => {
  let checkpoint = genesis();
  createDisposableManualActivationJournal({ directory, checkpoint });
  for (const stage of MANUAL_ACTIVATION_STAGES) {
    const evidence = proof(checkpoint, stage);
    const prepared = previewManualActivationPrepare({ checkpoint, stage, evidence });
    assert.equal(prepared.status, "PREPARED_PREVIEW_ONLY");
    persistDisposableManualActivationIntent({ directory, checkpoint: prepared.checkpoint });
    assert.equal(inspectDisposableManualActivationJournal({ directory }).status,
      "DISPOSABLE_PENDING_OPERATOR_RECONCILIATION");
    const observed = { stage, result: "completed", snapshotSha256: sha(`test:${stage}`) };
    const committed = previewManualActivationCommit({ checkpoint: prepared.checkpoint,
      stage, observed, evidence });
    assert.equal(committed.status, "COMMITTED_PREVIEW_ONLY");
    persistDisposableManualActivationCompletion({ directory, checkpoint: committed.checkpoint });
    assert.equal(inspectDisposableManualActivationJournal({ directory }).status,
      "DISPOSABLE_COMMITTED_NONAUTHORIZING");
    checkpoint = committed.checkpoint;
  }
  assert.equal(checkpoint.sequence, MANUAL_ACTIVATION_STAGES.length);
  assert.equal(inspectDisposableManualActivationJournal({ directory }).sequence,
    MANUAL_ACTIVATION_STAGES.length);
  assert.equal(previewManualActivationPrepare({ checkpoint, stage: "activate-runtime",
    evidence: proof(checkpoint, "activate-runtime") }).status, "BLOCKED_MANUAL_ACTIVATION");
}));

test("RED: actual SIGKILL after migrate-live intent survives restart and forbids any retry/rollback shortcut", opt, () => fixture((directory) => {
  let checkpoint = genesis();
  createDisposableManualActivationJournal({ directory, checkpoint });
  for (const stage of MANUAL_ACTIVATION_STAGES.slice(0, 4)) {
    const evidence = proof(checkpoint, stage);
    const prepare = previewManualActivationPrepare({ checkpoint, stage, evidence });
    persistDisposableManualActivationIntent({ directory, checkpoint: prepare.checkpoint });
    const finish = previewManualActivationCommit({ checkpoint: prepare.checkpoint, stage,
      evidence, observed: { stage, result: "completed", snapshotSha256: sha(stage) } });
    persistDisposableManualActivationCompletion({ directory, checkpoint: finish.checkpoint });
    checkpoint = finish.checkpoint;
  }
  const stage = "migrate-live";
  const evidence = proof(checkpoint, stage);
  const prepared = previewManualActivationPrepare({ checkpoint, stage, evidence });
  assert.equal(prepared.status, "PREPARED_PREVIEW_ONLY");
  // A separate OS process writes+fsyncs the exact pre-existing intent, then
  // is killed without a commit. No Docker/PG is contacted, no fake witness
  // proof is promoted to a host authority, and no process cleanup runs.
  const moduleUrl = new URL("./manual-activation-journal.mjs", import.meta.url).href;
  const script = `import { persistDisposableManualActivationIntent } from ${JSON.stringify(moduleUrl)};` +
    `persistDisposableManualActivationIntent({directory:process.argv[1],` +
    `checkpoint:JSON.parse(process.argv[2])});process.kill(process.pid,"SIGKILL");`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script,
    directory, JSON.stringify(prepared.checkpoint)], { shell: false, encoding: "utf8", timeout: 5000 });
  assert.equal(result.signal, "SIGKILL");
  assert.equal(inspectDisposableManualActivationJournal({ directory }).status,
    "DISPOSABLE_PENDING_OPERATOR_RECONCILIATION");
  assert.equal(inspectDisposableManualActivationJournal({ directory }).sequence, 4);
  assert.throws(() => persistDisposableManualActivationIntent({ directory,
    checkpoint: prepared.checkpoint }));
  assert.equal(previewManualActivationPrepare({ checkpoint: prepared.checkpoint,
    stage: "rollback-restore", evidence: proof(prepared.checkpoint, "rollback-restore") }).status,
    "BLOCKED_MANUAL_ACTIVATION");
  assert.equal(previewManualActivationPrepare({ checkpoint: prepared.checkpoint,
    stage: "resume-writers", evidence: proof(prepared.checkpoint, "resume-writers") }).status,
    "BLOCKED_MANUAL_ACTIVATION");
  assert.throws(() => persistDisposableManualActivationCompletion({ directory,
    checkpoint: { ...prepared.checkpoint, pending: null } }));
}));
