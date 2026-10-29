import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync,
  writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { activationSigningBytes, previewManualActivationCommit,
  previewManualActivationPrepare, MANUAL_ACTIVATION_STAGES } from "./manual-activation-transaction.mjs";
import { createDisposableManualActivationJournal, persistDisposableManualActivationIntent,
  persistDisposableManualActivationCompletion,
  inspectDisposableManualActivationJournal } from "./manual-activation-journal.mjs";
import { inspectNativeManualActivationSafety } from "./manual-native-activation-safety.mjs";

const fixtureOnly = { skip: process.platform !== "linux" || process.getuid?.() !== 0 ||
  !/microsoft|wsl/iu.test(os.release()) };
const sha = (data) => createHash("sha256").update(data).digest("hex");
const owner = generateKeyPairSync("ed25519");
const witness = generateKeyPairSync("ed25519");
const floor = generateKeyPairSync("ed25519");
const pem = (pair) => pair.publicKey.export({ type: "spki", format: "pem" });
const pin = (pair) => sha(pair.publicKey.export({ type: "spki", format: "der" }));
const genesis = () => ({ version: 1, attemptId: "a".repeat(32),
  hostIdentitySha256: "b".repeat(64), manifestSha256: "c".repeat(64),
  sequence: 0, receiptSha256: "d".repeat(64), completed: [], pending: null,
  previousDigest: "0".repeat(64) });
const signed = (message, pair) => ({ message,
  signature: sign(null, activationSigningBytes(message), pair.privateKey).toString("base64") });
function proof(c, stage) {
  const now = Math.floor(Date.now() / 1000);
  return { keys: { ownerPublicKeyPem: pem(owner), ownerPinSha256: pin(owner),
    witnessPublicKeyPem: pem(witness), witnessPinSha256: pin(witness) },
  measuredHostIdentitySha256: c.hostIdentitySha256,
  ownerApproval: signed({ version: 1, domain: "VIRKI_MANUAL_ACTIVATION_OWNER_STAGE_V1",
    attemptId: c.attemptId, hostIdentitySha256: c.hostIdentitySha256,
    manifestSha256: c.manifestSha256, stage, sequence: c.sequence + 1,
    previousDigest: sha(JSON.stringify(c)), expiresAt: now + 30 }, owner),
  witnessHead: signed({ version: 1, domain: "VIRKI_MANUAL_ACTIVATION_INDEPENDENT_HEAD_V1",
    attemptId: c.attemptId, hostIdentitySha256: c.hostIdentitySha256,
    manifestSha256: c.manifestSha256, sequence: c.sequence + 1,
    receiptSha256: sha(`${stage}:${c.sequence}`), issuedAt: now, expiresAt: now + 30 }, witness) };
}
function fixture(run) {
  const dir = mkdtempSync("/dev/shm/virki-manual-safety-fixture-");
  const journalDirectory = mkdtempSync("/dev/shm/virki-manual-activation-fixture-");
  chmodSync(dir, 0o700);
  chmodSync(journalDirectory, 0o700);
  const policyFile = path.join(dir, "owner-policy.json");
  const checkpointFile = path.join(dir, "checkpoint.json");
  const productionRoot = path.join(dir, "production");
  mkdirSync(productionRoot, { mode: 0o700 });
  const policy = { version: 1, attemptId: "a".repeat(32),
    hostIdentitySha256: "b".repeat(64), manifestSha256: "c".repeat(64),
    ownerPublicKeyPem: pem(owner), ownerPinSha256: pin(owner),
    witnessPublicKeyPem: pem(witness), witnessPinSha256: pin(witness),
    floorPublicKeyPem: pem(floor), floorPinSha256: pin(floor),
    journalDirectory, checkpointFile, productionRoot,
    candidateSha: "e".repeat(40), predecessorSha: "f".repeat(40) };
  const store = (file, value) => { writeFileSync(file, JSON.stringify(value), { mode: 0o600 }); chmodSync(file, 0o600); };
  const storeText = (file, value) => { writeFileSync(file, value, { mode: 0o600 }); chmodSync(file, 0o600); };
  let checkpoint = genesis();
  createDisposableManualActivationJournal({ directory: journalDirectory, checkpoint });
  store(policyFile, policy); store(checkpointFile, checkpoint);
  const args = (stage, evidence = proof(checkpoint, stage)) =>
    ({ policyFile, checkpointFile, journalDirectory, productionRoot, stage, evidence });
  const advance = () => {
    const stage = MANUAL_ACTIVATION_STAGES[checkpoint.sequence];
    const evidence = proof(checkpoint, stage);
    const prepared = previewManualActivationPrepare({ checkpoint, stage, evidence });
    assert.equal(prepared.status, "PREPARED_PREVIEW_ONLY");
    persistDisposableManualActivationIntent({ directory: journalDirectory, checkpoint: prepared.checkpoint });
    store(checkpointFile, prepared.checkpoint);
    const committed = previewManualActivationCommit({ checkpoint: prepared.checkpoint,
      stage, evidence, observed: { stage, result: "completed", snapshotSha256: sha(stage) } });
    assert.equal(committed.status, "COMMITTED_PREVIEW_ONLY");
    persistDisposableManualActivationCompletion({ directory: journalDirectory, checkpoint: committed.checkpoint });
    checkpoint = committed.checkpoint;
    store(checkpointFile, checkpoint);
  };
  try { run({ dir, args, advance, store, storeText, policy, policyFile, checkpointFile,
    productionRoot, journalDirectory, current: () => checkpoint }); }
  finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(journalDirectory, { recursive: true, force: true });
  }
}

test("native Windows denies all owner activation inspection", { skip: process.platform === "linux" }, () => {
  assert.throws(() => inspectNativeManualActivationSafety({}), /refused/u);
});

test("RED: root-pinned owner keys and ordered journal are prerequisite; never authorize", fixtureOnly,
  () => fixture(({ args, advance, productionRoot, storeText }) => {
    const first = inspectNativeManualActivationSafety(args("fence-writers"));
    assert.equal(first.status, "LOCAL_NATIVE_ACTIVATION_EVIDENCE_ONLY");
    assert.equal(first.deployAuthorized, false);
    assert.equal(first.writerFenceVerified, false);
    assert.equal(first.witnessFloorVerified, false);
    advance();
    assert.throws(() => inspectNativeManualActivationSafety(args("verify-backup")), /refused/u);
    storeText(path.join(productionRoot, ".virki-maintenance"),
      `revision=${"e".repeat(40)}\nstarted_at=2026-10-29T00:00:00Z\n`);
    const next = inspectNativeManualActivationSafety(args("verify-backup"));
    assert.equal(next.status, "LOCAL_NATIVE_ACTIVATION_EVIDENCE_ONLY");
    assert.equal(next.resumeWritersAuthorized, false);
  }));

test("RED: actual SIGKILL after fsynced intent keeps replay and resume blocked", fixtureOnly,
  () => fixture(({ args, advance, current, checkpointFile, store, journalDirectory }) => {
    advance(); advance(); advance(); advance();
    const c = current();
    const evidence = proof(c, "migrate-live");
    const prepared = previewManualActivationPrepare({ checkpoint: c, stage: "migrate-live", evidence });
    const script = `import { persistDisposableManualActivationIntent } from ` +
      `${JSON.stringify(new URL("./manual-activation-journal.mjs", import.meta.url).href)};` +
      `persistDisposableManualActivationIntent({directory:process.argv[1],` +
      `checkpoint:JSON.parse(process.argv[2])});process.kill(process.pid,"SIGKILL")`;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", script,
      journalDirectory, JSON.stringify(prepared.checkpoint)],
    { shell: false, encoding: "utf8", timeout: 10000 });
    assert.equal(child.signal, "SIGKILL", child.stderr);
    store(checkpointFile, prepared.checkpoint);
    assert.throws(() => inspectNativeManualActivationSafety(args("migrate-live", evidence)), /refused/u);
    assert.throws(() => inspectNativeManualActivationSafety(args("resume-writers", evidence)), /refused/u);
  }));

test("RED: forged installed owner, signer collision and replaced checkpoints denied", fixtureOnly,
  () => fixture(({ args, policy, policyFile, checkpointFile, store, current }) => {
    assert.throws(() => inspectNativeManualActivationSafety(args("activate-runtime")), /refused/u);
    const bad = { ...proof(current(), "fence-writers"),
      keys: { ...proof(current(), "fence-writers").keys, ownerPublicKeyPem: pem(floor), ownerPinSha256: pin(floor) } };
    assert.throws(() => inspectNativeManualActivationSafety(args("fence-writers", bad)), /refused/u);
    store(policyFile, { ...policy, floorPinSha256: pin(owner) });
    assert.throws(() => inspectNativeManualActivationSafety(args("fence-writers")), /refused/u);
    store(policyFile, policy);
    store(checkpointFile, { ...current(), sequence: 2 });
    assert.throws(() => inspectNativeManualActivationSafety(args("fence-writers")), /refused/u);
    // A forged state at the SAME sequence, even with a correctly signed new
    // permit, must not bypass the chained last journal checkpoint.
    const forged = { ...current(), receiptSha256: sha("replacement-head") };
    store(checkpointFile, forged);
    assert.throws(() => inspectNativeManualActivationSafety(args("fence-writers",
      proof(forged, "fence-writers"))), /refused/u);
    store(checkpointFile, current());
    chmodSync(policyFile, 0o644);
    assert.throws(() => inspectNativeManualActivationSafety(args("fence-writers")), /refused/u);
    chmodSync(policyFile, 0o600);
    unlinkSync(policyFile);
    symlinkSync(checkpointFile, policyFile);
    assert.throws(() => inspectNativeManualActivationSafety(args("fence-writers")), /refused/u);
  }));

test("RED: untrusted path, expiring permit and witness replay never open a native operation", fixtureOnly,
  () => fixture(({ args, current, dir }) => {
    const stage = "fence-writers";
    assert.throws(() => inspectNativeManualActivationSafety({ ...args(stage),
      policyFile: path.join(dir, "outside-policy.json") }), /refused/u);
    const e = proof(current(), stage);
    const stale = { ...e, ownerApproval: signed({ ...e.ownerApproval.message,
      expiresAt: Math.floor(Date.now() / 1000) - 1 }, owner) };
    assert.throws(() => inspectNativeManualActivationSafety(args(stage, stale)), /refused/u);
    const replay = { ...e, witnessHead: signed({ ...e.witnessHead.message,
      sequence: 7 }, witness) };
    assert.throws(() => inspectNativeManualActivationSafety(args(stage, replay)), /refused/u);
    assert.throws(() => inspectNativeManualActivationSafety(args("resume-writers")), /refused/u);
  }));

test("RED: signed historical stages cannot replace physical PG rollback and private health", fixtureOnly,
  () => fixture(({ args, advance, productionRoot, storeText }) => {
    for (let index = 0; index < 6; index++) advance();
    storeText(path.join(productionRoot, ".virki-maintenance"),
      `revision=${"e".repeat(40)}\nstarted_at=2026-10-29T00:00:00Z\n`);
    // All six prior signed journal entries exist, including an unphysical
    // preview of private health. Missing native backup/clone/guard blocks the
    // runtime switch, even with valid signer and journal chain.
    assert.throws(() => inspectNativeManualActivationSafety(args("activate-runtime")), /refused/u);
    assert.throws(() => inspectNativeManualActivationSafety(args("resume-writers")), /refused/u);
  }));

test("RED: concurrent independently fsynced next completion invalidates stale use-point inspection", fixtureOnly,
  () => fixture(({ args, current, journalDirectory }) => {
    const initial = current();
    const stage = "fence-writers";
    const evidence = proof(initial, stage);
    const prepared = previewManualActivationPrepare({ checkpoint: initial, stage, evidence });
    assert.equal(prepared.status, "PREPARED_PREVIEW_ONLY");
    const committed = previewManualActivationCommit({ checkpoint: prepared.checkpoint,
      stage, evidence, observed: { stage, result: "completed", snapshotSha256: sha(stage) } });
    assert.equal(committed.status, "COMMITTED_PREVIEW_ONLY");
    const childScript = `import { persistDisposableManualActivationIntent, ` +
      `persistDisposableManualActivationCompletion } from ` +
      `${JSON.stringify(new URL("./manual-activation-journal.mjs", import.meta.url).href)};` +
      `persistDisposableManualActivationIntent({directory:process.argv[1],` +
      `checkpoint:JSON.parse(process.argv[2])});` +
      `persistDisposableManualActivationCompletion({directory:process.argv[1],` +
      `checkpoint:JSON.parse(process.argv[3])});`;
    let concurrentCommitCount = 0;
    const racingEvidence = { ...evidence };
    // A malicious accessor forces the scheduling boundary after the guard's
    // initial journal snapshot, without introducing any test hook in the
    // production API. A separate real OS process durably advances the journal
    // while the root checkpoint remains at sequence zero.
    Object.defineProperty(racingEvidence, "ownerApproval", {
      enumerable: true,
      get() {
        if (concurrentCommitCount === 0) {
          concurrentCommitCount++;
          const child = spawnSync(process.execPath, ["--input-type=module", "-e", childScript,
            journalDirectory, JSON.stringify(prepared.checkpoint), JSON.stringify(committed.checkpoint)],
          { shell: false, encoding: "utf8", timeout: 10000 });
          assert.equal(child.status, 0, child.stderr);
        }
        return evidence.ownerApproval;
      },
    });
    assert.throws(() => inspectNativeManualActivationSafety(args(stage, racingEvidence)), /refused/u);
    assert.equal(concurrentCommitCount, 1);
    assert.equal(inspectDisposableManualActivationJournal({ directory: journalDirectory }).sequence, 1);
    assert.throws(() => inspectNativeManualActivationSafety(args(stage)), /refused/u);
  }));
