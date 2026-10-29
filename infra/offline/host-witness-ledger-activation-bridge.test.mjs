import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync,
  symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { GENESIS_HEAD, GENESIS_RECEIPT, independentWitnessOwnerCasSigningBytes,
  WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN } from "../../scripts/lib/offline-independent-witness-service.mjs";
import { offlineWitnessLedgerTransitionDigest } from "./disposable-witness-ledger-reservation.mjs";
import { FLOOR_READ_DOMAIN } from "./trusted-out-of-host-floor-evidence.mjs";
import { activationSigningBytes } from "./manual-activation-transaction.mjs";
import { recordHostWitnessLedgerActivationBridge } from "./host-witness-ledger-activation-bridge.mjs";

const enabled = process.platform === "linux" && process.getuid?.() === 0 &&
  /wsl|microsoft/iu.test(os.release());
const sha = (v) => createHash("sha256").update(v).digest("hex");
const pem = (key) => key.export({ format: "pem", type: "spki" });
const pin = (key) => sha(key.export({ format: "der", type: "spki" }));
const signMessage = (message, key, domain = "") => sign(null,
  domain ? Buffer.from(`${domain}\0${JSON.stringify(message)}`) : Buffer.from(JSON.stringify(message)),
  key).toString("base64");
const signed = (message, key) => {
  const signature = signMessage(message, key);
  return { message, signature, receiptSha256: sha(JSON.stringify({ message, signature })) };
};
const now = () => Math.floor(Date.now() / 1000);

function fixture() {
  const dir = mkdtempSync("/dev/shm/virki-witness-bridge-fixture-");
  const intentDirectory = path.join(dir, "intents");
  mkdirSync(intentDirectory, { mode: 0o700 });
  const owner = generateKeyPairSync("ed25519");
  const witness = generateKeyPairSync("ed25519");
  const floor = generateKeyPairSync("ed25519");
  const keys = {
    ownerPublicKeyPem: pem(owner.publicKey), ownerPinSha256: pin(owner.publicKey),
    witnessPublicKeyPem: pem(witness.publicKey), witnessPinSha256: pin(witness.publicKey),
    floorPublicKeyPem: pem(floor.publicKey), floorPinSha256: pin(floor.publicKey),
  };
  const hostIdentitySha256 = "1".repeat(64);
  const ledgerIdSha256 = "2".repeat(64);
  const manifestBytes = Buffer.from('{"version":1,"release":"disposable-w26"}');
  const manifestSha256 = sha(manifestBytes);
  const manifestFile = path.join(dir, "manifest.json");
  writeFileSync(manifestFile, manifestBytes, { mode: 0o600 });
  const nextSha = "b".repeat(40);
  const ledgerDirectory = path.join(dir, "ledger");
  mkdirSync(ledgerDirectory, { mode: 0o700 });
  const ledgerState = { version: 1, anchorSha: GENESIS_HEAD, entries: [] };
  writeFileSync(path.join(ledgerDirectory, "ledger.json"), JSON.stringify(ledgerState), { mode: 0o600 });
  const ledgerRequest = {
    directory: ledgerDirectory, manifestSha256,
    priorSha: GENESIS_HEAD, nextSha, nonce: "4".repeat(32),
    sequence: 1, approvalDigest: "5".repeat(64),
  };
  const checkpoint = { version: 1, attemptId: "6".repeat(32), hostIdentitySha256,
    manifestSha256, sequence: 0, receiptSha256: GENESIS_RECEIPT,
    completed: [], pending: null, previousDigest: "0".repeat(64) };
  const activationCheckpointFile = path.join(dir, "activation-checkpoint.json");
  writeFileSync(activationCheckpointFile, JSON.stringify(checkpoint), { mode: 0o600 });
  const unsigned = {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: "7".repeat(64), requestId: "8".repeat(64),
    hostIdentitySha256, ledgerIdSha256, expectedSequence: 0,
    expectedHeadSha: GENESIS_HEAD, expectedReceiptSha256: GENESIS_RECEIPT,
    nextHeadSha: nextSha,
    transitionSha256: offlineWitnessLedgerTransitionDigest(ledgerRequest),
    ownerExpiresAt: now() + 25,
  };
  const casRequest = { ...unsigned, ownerSignature: sign(null,
    independentWitnessOwnerCasSigningBytes(unsigned), owner.privateKey).toString("base64") };
  const m = {
    version: 1, domain: WITNESS_CAS_DOMAIN,
    challenge: casRequest.challenge, requestId: casRequest.requestId,
    hostIdentitySha256, ledgerIdSha256, sequence: 1, priorHeadSha: GENESIS_HEAD,
    headSha: nextSha, previousReceiptSha256: GENESIS_RECEIPT,
    transitionSha256: casRequest.transitionSha256, ownerSignature: casRequest.ownerSignature,
    ownerSignatureSha256: sha(casRequest.ownerSignature), ownerExpiresAt: casRequest.ownerExpiresAt,
    issuedAt: now(), expiresAt: now() + 30,
  };
  const casReceipt = signed(m, witness.privateKey);
  const headRequest = { version: 1, domain: WITNESS_READ_DOMAIN, challenge: "9".repeat(64),
    hostIdentitySha256, ledgerIdSha256 };
  const headReceipt = signed({ ...headRequest, sequence: 1, headSha: nextSha,
    receiptSha256: casReceipt.receiptSha256, issuedAt: now(), expiresAt: now() + 30 }, witness.privateKey);
  const floorRequest = { version: 1, domain: FLOOR_READ_DOMAIN,
    challenge: headRequest.challenge, hostIdentitySha256, ledgerIdSha256,
    phase: "after", casRequestSha256: sha(JSON.stringify(casRequest)) };
  const floorMessage = { ...floorRequest, sequence: 1, headSha: nextSha,
    receiptSha256: casReceipt.receiptSha256, issuedAt: now(), expiresAt: now() + 30 };
  const floorReceipt = { message: floorMessage,
    signature: signMessage(floorMessage, floor.privateKey, FLOOR_READ_DOMAIN) };
  const stageOwnerMessage = {
    version: 1, domain: "VIRKI_MANUAL_ACTIVATION_OWNER_STAGE_V1",
    attemptId: checkpoint.attemptId, hostIdentitySha256,
    manifestSha256, stage: "fence-writers", sequence: 1,
    previousDigest: sha(JSON.stringify(checkpoint)), expiresAt: now() + 25,
  };
  const stageApproval = { message: stageOwnerMessage,
    signature: sign(null, activationSigningBytes(stageOwnerMessage), owner.privateKey).toString("base64") };
  const installedPolicyFile = path.join(dir, "owner-installed-trust.json");
  const policy = { version: 1, hostIdentitySha256, ledgerIdSha256, manifestSha256,
    manifestFile, sourceSha: nextSha, ledgerDirectory, activationCheckpointFile,
    activationAttemptId: checkpoint.attemptId,
    expectedSequence: 0, expectedHeadSha: GENESIS_HEAD,
    expectedReceiptSha256: GENESIS_RECEIPT, ...keys };
  writeFileSync(installedPolicyFile, JSON.stringify(policy), { mode: 0o600 });
  chmodSync(installedPolicyFile, 0o600);
  const evidence = { phase: "after", pins: keys,
    expected: { hostIdentitySha256, ledgerIdSha256, sequence: 0,
      headSha: GENESIS_HEAD, receiptSha256: GENESIS_RECEIPT },
    casRequest, casReceipt, headRequest, headReceipt, floorRequest, floorReceipt,
    ack: "confirmed" };
  const input = { installedPolicyFile, intentDirectory, ledgerState, ledgerRequest,
    checkpoint, stageApproval, evidence };
  return { dir, input, policy, owner, witness, floor,
    cleanup: () => rmSync(dir, { force: true, recursive: true }) };
}

test("root-installed witness bridge binds exact signed CAS, distinct signed floor, ledger and first activation stage", { skip: !enabled }, () => {
  const f = fixture();
  try {
    const result = recordHostWitnessLedgerActivationBridge(f.input);
    assert.equal(result.status, "BRIDGE_INTENT_RECORDED_NONAUTHORIZING");
    assert.equal(result.manifestSha256, f.input.ledgerRequest.manifestSha256);
    assert.equal(result.sequence, 1);
    assert.equal(result.receiptSha256, f.input.evidence.casReceipt.receiptSha256);
    assert.equal(result.deployAuthorized, false);
    assert.equal(result.ledgerAttemptAuthorized, false);
    assert.equal(readdirSync(f.input.intentDirectory).length, 1);
    const intent = JSON.parse(readFileSync(path.join(f.input.intentDirectory,
      readdirSync(f.input.intentDirectory)[0]), "utf8"));
    assert.equal(intent.manifestSha256, f.input.ledgerRequest.manifestSha256);
    assert.equal(intent.stage, "fence-writers");
    assert.throws(() => recordHostWitnessLedgerActivationBridge(f.input), /refused/u);
    const retryInput = path.join(f.dir, "retry.json");
    writeFileSync(retryInput, JSON.stringify(f.input), { mode: 0o600 });
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import { readFileSync } from "node:fs";
      import { recordHostWitnessLedgerActivationBridge } from ${JSON.stringify(fileURLToPath(new URL("./host-witness-ledger-activation-bridge.mjs", import.meta.url)).replaceAll("\\", "/"))};
      try { recordHostWitnessLedgerActivationBridge(JSON.parse(readFileSync(process.argv[1]))); process.exit(0); }
      catch { process.exit(42); }
    `, retryInput], { env: { ...process.env, VIRKI_DISPOSABLE_WITNESS_BRIDGE: "1" }, encoding: "utf8" });
    assert.equal(child.status, 42, child.stderr);
    assert.equal(readdirSync(f.input.intentDirectory).length, 1);
  } finally { f.cleanup(); }
});

test("owner-signed witness HEAD domain must NEVER stand in for stage approval or create an intent", { skip: !enabled }, () => {
  const f = fixture();
  try {
    // The signature is legitimate for the owner's pinned Ed25519 key, and
    // activationSigningBytes supports both domains. Only the stage-use point
    // can prevent cross-domain authorization.
    const wrongDomain = {
      ...f.input.stageApproval.message,
      domain: "VIRKI_MANUAL_ACTIVATION_INDEPENDENT_HEAD_V1",
    };
    f.input.stageApproval = {
      message: wrongDomain,
      signature: sign(null, activationSigningBytes(wrongDomain),
        f.owner.privateKey).toString("base64"),
    };
    assert.throws(() => recordHostWitnessLedgerActivationBridge(f.input), /refused/u);
    assert.deepEqual(readdirSync(f.input.intentDirectory), [],
      "cross-domain signed proof cannot produce durable activation intent");
  } finally { f.cleanup(); }
});

test("bridge fails closed before durable intent on manifest, sequence, floor, owner, stage and trust substitution", { skip: !enabled }, () => {
  const mutations = [
    (x) => { x.ledgerRequest.manifestSha256 = "e".repeat(64); },
    (x) => { x.ledgerRequest.sequence += 1; },
    (x) => { x.checkpoint.manifestSha256 = "f".repeat(64); },
    (x) => { x.checkpoint.attemptId = "f".repeat(32); },
    (x) => { x.stageApproval.message.stage = "activate-runtime"; },
    (x) => { x.stageApproval.signature = "A".repeat(86) + "=="; },
    (x) => { x.evidence.casReceipt.message.transitionSha256 = "f".repeat(64); },
    (x) => { x.evidence.casRequest.requestId = "f".repeat(64); },
    (x) => { x.evidence.floorReceipt.message.receiptSha256 = "f".repeat(64); },
    (x) => { x.evidence.floorReceipt.signature = "A".repeat(86) + "=="; },
    (x) => { x.evidence.ack = "unknown"; },
    (x) => { x.evidence.expected.sequence = 1; },
    (x) => { x.evidence.pins.floorPinSha256 = x.evidence.pins.witnessPinSha256; },
    (x) => { x.evidence.pins.ownerPublicKeyPem = generateKeyPairSync("ed25519")
      .publicKey.export({ format: "pem", type: "spki" }); },
    (x) => { x.ledgerState.entries = [{ fake: true }]; },
    (x) => { writeFileSync(path.join(path.dirname(x.installedPolicyFile), "manifest.json"),
      "replaced", { mode: 0o600 }); },
    (x) => { writeFileSync(path.join(path.dirname(x.installedPolicyFile), "ledger", "ledger.json"),
      "{}", { mode: 0o600 }); },
    (x) => { writeFileSync(path.join(path.dirname(x.installedPolicyFile), "activation-checkpoint.json"),
      "{}", { mode: 0o600 }); },
  ];
  for (const mutate of mutations) {
    const f = fixture();
    try {
      mutate(f.input);
      assert.throws(() => recordHostWitnessLedgerActivationBridge(f.input), /refused/u);
      assert.deepEqual(readdirSync(f.input.intentDirectory), []);
    } finally { f.cleanup(); }
  }
});

test("bridge never accepts arbitrary operator-trust paths or public fixture on normal Linux", { skip: !enabled }, () => {
  const f = fixture();
  try {
    chmodSync(f.input.installedPolicyFile, 0o644);
    assert.throws(() => recordHostWitnessLedgerActivationBridge(f.input), /refused/u);
    chmodSync(f.input.installedPolicyFile, 0o600);
    assert.throws(() => recordHostWitnessLedgerActivationBridge({ ...f.input,
      installedPolicyFile: "/tmp/owner.json" }), /refused/u);
    const manifest = f.policy.manifestFile;
    const safe = path.join(f.dir, "manifest.bak");
    writeFileSync(safe, readFileSync(manifest), { mode: 0o600 });
    unlinkSync(manifest);
    symlinkSync(safe, manifest);
    assert.throws(() => recordHostWitnessLedgerActivationBridge(f.input), /refused/u);
  } finally { f.cleanup(); }
});
