import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  IndependentOfflineWitness, WITNESS_CAS_DOMAIN, GENESIS_HEAD, GENESIS_RECEIPT,
  independentWitnessOwnerCasSigningBytes,
} from "../../scripts/lib/offline-independent-witness-service.mjs";
import {
  reserveDisposableWitnessedLedgerAttempt, offlineWitnessLedgerTransitionDigest,
} from "./disposable-witness-ledger-reservation.mjs";
import { validateOfflineLedgerTransition } from "../../scripts/lib/offline-release-ledger.mjs";

const hex = (n) => randomBytes(n).toString("hex");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const pin = (key) => sha256(key.export({ type: "spki", format: "der" }));

test("reservation digest is canonical across property order and binds every ledger field", () => {
  const request = {
    directory: "/isolated/ledger", manifestSha256: "1".repeat(64),
    priorSha: "a".repeat(40), nextSha: "b".repeat(40),
    nonce: "c".repeat(32), sequence: 1, approvalDigest: "d".repeat(64),
  };
  const expected = offlineWitnessLedgerTransitionDigest(request);
  assert.match(expected, /^[a-f0-9]{64}$/u);
  assert.equal(offlineWitnessLedgerTransitionDigest(Object.fromEntries(Object.entries(request).reverse())), expected);
  for (const [key, value] of Object.entries(request)) {
    assert.notEqual(offlineWitnessLedgerTransitionDigest({ ...request, [key]:
      typeof value === "number" ? 2 : `${value}changed` }), expected, key);
  }
  assert.throws(() => offlineWitnessLedgerTransitionDigest({ ...request, injected: true }), /blocked/u);
});

const fixture = (t) => {
  const root = mkdtempSync(join(tmpdir(), "virki-disposable-cas-reserve-"));
  const database = join(root, "db");
  const anchors = join(root, "anchors");
  mkdirSync(database, { mode: 0o700 });
  mkdirSync(anchors, { mode: 0o700 });
  const witness = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const keyFile = join(root, "witness.pem");
  const ownerFile = join(root, "owner.pem");
  writeFileSync(keyFile, witness.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(ownerFile, owner.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  chmodSync(keyFile, 0o600);
  chmodSync(ownerFile, 0o600);
  const scope = { hostIdentitySha256: hex(32), ledgerIdSha256: hex(32) };
  const previous = process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE;
  process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE = "1";
  const service = new IndependentOfflineWitness({
    directory: database, anchorDirectory: anchors,
    keyFile, ownerPublicKeyFile: ownerFile,
    expectedKeyPinSha256: pin(witness.publicKey),
    expectedOwnerPinSha256: pin(owner.publicKey), ...scope,
  });
  t.after(() => {
    service.close();
    if (previous === undefined) delete process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE;
    else process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE = previous;
    rmSync(root, { recursive: true, force: true });
  });
  const keys = {
    publicKeyPem: witness.publicKey.export({ type: "spki", format: "pem" }),
    pinSha256: pin(witness.publicKey),
    ownerPublicKeyPem: owner.publicKey.export({ type: "spki", format: "pem" }),
    ownerPinSha256: pin(owner.publicKey),
  };
  const ledgerState = { version: 1, anchorSha: "a".repeat(40), entries: [] };
  const ledgerRequest = {
    directory: join(root, "not-a-production-ledger"), manifestSha256: hex(32),
    priorSha: ledgerState.anchorSha, nextSha: "b".repeat(40),
    nonce: hex(16), sequence: 1, approvalDigest: hex(32),
  };
  const checkpoint = { sequence: 0, receiptSha256: GENESIS_RECEIPT };
  const signedRequest = (changes = {}) => {
    const unsigned = {
      version: 1, domain: WITNESS_CAS_DOMAIN, challenge: hex(32), requestId: hex(32),
      ...scope, expectedSequence: 0, expectedHeadSha: GENESIS_HEAD,
      expectedReceiptSha256: GENESIS_RECEIPT, nextHeadSha: ledgerRequest.nextSha,
      transitionSha256: offlineWitnessLedgerTransitionDigest(ledgerRequest),
      ownerExpiresAt: Math.floor(Date.now() / 1000) + 25, ...changes,
    };
    return { ...unsigned, ownerSignature: sign(null,
      independentWitnessOwnerCasSigningBytes(unsigned), owner.privateKey).toString("base64") };
  };
  const calls = { read: 0, cas: 0, reserve: 0 };
  const adapters = {
    readWitness: async (request) => { calls.read += 1; return service.read(request); },
    casWitness: async (request) => { calls.cas += 1; return service.cas(request); },
    reserveAttempt: async (accepted) => {
      assert.equal(Object.isFrozen(accepted), true);
      assert.deepEqual(accepted, ledgerRequest);
      calls.reserve += 1;
      return { status: "attempted", pendingSha: accepted.nextSha, sequence: accepted.sequence };
    },
  };
  const inputs = (changes = {}) => ({
    ledgerState, ledgerRequest, ownerCasRequest: signedRequest(), scope, keys,
    checkpoint, ...adapters, ...changes,
  });
  return { service, inputs, signedRequest, ledgerRequest, ledgerState, checkpoint, scope, keys, calls, adapters };
};

test("owner-authorized witness CAS binds the exact ledger reservation before the local attempt", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  const accepted = await reserveDisposableWitnessedLedgerAttempt(f.inputs());
  assert.deepEqual({ status: accepted.status, sequence: accepted.sequence, pendingSha: accepted.pendingSha },
    { status: "witnessed-attempt-disposable-only", sequence: 1, pendingSha: f.ledgerRequest.nextSha });
  assert.equal(accepted.witnessCasAuthorized, false);
  assert.equal(accepted.deployAuthorized, false);
  assert.deepEqual(f.calls, { read: 1, cas: 1, reserve: 1 });
  await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs()), /refused|blocked/iu);
  assert.deepEqual(f.calls, { read: 2, cas: 1, reserve: 1 });
});

test("second release requires a committed predecessor, new owner authorization and previous witness checkpoint", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  const first = await reserveDisposableWitnessedLedgerAttempt(f.inputs());
  const committedLedger = validateOfflineLedgerTransition(f.ledgerState, f.ledgerRequest);
  const secondRequest = {
    ...f.ledgerRequest, priorSha: f.ledgerRequest.nextSha, nextSha: "c".repeat(40),
    sequence: 2, nonce: hex(16), manifestSha256: hex(32), approvalDigest: hex(32),
  };
  const ownerCasRequest = f.signedRequest({
    expectedSequence: 1, expectedHeadSha: f.ledgerRequest.nextSha,
    expectedReceiptSha256: first.receiptSha256,
    nextHeadSha: secondRequest.nextSha,
    transitionSha256: offlineWitnessLedgerTransitionDigest(secondRequest),
  });
  const second = await reserveDisposableWitnessedLedgerAttempt(f.inputs({
    ledgerState: committedLedger, ledgerRequest: secondRequest,
    checkpoint: { sequence: 1, receiptSha256: first.receiptSha256 }, ownerCasRequest,
    reserveAttempt: async (accepted) => ({
      status: "attempted", pendingSha: accepted.nextSha, sequence: accepted.sequence,
    }),
  }));
  assert.equal(second.sequence, 2);
  assert.equal(second.pendingSha, "c".repeat(40));
  assert.notEqual(second.receiptSha256, first.receiptSha256);
});

test("tampering with any accepted ledger identity, SHA, nonce or approval refuses before CAS or reserve", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  for (const field of ["manifestSha256", "nonce", "approvalDigest", "nextSha", "priorSha", "sequence"]) {
    const replacement = field === "sequence" ? 2
      : field === "nonce" ? hex(16)
        : field === "nextSha" || field === "priorSha" ? "c".repeat(40) : hex(32);
    const changed = { ...f.ledgerRequest, [field]: replacement };
    await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs({ ledgerRequest: changed })), /refused|blocked/iu, field);
  }
  assert.equal(f.calls.cas, 0);
  assert.equal(f.calls.reserve, 0);
});

test("two concurrent owner-authorized reservations against one witnessed head admit exactly one", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  const [first, second] = await Promise.allSettled([
    reserveDisposableWitnessedLedgerAttempt(f.inputs()),
    reserveDisposableWitnessedLedgerAttempt(f.inputs()),
  ]);
  assert.deepEqual([first.status, second.status].sort(), ["fulfilled", "rejected"]);
  assert.equal(f.calls.reserve, 1);
  assert.equal(f.calls.cas, 2);
});

test("forged signed witness CAS receipt cannot invoke a local attempt, even if the witness advanced", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  const request = f.signedRequest();
  await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs({
    ownerCasRequest: request,
    casWitness: async (value) => {
      const receipt = f.service.cas(value);
      return { ...receipt, receiptSha256: hex(32) };
    },
  })), /blocked/iu);
  assert.equal(f.calls.reserve, 0);
  await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs({ ownerCasRequest: request })), /blocked/iu);
  assert.equal(f.calls.reserve, 0);
});

test("owner-approved CAS request cannot be swapped to a different signed transition during async HEAD read", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  const original = f.signedRequest();
  const malicious = f.signedRequest({ nextHeadSha: "c".repeat(40), transitionSha256: hex(32) });
  const accepted = await reserveDisposableWitnessedLedgerAttempt(f.inputs({
    ownerCasRequest: original,
    readWitness: async (read) => {
      const signedHead = f.service.read(read);
      Object.assign(original, malicious);
      return signedHead;
    },
  }));
  assert.equal(accepted.pendingSha, f.ledgerRequest.nextSha);
  assert.equal(f.calls.cas, 1);
  assert.equal(f.calls.reserve, 1);
  const head = f.service.read({ version: 1, domain: "VIRKI_OFFLINE_INDEPENDENT_WITNESS_HEAD_V1", challenge: hex(32), ...f.scope });
  assert.equal(head.message.headSha, f.ledgerRequest.nextSha);
});

test("missing independent checkpoint, wrong witness/owner pins and forged owner CAS refuse without reservation", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  for (const change of [
    { checkpoint: undefined },
    { checkpoint: { sequence: 1, receiptSha256: GENESIS_RECEIPT } },
    { keys: { ...f.keys, pinSha256: hex(32) } },
    { keys: { ...f.keys, ownerPinSha256: hex(32) } },
    { ownerCasRequest: { ...f.signedRequest(), ownerSignature: "A".repeat(86) + "==" } },
    { ownerCasRequest: f.signedRequest({ expectedHeadSha: "f".repeat(40) }) },
    { ownerCasRequest: f.signedRequest({ expectedReceiptSha256: hex(32) }) },
  ]) await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs(change)), /refused|blocked/iu);
  assert.equal(f.calls.cas, 0);
  assert.equal(f.calls.reserve, 0);
});

test("lost CAS receipt after durable witness COMMIT and failed ledger reserve must NOT retry", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  const request = f.signedRequest();
  await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs({
    ownerCasRequest: request,
    casWitness: async (value) => { f.service.cas(value); throw new Error("connection lost after COMMIT"); },
  })), /blocked/iu);
  assert.equal(f.calls.reserve, 0);
  const head = f.service.read({ version: 1, domain: "VIRKI_OFFLINE_INDEPENDENT_WITNESS_HEAD_V1", challenge: hex(32), ...f.scope });
  assert.equal(head.message.sequence, 1);
  await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs({ ownerCasRequest: request })), /blocked/iu);
  assert.equal(f.calls.reserve, 0);
});

test("valid CAS followed by failed local reservation cannot yield a second attempt", { skip: process.platform !== "linux" }, async (t) => {
  const f = fixture(t);
  const request = f.signedRequest();
  await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs({
    ownerCasRequest: request,
    reserveAttempt: async () => { throw new Error("disk full after witness CAS"); },
  })), /blocked/iu);
  assert.equal(f.calls.cas, 1);
  await assert.rejects(reserveDisposableWitnessedLedgerAttempt(f.inputs({ ownerCasRequest: request })), /blocked/iu);
  assert.equal(f.calls.reserve, 0);
});
