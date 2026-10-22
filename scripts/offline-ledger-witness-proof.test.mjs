import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  probeIndependentOfflineLedgerWitnessRead,
  verifyIndependentOfflineLedgerWitnessRead,
} from "./lib/offline-ledger-witness-proof.mjs";

const NOW = 1_800_000_000;
const HOST = "a".repeat(64);
const LEDGER = "b".repeat(64);
const HEAD = "c".repeat(40);
const CHALLENGE = "d".repeat(64);
const witness = generateKeyPairSync("ed25519");
const outsider = generateKeyPairSync("ed25519");
const pin = createHash("sha256").update(witness.publicKey.export({ type: "spki", format: "der" })).digest("hex");
const publicPem = witness.publicKey.export({ type: "spki", format: "pem" });

function message(challenge = CHALLENGE) {
  return {
    version: 1, domain: "VIRKI_OFFLINE_LEDGER_WITNESS_READ_V1", challenge,
    hostIdentitySha256: HOST, ledgerSha256: LEDGER, sequence: 4,
    headSha: HEAD, issuedAt: NOW - 2, expiresAt: NOW + 15,
  };
}

function signed(value, key = witness.privateKey) {
  return Buffer.from(JSON.stringify({
    message: value,
    signature: sign(null, Buffer.from(JSON.stringify(value)), key).toString("base64"),
  }));
}

function request(responseBytes = signed(message())) {
  return {
    responseBytes, witnessPublicKeyPem: publicPem, witnessPublicKeyPinSha256: pin,
    expectedChallenge: CHALLENGE, hostIdentitySha256: HOST,
    ledgerSha256: LEDGER, sequence: 4, headSha: HEAD, nowSeconds: NOW,
  };
}

test("signed independent read proves only a fresh exact host and ledger snapshot, never authority", () => {
  const result = verifyIndependentOfflineLedgerWitnessRead(request());
  assert.deepEqual(result, {
    status: "INDEPENDENT_WITNESS_READ_MATCH_ONLY",
    sequence: 4, headSha: HEAD, ledgerSha256: LEDGER,
    witnessCasAuthorized: false, dockerLoadAuthorized: false, deployAuthorized: false,
  });
  assert.equal(Object.isFrozen(result), true);
});

test("fresh challenge rejects replay, crossed host, stale head, and rolled back digest", async (t) => {
  const variants = [
    ["old challenge", { expectedChallenge: "1".repeat(64) }],
    ["other host", { hostIdentitySha256: "1".repeat(64) }],
    ["rewound ledger", { ledgerSha256: "2".repeat(64) }],
    ["rewound sequence", { sequence: 3 }],
    ["alternate head", { headSha: "e".repeat(40) }],
    ["revoked public key pin", { witnessPublicKeyPinSha256: "0".repeat(64) }],
  ];
  for (const [name, changed] of variants) {
    await t.test(name, () => assert.throws(() =>
      verifyIndependentOfflineLedgerWitnessRead({ ...request(), ...changed })));
  }
});

test("refuses forged signatures and unrelated Ed25519 signers", () => {
  assert.throws(() => verifyIndependentOfflineLedgerWitnessRead(
    request(signed(message(), outsider.privateKey))));
  const replacement = signed(message());
  replacement[15] ^= 1;
  assert.throws(() => verifyIndependentOfflineLedgerWitnessRead(request(replacement)));
});

test("rejects expired, premature, future-dated, and excessively long witness statements", async (t) => {
  for (const [name, change] of [
    ["expired", { expiresAt: NOW }],
    ["not issued", { issuedAt: NOW + 1 }],
    ["old issuance", { issuedAt: NOW - 31 }],
    ["long validity", { expiresAt: NOW + 31 }],
  ]) {
    await t.test(name, () => assert.throws(() => verifyIndependentOfflineLedgerWitnessRead(
      request(signed({ ...message(), ...change })))));
  }
});

test("rejects duplicate JSON keys, unknown fields, shuffled field order and oversized response", async (t) => {
  const valid = signed(message());
  const nonCanonical = [
    Buffer.from(valid.toString().replace('"version":1', '"version":1,"version":1')),
    Buffer.from(valid.toString().replace('"signature":', '"extra":true,"signature":')),
    Buffer.from(JSON.stringify({ signature: "x", message: message() })),
    signed({ ...message(), extra: "forged" }),
    signed({ version: 1, domain: message().domain, sequence: 4,
      challenge: CHALLENGE, hostIdentitySha256: HOST, ledgerSha256: LEDGER,
      headSha: HEAD, issuedAt: NOW - 2, expiresAt: NOW + 15 }),
    Buffer.alloc(4097, 32),
  ];
  for (const [i, bytes] of nonCanonical.entries()) {
    await t.test(`invalid canonical reply ${i}`, () => assert.throws(() =>
      verifyIndependentOfflineLedgerWitnessRead(request(bytes))));
  }
});

test("read transport is fixture-only and caller cannot inject its generated challenge", async (t) => {
  const old = process.env.VIRKI_DISPOSABLE_WITNESS_PROBE;
  t.after(() => {
    if (old === undefined) delete process.env.VIRKI_DISPOSABLE_WITNESS_PROBE;
    else process.env.VIRKI_DISPOSABLE_WITNESS_PROBE = old;
  });
  const base = request();
  delete base.responseBytes;
  delete base.expectedChallenge;
  let captured;
  const exchange = async (challengeMessage) => {
    captured = challengeMessage;
    return signed(message(challengeMessage.challenge));
  };
  delete process.env.VIRKI_DISPOSABLE_WITNESS_PROBE;
  await assert.rejects(probeIndependentOfflineLedgerWitnessRead({ ...base, exchange }));
  assert.equal(captured, undefined);
  process.env.VIRKI_DISPOSABLE_WITNESS_PROBE = "1";
  const result = await probeIndependentOfflineLedgerWitnessRead({ ...base, exchange });
  assert.match(captured.challenge, /^[0-9a-f]{64}$/u);
  assert.notEqual(captured.challenge, CHALLENGE);
  assert.equal(Object.isFrozen(captured), true);
  assert.equal(result.deployAuthorized, false);
  await assert.rejects(probeIndependentOfflineLedgerWitnessRead({
    ...base, exchange: async () => signed(message(CHALLENGE)),
  }));
});
