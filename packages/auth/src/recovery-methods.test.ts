import assert from "node:assert/strict";
import { test } from "node:test";
import type { Prisma } from "@virki/database";
import { normalizeRecoveryPolicy, isRecoveryProofSatisfied, sanitizeRecoveryComment, recoveryPasskeyBinding, recoveryTotpBinding, requireLiveRecoveryProofsInTransaction, recoveryReviewReady } from "./recovery-methods";

test("explicit recovery methods require two independent factors or one plus different admin", () => {
  assert.deepEqual(normalizeRecoveryPolicy({ proofs: ["PASSKEY", "TOTP"], adminReview: false }), { proofs: ["PASSKEY", "TOTP"], adminReview: false });
  assert.deepEqual(normalizeRecoveryPolicy({ proofs: ["TOTP", "EMAIL"], adminReview: false }), { proofs: ["EMAIL", "TOTP"], adminReview: false });
  assert.deepEqual(normalizeRecoveryPolicy({ proofs: ["PASSKEY", "EMAIL"], adminReview: false }), { proofs: ["EMAIL", "PASSKEY"], adminReview: false });
  assert.deepEqual(normalizeRecoveryPolicy({ proofs: ["PASSKEY", "EMAIL", "TOTP"], adminReview: false })?.proofs, ["EMAIL", "PASSKEY", "TOTP"]);
  for (const proof of ["EMAIL", "PASSKEY", "TOTP"]) assert.deepEqual(normalizeRecoveryPolicy({ proofs: [proof], adminReview: true }), { proofs: [proof], adminReview: true });
  for (const policy of [
    { proofs: ["EMAIL"], adminReview: false },
    { proofs: ["PASSKEY", "TOTP"], adminReview: true },
    { proofs: ["EMAIL", "EMAIL"], adminReview: false },
    { proofs: ["EMAIL", "PASSWORD"], adminReview: false },
    { proofs: [], adminReview: true },
    { proofs: ["PASSKEY", "TOTP", "EMAIL", "EMAIL"], adminReview: false },
  ]) assert.equal(normalizeRecoveryPolicy(policy), null);
});

test("proof checks never substitute a missing factor or a missing independent reviewer", () => {
  const at = new Date();
  assert.equal(isRecoveryProofSatisfied(["PASSKEY", "TOTP"], false, { emailVerifiedAt: at, recoveryPasskeyVerifiedAt: at, recoveryTotpVerifiedAt: null, reviewedByUserId: null }), false);
  assert.equal(isRecoveryProofSatisfied(["PASSKEY", "TOTP"], false, { emailVerifiedAt: null, recoveryPasskeyVerifiedAt: at, recoveryTotpVerifiedAt: at, reviewedByUserId: null }), true);
  assert.equal(isRecoveryProofSatisfied(["EMAIL"], true, { emailVerifiedAt: at, recoveryPasskeyVerifiedAt: null, recoveryTotpVerifiedAt: null, reviewedByUserId: null }), false);
  assert.equal(isRecoveryProofSatisfied(["EMAIL"], true, { emailVerifiedAt: at, recoveryPasskeyVerifiedAt: null, recoveryTotpVerifiedAt: null, reviewedByUserId: "other-admin" }), true);
  assert.equal(isRecoveryProofSatisfied([], false, { emailVerifiedAt: at, recoveryPasskeyVerifiedAt: at, recoveryTotpVerifiedAt: at, reviewedByUserId: "other-admin" }), false);
});

test("optional recovery comment rejects oversized and control-laden content", () => {
  assert.equal(sanitizeRecoveryComment("  Preciso recuperar minha conta  "), "Preciso recuperar minha conta");
  assert.equal(sanitizeRecoveryComment(" "), null);
  assert.throws(() => sanitizeRecoveryComment("a".repeat(301)));
  assert.throws(() => sanitizeRecoveryComment("texto\r\nperigoso"));
});

test("recovery passkey proof stays bound to exact credential and signing key, independent of changing counter", () => {
  const credential = { id: "credential-1", userId: "user-1", credentialId: "webauthn-id", publicKey: Buffer.from("public-key-v1") };
  const initial = recoveryPasskeyBinding(credential);
  assert.equal(initial, recoveryPasskeyBinding({ ...credential, publicKey: Buffer.from("public-key-v1") }));
  assert.notEqual(initial, recoveryPasskeyBinding({ ...credential, publicKey: Buffer.from("different-key") }));
  assert.notEqual(initial, recoveryPasskeyBinding({ ...credential, userId: "different-user" }));
  assert.notEqual(initial, recoveryPasskeyBinding({ ...credential, id: "new-credential" }));
});

test("recovery TOTP proof stays bound to enrolled secret and confirmation epoch", () => {
  const factor = { id: "factor-1", secretCiphertext: "ciphertext-v1", keyVersion: 1, confirmedAt: new Date("2026-11-09T15:00:00.000Z") };
  const initial = recoveryTotpBinding(factor);
  assert.equal(initial, recoveryTotpBinding({ ...factor }));
  assert.notEqual(initial, recoveryTotpBinding({ ...factor, secretCiphertext: "rotated-secret" }));
  assert.notEqual(initial, recoveryTotpBinding({ ...factor, confirmedAt: new Date("2026-11-09T15:02:00.000Z") }));
  assert.notEqual(initial, recoveryTotpBinding({ ...factor, keyVersion: 2 }));
});

test("stale or revoked TOTP proof is rejected under recovery account lock", async () => {
  const factor = { id: "factor-1", secretCiphertext: "encrypted-secret", keyVersion: 1, confirmedAt: new Date(), lastUsedStep: 42, status: "ACTIVE" };
  const user = { secondFactorMethod: "TOTP" };
  const tx = {
    totpFactor: { findUnique: async () => factor },
    user: { findUnique: async () => user }
  } as unknown as Prisma.TransactionClient;
  const row = { userId: "user-1", recoveryProofs: ["TOTP"], recoveryTotpBindingHash: recoveryTotpBinding(factor), recoveryTotpUsedStep: 42, recoveryPasskeyCredentialId: null, recoveryPasskeyBindingHash: null };
  await assert.doesNotReject(requireLiveRecoveryProofsInTransaction(tx, row));
  factor.lastUsedStep = 41;
  await assert.rejects(requireLiveRecoveryProofsInTransaction(tx, row));
  factor.lastUsedStep = 42;
  factor.status = "REVOKED";
  await assert.rejects(requireLiveRecoveryProofsInTransaction(tx, row));
  factor.status = "ACTIVE";
  user.secondFactorMethod = "EMAIL";
  await assert.rejects(requireLiveRecoveryProofsInTransaction(tx, row));
  user.secondFactorMethod = "TOTP";
  factor.secretCiphertext = "rotated-secret";
  await assert.rejects(requireLiveRecoveryProofsInTransaction(tx, row));
});

test("passkey recovery proof is rejected after credential revocation or key rotation", async () => {
  const credential = { id: "credential-1", userId: "user-1", credentialId: "authenticator-id", publicKey: Buffer.from("public-key"), revokedAt: null as Date | null };
  const tx = {
    passkeyCredential: {
      findFirst: async ({ where }: { where: { id: string; userId: string; revokedAt: null } }) =>
        where.id === credential.id && where.userId === credential.userId && where.revokedAt === null && credential.revokedAt === null ? credential : null
    }
  } as unknown as Prisma.TransactionClient;
  const row = { userId: "user-1", recoveryProofs: ["PASSKEY"], recoveryTotpBindingHash: null, recoveryTotpUsedStep: null, recoveryPasskeyCredentialId: credential.id, recoveryPasskeyBindingHash: recoveryPasskeyBinding(credential) };
  await assert.doesNotReject(requireLiveRecoveryProofsInTransaction(tx, row));
  credential.revokedAt = new Date();
  await assert.rejects(requireLiveRecoveryProofsInTransaction(tx, row));
  credential.revokedAt = null;
  credential.publicKey = Buffer.from("rotated-key");
  await assert.rejects(requireLiveRecoveryProofsInTransaction(tx, row));
});

test("administrator queue accepts one proven factor only when reviewer is still required", () => {
  const at = new Date();
  const pending = { recoveryProofs: ["PASSKEY", "TOTP"], recoveryAdminReview: false, emailVerifiedAt: null, recoveryPasskeyVerifiedAt: at, recoveryTotpVerifiedAt: at, reviewedByUserId: null };
  assert.equal(recoveryReviewReady(pending), false);
  assert.equal(recoveryReviewReady({ ...pending, recoveryProofs: ["PASSKEY"], recoveryAdminReview: true }), true);
  assert.equal(recoveryReviewReady({ ...pending, recoveryProofs: ["EMAIL"], recoveryAdminReview: true }), false);
});
