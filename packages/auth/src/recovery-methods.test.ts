import assert from "node:assert/strict";
import { test } from "node:test";
import { prisma } from "@virki/database";
import type { Prisma } from "@virki/database";
import { finishRecoveryPasskeyAssertion, generateRecoveryPublicRequestId, getMultiMethodRecoveryState, normalizeRecoveryPolicy, isRecoveryProofSatisfied, sanitizeRecoveryComment, recoveryPasskeyBinding, recoveryTotpBinding, requireLiveRecoveryProofsInTransaction, recoveryReviewReady, startMultiMethodRecovery, startRecoveryPasskeyAssertion } from "./recovery-methods";
import { consumeApprovedAccountRecovery } from "./security";

test("public recovery request IDs use a cryptographic, database-compatible format", () => {
  const samples = Array.from({ length: 128 }, () => generateRecoveryPublicRequestId());
  assert.equal(new Set(samples).size, samples.length);
  for (const id of samples) {
    // Same pattern accepted by security.ts:isDatabaseId when consuming the request.
    assert.match(id, /^[A-Za-z0-9_-]{43}$/u);
    assert.match(id, /^[A-Za-z0-9_-]{8,64}$/u);
  }
});

test("existing and nonexistent recovery IDs have identical public formats and unproven GET state", async (context) => {
  const knownEmail = "known-recovery-id@integration.invalid";
  const user = { id: "recovery-public-id-user", email: knownEmail, emailNormalized: knownEmail, displayName: "Test", role: "USER", isActive: true, accountStatus: "ACTIVE" };
  const policy = { proofs: ["PASSKEY", "TOTP"] as ("PASSKEY" | "TOTP")[], adminReview: false };
  const now = new Date();
  const captured: Array<Record<string, unknown>> = [];
  let saved: Record<string, unknown> | null = null;
  const transaction = {
    $queryRaw: async (literals: TemplateStringsArray) => literals.join("").includes('FROM "User"') ? [{ id: user.id }] : [],
    passkeyCredential: { count: async () => 1 },
    loginRateLimit: { findUnique: async () => null, create: async () => ({}) },
    accountRecoveryRequest: {
      findFirst: async () => null,
      create: async ({ data }: { data: Record<string, unknown> }) => {
        captured.push(data);
        saved = {
          ...data, status: "PENDING", reviewedByUserId: null, emailVerifiedAt: null,
          recoveryTotpVerifiedAt: null, recoveryPasskeyVerifiedAt: null, user
        };
        return { id: data.id };
      }
    },
    auditLog: { create: async () => ({}) }
  } as unknown as Prisma.TransactionClient;
  const userFind = Object.getOwnPropertyDescriptor(prisma.user, "findUnique");
  const requestFind = Object.getOwnPropertyDescriptor(prisma.accountRecoveryRequest, "findUnique");
  const runTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(userFind && requestFind && runTransaction);
  const oldNodeEnv = process.env.NODE_ENV;
  const oldPasskeyFlag = process.env.VIRKI_PASSKEYS_ENABLED;
  process.env.NODE_ENV = "test";
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  Object.defineProperty(prisma.user, "findUnique", {
    ...userFind, value: async ({ where }: { where: { emailNormalized: string } }) => where.emailNormalized === knownEmail ? user : null
  });
  Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", {
    ...requestFind, value: async ({ where }: { where: { id: string } }) => saved && saved.id === where.id ? saved : null
  });
  Object.defineProperty(prisma, "$transaction", {
    ...runTransaction, value: async (operation: (tx: Prisma.TransactionClient) => Promise<unknown>) => operation(transaction)
  });
  context.after(() => {
    Object.defineProperty(prisma, "$transaction", runTransaction);
    Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", requestFind);
    Object.defineProperty(prisma.user, "findUnique", userFind);
    if (oldNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = oldNodeEnv;
    if (oldPasskeyFlag === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED;
    else process.env.VIRKI_PASSKEYS_ENABLED = oldPasskeyFlag;
  });
  const real = await startMultiMethodRecovery(knownEmail, "USER", policy, "pt-BR", now);
  const fake = await startMultiMethodRecovery("absent-recovery-id@integration.invalid", "USER", policy, "pt-BR", now);
  assert.equal(captured.length, 1);
  assert.equal(captured[0]?.id, real.requestId, "real row MUST persist the public random ID, bypassing Prisma's CUID default");
  assert.match(real.requestId, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(fake.requestId, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(real.requestId.length, fake.requestId.length);
  assert.notEqual(real.requestId, fake.requestId);
  assert.deepEqual(
    await getMultiMethodRecoveryState(real.requestId, real.requestKey, real.browserToken, "USER", policy, now),
    await getMultiMethodRecoveryState(fake.requestId, fake.requestKey, fake.browserToken, "USER", policy, now)
  );
  process.env.VIRKI_PASSKEYS_ENABLED = "false";
  const disabled = await startMultiMethodRecovery(knownEmail, "USER", policy, "pt-BR", now);
  assert.equal(captured.length, 1, "forged disabled PASSKEY method must not persist a request");
  assert.match(disabled.requestId, /^[A-Za-z0-9_-]{43}$/u);
  assert.deepEqual(
    await getMultiMethodRecoveryState(real.requestId, real.requestKey, real.browserToken, "USER", policy, now),
    await getMultiMethodRecoveryState(disabled.requestId, disabled.requestKey, disabled.browserToken, "USER", policy, now)
  );
  await assert.rejects(startRecoveryPasskeyAssertion(real.requestId, real.requestKey, real.browserToken, "USER"));
  await assert.rejects(finishRecoveryPasskeyAssertion(real.requestId, real.requestKey, real.browserToken, {} as never, "USER"));
  saved = { ...saved!, status: "APPROVED", recoveryPasskeyVerifiedAt: now, recoveryTotpVerifiedAt: now };
  await assert.rejects(consumeApprovedAccountRecovery(real.requestId, real.requestKey, "valid-new-recovery-password", now, "USER", real.browserToken),
    /Security mutation rejected/u, "a flag revoked after proof must prevent password reset");
});

test("explicit recovery methods require two independent factors or one plus different admin", () => {
  assert.deepEqual(normalizeRecoveryPolicy({ proofs: ["PASSKEY", "TOTP"], adminReview: false }), { proofs: ["PASSKEY", "TOTP"], adminReview: false });
  assert.deepEqual(normalizeRecoveryPolicy({ proofs: ["TOTP", "EMAIL"], adminReview: false }), { proofs: ["EMAIL", "TOTP"], adminReview: false });
  assert.deepEqual(normalizeRecoveryPolicy({ proofs: ["PASSKEY", "EMAIL"], adminReview: false }), { proofs: ["EMAIL", "PASSKEY"], adminReview: false });
  assert.equal(normalizeRecoveryPolicy({ proofs: ["PASSKEY", "EMAIL", "TOTP"], adminReview: false }), null, "an undocumented three-factor combination must not be accepted through the backend");
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
  assert.equal(sanitizeRecoveryComment("🙂".repeat(300)), "🙂".repeat(300), "300 emoji are 300 Unicode characters");
  assert.throws(() => sanitizeRecoveryComment("🙂".repeat(301)), "301 emoji exceed the character limit");
  assert.throws(() => sanitizeRecoveryComment("texto\r\nperigoso"));
});

test("recovery passkey proof stays bound to exact credential and signing key, independent of changing counter", () => {
  const credential = { id: "credential-1", userId: "user-1", credentialId: "webauthn-id", publicKey: Buffer.from("public-key-v1") };
  const initial = recoveryPasskeyBinding(credential);
  assert.equal(initial, recoveryPasskeyBinding({ ...credential, publicKey: Buffer.from("public-key-v1") }));
  assert.notEqual(initial, recoveryPasskeyBinding({ ...credential, publicKey: Buffer.from("different-key") }));
  assert.notEqual(initial, recoveryPasskeyBinding({ ...credential, rpID: "hub.biel.dev.br" }));
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
