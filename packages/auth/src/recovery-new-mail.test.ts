import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { prisma, type Prisma } from "@virki/database";
import { decryptEmailPayload } from "./email";
import {
  getMultiMethodRecoveryState, needsRecoveryNewMailbox, recoveryPasskeyBinding,
  recoveryTotpBinding, startRecoveryNewMailbox, verifyRecoveryNewMailbox
} from "./recovery-methods";
import { consumeApprovedAccountRecovery, hashEmailAddress, hashRecoveryRequestKey } from "./security";

const requestId = "R".repeat(43);
const requestKey = "K".repeat(32);
const browserToken = "B".repeat(43);
const otherBrowser = "O".repeat(43);
const originalEmail = "recovery-owner@example.invalid";
const replacement = "new-owner@example.invalid";
const approvedAt = new Date("2026-11-09T16:00:00Z");
const browserHash = createHash("sha256").update("Virki recovery browser v1:").update(browserToken).digest("hex");

test("EMAIL-inclusive proofs do not require replacement; independent proofs always do", () => {
  assert.equal(needsRecoveryNewMailbox(["PASSKEY", "TOTP"]), true);
  assert.equal(needsRecoveryNewMailbox(["PASSKEY"]), true);
  assert.equal(needsRecoveryNewMailbox(["TOTP"]), true);
  assert.equal(needsRecoveryNewMailbox(["PASSKEY", "EMAIL"]), false);
  assert.equal(needsRecoveryNewMailbox(["TOTP", "EMAIL"]), false);
  assert.equal(needsRecoveryNewMailbox(["EMAIL"]), false);
  assert.equal(needsRecoveryNewMailbox([]), false);
});

test("unverified replacement blocks password consumption before any MFA or session mutation", async (context) => {
  const descriptor = Object.getOwnPropertyDescriptor(prisma.accountRecoveryRequest, "findUnique");
  const transaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(descriptor && transaction);
  const oldPasskeys = process.env.VIRKI_PASSKEYS_ENABLED;
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  const row = {
    id: requestId, requestKeyHash: hashRecoveryRequestKey(requestKey), userId: "target-user",
    emailAddressHash: hashEmailAddress(originalEmail), status: "APPROVED",
    recoveryProofs: ["PASSKEY", "TOTP"], recoveryRole: "USER", recoveryAdminReview: false,
    recoveryBrowserHash: browserHash, emailVerifiedAt: null,
    recoveryPasskeyVerifiedAt: approvedAt, recoveryTotpVerifiedAt: approvedAt,
    recoveryNewEmail: null as string | null, recoveryNewEmailVerifiedAt: null as Date | null,
    reviewedByUserId: null, expiresAt: new Date(Date.now() + 20 * 60_000),
    user: { email: originalEmail, emailNormalized: originalEmail, role: "USER", isActive: true, accountStatus: "ACTIVE" }
  };
  let transactions = 0;
  Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", { ...descriptor, value: async () => row });
  Object.defineProperty(prisma, "$transaction", { ...transaction, value: async () => { transactions++; throw new Error("unexpected mutation"); } });
  context.after(() => {
    Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", descriptor);
    Object.defineProperty(prisma, "$transaction", transaction);
    if (oldPasskeys === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED;
    else process.env.VIRKI_PASSKEYS_ENABLED = oldPasskeys;
  });
  await assert.rejects(consumeApprovedAccountRecovery(requestId, requestKey, "valid-new-password", undefined, "USER", browserToken), /Security mutation rejected/u);
  assert.equal(transactions, 0, "no rate-limit, User, session or factor mutation on an unverified inbox");
  row.recoveryNewEmail = replacement;
  await assert.rejects(consumeApprovedAccountRecovery(requestId, requestKey, "valid-new-password", undefined, "USER", browserToken), /Security mutation rejected/u);
  assert.equal(transactions, 0, "a proposed address without verified OTP cannot consume the recovery");
  row.recoveryNewEmailVerifiedAt = new Date();
  await assert.rejects(consumeApprovedAccountRecovery(requestId, requestKey, "valid-new-password", undefined, "USER", browserToken), /unexpected mutation/u);
  assert.equal(transactions, 1, "after proof the code reaches the transaction, which independently rechecks it");
});

test("new inbox OTP belongs to the current browser/request; reissue invalidates prior code and only one verification wins", async (context) => {
  const transactionDescriptor = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  const findDescriptor = Object.getOwnPropertyDescriptor(prisma.accountRecoveryRequest, "findUnique");
  assert.ok(transactionDescriptor && findDescriptor);
  const oldNodeEnv = process.env.NODE_ENV;
  const oldPasskeys = process.env.VIRKI_PASSKEYS_ENABLED;
  process.env.NODE_ENV = "test";
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  const factor = { id: "factor-1", secretCiphertext: "encrypted", keyVersion: 1, confirmedAt: approvedAt, lastUsedStep: 42, status: "ACTIVE" };
  const credential = { id: "passkey-1", credentialId: "credential-1", userId: "target-user", publicKey: Buffer.from("public-key"), revokedAt: null };
  const row = {
    id: requestId, userId: "target-user", requestKeyHash: hashRecoveryRequestKey(requestKey),
    emailAddressHash: hashEmailAddress(originalEmail), purpose: "RECOVERY",
    recoveryBrowserHash: browserHash, recoveryRole: "USER", recoveryProofs: ["PASSKEY", "TOTP"],
    recoveryAdminReview: false, status: "APPROVED",
    emailVerifiedAt: null, recoveryPasskeyVerifiedAt: approvedAt, recoveryTotpVerifiedAt: approvedAt,
    recoveryPasskeyCredentialId: credential.id, recoveryPasskeyBindingHash: recoveryPasskeyBinding(credential),
    recoveryTotpBindingHash: recoveryTotpBinding(factor), recoveryTotpUsedStep: 42,
    recoveryNewEmail: null as string | null, recoveryNewEmailChallengeHash: null as string | null,
    recoveryNewEmailExpiresAt: null as Date | null, recoveryNewEmailVerifiedAt: null as Date | null,
    reviewedByUserId: null, expiresAt: new Date(Date.now() + 25 * 60_000),
    user: { id: "target-user", email: originalEmail, emailNormalized: originalEmail,
      role: "USER", isActive: true, accountStatus: "ACTIVE" }
  };
  const sent: Array<{ recipientEmail: string; payload: unknown }> = [];
  let locked = 0;
  let verifiedClaims = 0;
  let mutatedLogin = 0;
  let occupied = false;
  const tx = {
    $queryRaw: async (parts: TemplateStringsArray) => {
      const query = parts.join("");
      if (query.includes('FROM "User"') || query.includes('FROM "AccountRecoveryRequest"')) locked++;
      return [{ id: "target-user" }];
    },
    $executeRaw: async (parts: TemplateStringsArray) => {
      const query = parts.join("");
      if (!query.includes('"recoveryNewEmailVerifiedAt" = verification_time."at"') ||
          !query.includes("clock_timestamp() AT TIME ZONE 'UTC'") ||
          !query.includes('"recoveryNewEmailExpiresAt" > verification_time."at"')) throw new Error("missing at-use UTC OTP deadline");
      if (row.recoveryNewEmailVerifiedAt || row.recoveryNewEmailExpiresAt! <= new Date()) return 0;
      row.recoveryNewEmailVerifiedAt = new Date();
      verifiedClaims++;
      return 1;
    },
    accountRecoveryRequest: {
      findUnique: async () => row,
      updateMany: async ({ data }: { data: Record<string, unknown> }) => {
        Object.assign(row, data);
        return { count: 1 };
      }
    },
    user: {
      count: async () => occupied ? 1 : 0,
      findUnique: async () => ({ secondFactorMethod: "TOTP" }),
      update: async () => { mutatedLogin++; throw new Error("pre-reset User mutation"); }
    },
    totpFactor: { findUnique: async () => factor },
    passkeyCredential: { findFirst: async () => credential },
    loginRateLimit: { findUnique: async () => null, create: async () => ({}) },
    auditLog: { create: async () => ({}) },
    emailOutboxMessage: { upsert: async ({ create }: { create: { recipientEmail: string; payload: unknown } }) => {
      sent.push({ recipientEmail: create.recipientEmail, payload: create.payload }); return {};
    } }
  } as unknown as Prisma.TransactionClient;
  Object.defineProperty(prisma, "$transaction", { ...transactionDescriptor,
    value: async (callback: (client: Prisma.TransactionClient) => Promise<unknown>) => callback(tx) });
  Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", { ...findDescriptor, value: async () => row });
  context.after(() => {
    Object.defineProperty(prisma, "$transaction", transactionDescriptor);
    Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", findDescriptor);
    if (oldNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = oldNodeEnv;
    if (oldPasskeys === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED;
    else process.env.VIRKI_PASSKEYS_ENABLED = oldPasskeys;
  });

  const policy = { proofs: ["PASSKEY", "TOTP"] as ["PASSKEY", "TOTP"], adminReview: false };
  const state = await getMultiMethodRecoveryState(requestId, requestKey, browserToken, "USER", policy);
  assert.equal(state.status, "APPROVED");
  assert.equal(state.newMailboxRequired, true);
  assert.equal(state.newMailboxVerified, false);
  assert.equal(state.newMailboxChallengeSent, false);

  await assert.rejects(startRecoveryNewMailbox(requestId, requestKey, otherBrowser, "USER", replacement));
  assert.equal(sent.length, 0);
  occupied = true;
  await assert.rejects(startRecoveryNewMailbox(requestId, requestKey, browserToken, "USER", replacement));
  assert.equal(sent.length, 0, "occupied mailbox cannot receive a recovery OTP");
  occupied = false;
  await startRecoveryNewMailbox(requestId, requestKey, browserToken, "USER", replacement);
  assert.equal(sent.length, 1);
  assert.equal(sent[0]?.recipientEmail, replacement);
  const first = decryptEmailPayload(sent[0]!.payload);
  assert.match(first.code, /^\d{6}$/u);
  assert.doesNotMatch(JSON.stringify(sent[0]?.payload), new RegExp(first.code), "SMTP OTP is encrypted at rest");
  assert.equal((await getMultiMethodRecoveryState(requestId, requestKey, browserToken, "USER", policy)).newMailboxChallengeSent, true);
  await startRecoveryNewMailbox(requestId, requestKey, browserToken, "USER", "later@example.invalid");
  const second = decryptEmailPayload(sent[1]!.payload);
  await assert.rejects(verifyRecoveryNewMailbox(requestId, requestKey, browserToken, "USER", first.code));
  await assert.rejects(verifyRecoveryNewMailbox(requestId, requestKey, otherBrowser, "USER", second.code));
  const results = await Promise.allSettled([
    verifyRecoveryNewMailbox(requestId, requestKey, browserToken, "USER", second.code),
    verifyRecoveryNewMailbox(requestId, requestKey, browserToken, "USER", second.code)
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.equal(verifiedClaims, 1, "verification is one-time");
  assert.equal(mutatedLogin, 0, "starting, reissuing and verifying do not change credentials or MFA");
  assert.equal(factor.status, "ACTIVE");
  assert.equal(credential.revokedAt, null);
  assert.ok(locked > 0);
  const verified = await getMultiMethodRecoveryState(requestId, requestKey, browserToken, "USER", policy);
  assert.equal(verified.newMailboxVerified, true);
  assert.equal(verified.newMailboxRequired, true);
});
