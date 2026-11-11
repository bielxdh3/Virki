import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { prisma } from "@virki/database";
import { approveAccountRecovery, consumeApprovedAccountRecovery, hashEmailAddress, SecurityMutationError } from "./security";

const base = new Date("2026-11-09T14:00:00.000Z");
const ownerId = "recovery-owner-123";
const reviewerId = "recovery-reviewer-123";
const requestId = "recovery-request-123";
const requestKey = "R".repeat(32);
const email = "expiring-recovery@example.test";
const user = { email, emailNormalized: email, displayName: "Recovery owner", role: "USER", isActive: true, accountStatus: "ACTIVE" };
const digest = (value: string) => createHash("sha256").update(value).digest("hex");

test("approval refuses an expiry reached while waiting for its account lock", async (context) => {
  let expiredAfterLock = false;
  let casCalls = 0;
  let casSql = "";
  const request = {
    id: requestId, requestKeyHash: digest(requestKey), emailAddressHash: hashEmailAddress(email), userId: ownerId,
    status: "PENDING", recoveryProofs: [], recoveryRole: null, recoveryAdminReview: true, recoveryBrowserHash: null,
    emailVerifiedAt: base, expiresAt: new Date(base.getTime() + 60_000), user
  };
  const originalFindUser = Object.getOwnPropertyDescriptor(prisma.user, "findUnique");
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalFindUser && originalTransaction);
  Object.defineProperty(prisma.user, "findUnique", { ...originalFindUser, value: async () => ({ role: "ADMIN", isActive: true, accountStatus: "ACTIVE" }) });
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const statement = strings.join("");
      if (statement.includes('FROM "AdministrativeCredential"')) return [{ passwordHash: "hash", keyVersion: 1, status: "ACTIVE", revokedAt: null }];
      if (statement.includes('FROM "SecurityElevation"')) return [{ id: "elevation", credentialKeyVersion: 1 }];
      if (statement.includes('FROM "AccountRecoveryRequest"')) return [{ id: requestId }];
      if (statement.includes('FROM "User"') && values[0] === ownerId) expiredAfterLock = true;
      return [{ id: String(values[0] ?? reviewerId) }];
    },
    accountRecoveryRequest: {
      findUnique: async () => request,
      findFirst: async () => null, // No competing recovery in the expiry-only fixture.
    },
    $executeRaw: async (statement: { sql: string }) => { casCalls += 1; casSql = statement.sql; return 0; }
  };
  Object.defineProperty(prisma, "$transaction", { ...originalTransaction, value: async (run: (tx: never) => Promise<unknown>) => run(transaction as never) });
  context.after(() => {
    Object.defineProperty(prisma.user, "findUnique", originalFindUser);
    Object.defineProperty(prisma, "$transaction", originalTransaction);
  });

  const clock = () => new Date(base.getTime() + (expiredAfterLock ? 61_000 : 0));
  await assert.rejects(approveAccountRecovery({ id: reviewerId, role: "ADMIN" }, "session-123", requestId, clock), SecurityMutationError);
  assert.equal(expiredAfterLock, true);
  assert.equal(casCalls, 0, "an expired request must never reach its CAS update");

  // With a live clock, the DB itself makes the final expiry decision.
  const previousPortalUrl = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_URL = "https://portal.biel.dev.br";
  context.after(() => {
    if (previousPortalUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousPortalUrl;
  });
  request.expiresAt = new Date(Date.now() + 60_000);
  await assert.rejects(approveAccountRecovery({ id: reviewerId, role: "ADMIN" }, "session-123", requestId), SecurityMutationError);
  assert.equal(casCalls, 1);
  assert.match(casSql, /clock_timestamp\(\) AT TIME ZONE 'UTC'/u);
  assert.match(casSql, /recovery\."expiresAt" > recovery_time\."at"/u);
});

test("completion rechecks after Argon2/locks and makes production CAS conditional on DB clock", async (context) => {
  const now = new Date();
  let expireAfterLock = false;
  let forceExpiry = false;
  let casCalls = 0;
  let passwordUpdates = 0;
  let rawStatement = "";
  let reviewerAllowed = true;
  let ownerLocks = 0;
  const browserToken = "B".repeat(43);
  const request = {
    id: requestId, requestKeyHash: digest(requestKey), emailAddressHash: hashEmailAddress(email), userId: ownerId,
    status: "APPROVED", recoveryProofs: [] as string[], recoveryRole: null as string | null,
    recoveryAdminReview: true, recoveryBrowserHash: null as string | null,
    reviewedByUserId: null as string | null,
    emailVerifiedAt: now, recoveryPasskeyVerifiedAt: null, recoveryTotpVerifiedAt: null,
    expiresAt: new Date(now.getTime() + 60_000), user
  };
  const originalFindRequest = Object.getOwnPropertyDescriptor(prisma.accountRecoveryRequest, "findUnique");
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalFindRequest && originalTransaction);
  Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", { ...originalFindRequest, value: async () => request });
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray) => {
      const statement = strings.join("");
      if (statement.includes('FROM "User"')) {
        if (statement.includes("FOR SHARE")) return reviewerAllowed ? [{ id: reviewerId }] : [];
        ownerLocks += 1;
        if (forceExpiry) expireAfterLock = true;
        return [{ id: ownerId }];
      }
      if (statement.includes('FROM "AccountRecoveryRequest"')) return [{ id: requestId }];
      return [];
    },
    $executeRaw: async (statement: { sql: string }) => {
      casCalls += 1;
      rawStatement = statement.sql;
      return 0; // DB rejects a request that expired before the conditional write.
    },
    loginRateLimit: { findUnique: async () => null, create: async () => ({}) },
    accountRecoveryRequest: { findUnique: async () => request, updateMany: async () => ({ count: 0 }) },
    user: { update: async () => { passwordUpdates += 1; return { id: ownerId }; } }
  };
  Object.defineProperty(prisma, "$transaction", { ...originalTransaction, value: async (run: (tx: never) => Promise<unknown>) => run(transaction as never) });
  context.after(() => {
    Object.defineProperty(prisma.accountRecoveryRequest, "findUnique", originalFindRequest);
    Object.defineProperty(prisma, "$transaction", originalTransaction);
  });

  forceExpiry = true;
  const clock = () => new Date(now.getTime() + (expireAfterLock ? 61_000 : 0));
  await assert.rejects(consumeApprovedAccountRecovery(requestId, requestKey, "new-safe-password-123", clock), SecurityMutationError);
  assert.equal(expireAfterLock, true);
  assert.equal(casCalls, 0, "post-lock expiry must stop before the conditional write");

  forceExpiry = false;
  expireAfterLock = false;
  await assert.rejects(consumeApprovedAccountRecovery(requestId, requestKey, "new-safe-password-123"), SecurityMutationError);
  assert.equal(casCalls, 1);
  assert.match(rawStatement, /clock_timestamp\(\) AT TIME ZONE 'UTC'/u);
  assert.match(rawStatement, /recovery\."expiresAt" > recovery_time\."at"/u);
  assert.equal(passwordUpdates, 0, "failed CAS must not replace the password");

  // A reviewer removed before this transaction must fail before taking the owner lock.
  request.recoveryProofs = ["EMAIL"];
  request.recoveryRole = "USER";
  request.recoveryBrowserHash = digest("Virki recovery browser v1:" + browserToken);
  request.reviewedByUserId = reviewerId;
  reviewerAllowed = false;
  const previousOwnerLocks = ownerLocks;
  await assert.rejects(consumeApprovedAccountRecovery(requestId, requestKey, "new-safe-password-123", now, "USER", browserToken), SecurityMutationError);
  assert.equal(ownerLocks, previousOwnerLocks);
  assert.equal(casCalls, 1);
  assert.equal(passwordUpdates, 0);
});
