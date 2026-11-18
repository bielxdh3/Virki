import assert from "node:assert/strict";
import { test } from "node:test";
import { prisma, type Prisma } from "@virki/database";
import {
  hashEmailAddress, hashRecoveryRequestKey, hashSecurityCode,
  requestAccountRecovery, verifyAccountRecoveryEmail
} from "./security";

type Sibling = {
  id: string;
  status: "PENDING" | "APPROVED";
  purpose: "RECOVERY" | "INVITATION";
  emailVerifiedAt: Date | null;
  recoveryPasskeyVerifiedAt: Date | null;
  recoveryTotpVerifiedAt: Date | null;
  expiresAt: Date;
};

// Evaluate the Prisma where clauses, rather than returning a canned result
// for a particular query. An omitted proof check should actually miss the row.
function matchesSibling(where: Record<string, unknown>, sibling: Sibling): boolean {
  for (const [key, condition] of Object.entries(where)) {
    if (key === "OR") {
      if (!(condition as Record<string, unknown>[]).some(clause => matchesSibling(clause, sibling))) return false;
      continue;
    }
    if (key === "userId") continue;
    const value = sibling[key as keyof Sibling];
    if (condition && typeof condition === "object" && !Array.isArray(condition) && !(condition instanceof Date)) {
      const op = condition as { in?: string[]; gt?: Date; not?: unknown };
      if (op.in && !op.in.includes(String(value))) return false;
      if (op.gt && (!(value instanceof Date) || value <= op.gt)) return false;
      if (Object.hasOwn(op, "not") && value === op.not) return false;
    } else if (value !== condition) return false;
  }
  return true;
}

test("legacy start cannot displace a live strong proof or any approval; unproven recovery remains eligible", async t => {
  const now = new Date();
  const email = "legacy-crossflow@example.invalid";
  const owner = { id: "owner-crossflow-1", email, emailNormalized: email, displayName: "Owner", role: "USER", isActive: true, accountStatus: "ACTIVE" };
  const previousEnv = { nodeEnv: process.env.NODE_ENV, portalUrl: process.env.VIRKI_PORTAL_URL };
  const originalFind = Object.getOwnPropertyDescriptor(prisma.user, "findUnique");
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalFind && originalTransaction);
  process.env.NODE_ENV = "test";
  process.env.VIRKI_PORTAL_URL = "https://portal.biel.dev.br";
  let attemptedCreates = 0;
  let sibling: Sibling = {
    id: "rival", status: "PENDING", purpose: "RECOVERY", emailVerifiedAt: null,
    recoveryPasskeyVerifiedAt: null, recoveryTotpVerifiedAt: now,
    expiresAt: new Date(now.getTime() + 300_000)
  };
  const tx = {
    $queryRaw: async () => [{ id: owner.id }],
    loginRateLimit: { findUnique: async () => null, create: async () => ({}) },
    accountRecoveryRequest: {
      findFirst: async ({ where, orderBy }: { where: Record<string, unknown>; orderBy?: unknown }) =>
        orderBy ? { createdAt: new Date(now.getTime() - 61_000) } : (matchesSibling(where, sibling) ? { id: sibling.id } : null),
      create: async () => { attemptedCreates++; throw Error("unsafe legacy creation reached"); }
    }
  } as unknown as Prisma.TransactionClient;
  Object.defineProperty(prisma.user, "findUnique", { ...originalFind, value: async () => owner });
  Object.defineProperty(prisma, "$transaction", { ...originalTransaction, value: async (fn: (tx: Prisma.TransactionClient) => Promise<unknown>) => fn(tx) });
  t.after(() => {
    Object.defineProperty(prisma.user, "findUnique", originalFind);
    Object.defineProperty(prisma, "$transaction", originalTransaction);
    if (previousEnv.nodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousEnv.nodeEnv;
    if (previousEnv.portalUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousEnv.portalUrl;
  });
  await requestAccountRecovery(email, "pt-BR", now);
  sibling = { ...sibling, recoveryTotpVerifiedAt: null, recoveryPasskeyVerifiedAt: now };
  await requestAccountRecovery(email, "pt-BR", now);
  sibling = { ...sibling, status: "APPROVED", recoveryPasskeyVerifiedAt: null };
  await requestAccountRecovery(email, "pt-BR", now);
  sibling = { ...sibling, purpose: "INVITATION" };
  await requestAccountRecovery(email, "pt-BR", now);
  sibling = { ...sibling, status: "PENDING", purpose: "RECOVERY", emailVerifiedAt: now };
  await requestAccountRecovery(email, "pt-BR", now);
  assert.equal(attemptedCreates, 0, "protected requests must stop legacy creation inside the account lock");
  sibling = { ...sibling, emailVerifiedAt: null };
  await assert.rejects(requestAccountRecovery(email, "pt-BR", now), /Security mutation rejected|unsafe legacy creation/i);
  assert.equal(attemptedCreates, 1, "an unproven request does not monopolize legacy recovery");
});

test("legacy mailbox verification cannot expire a pending strong proof or approved invitation", async t => {
  const now = new Date();
  const email = "legacy-verify-crossflow@example.invalid";
  const owner = { id: "owner-crossflow-verify", email, emailNormalized: email, role: "USER", isActive: true, accountStatus: "ACTIVE" };
  const code = "123456";
  const key = "R".repeat(32);
  const requestId = "legacy-crossflow-verify";
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalTransaction);
  const oldNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  let expiredSiblingWrites = 0;
  let emailProofWrites = 0;
  let sibling: Sibling | null = {
    id: "strong", status: "PENDING", purpose: "RECOVERY",
    emailVerifiedAt: null, recoveryPasskeyVerifiedAt: null, recoveryTotpVerifiedAt: now,
    expiresAt: new Date(now.getTime() + 300_000)
  };
  const legacy = {
    id: requestId, userId: owner.id, requestKeyHash: hashRecoveryRequestKey(key),
    emailAddressHash: hashEmailAddress(email), emailChallengeHash: hashSecurityCode(code),
    status: "PENDING", emailVerifiedAt: null, expiresAt: new Date(now.getTime() + 300_000),
    recoveryProofs: [], recoveryBrowserHash: null, user: owner
  };
  const tx = {
    $queryRaw: async () => [{ id: owner.id }],
    loginRateLimit: { findUnique: async () => null, create: async () => ({}) },
    accountRecoveryRequest: {
      findUnique: async () => legacy,
      findFirst: async ({ where }: { where: Record<string, unknown> }) =>
        sibling && matchesSibling(where, sibling) ? { id: sibling.id } : null,
      updateMany: async ({ where }: { where: Record<string, unknown> }) => {
        if (where.id === requestId) { emailProofWrites++; return { count: 1 }; }
        if (where.userId === owner.id) { expiredSiblingWrites++; return { count: 1 }; }
        return { count: 0 };
      }
    },
    user: { update: async () => ({}) },
    auditLog: { create: async () => ({}) }
  } as unknown as Prisma.TransactionClient;
  Object.defineProperty(prisma, "$transaction", { ...originalTransaction, value: async (fn: (tx: Prisma.TransactionClient) => Promise<unknown>) => fn(tx) });
  t.after(() => {
    Object.defineProperty(prisma, "$transaction", originalTransaction);
    if (oldNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = oldNodeEnv;
  });
  await assert.rejects(verifyAccountRecoveryEmail(requestId, key, code, now));
  sibling = { ...sibling!, recoveryTotpVerifiedAt: null, recoveryPasskeyVerifiedAt: now };
  await assert.rejects(verifyAccountRecoveryEmail(requestId, key, code, now));
  sibling = { ...sibling, status: "APPROVED", purpose: "INVITATION", recoveryPasskeyVerifiedAt: null };
  await assert.rejects(verifyAccountRecoveryEmail(requestId, key, code, now));
  assert.equal(emailProofWrites, 0, "a weaker legacy email must not write proof while strong/approved sibling exists");
  assert.equal(expiredSiblingWrites, 0, "a weaker legacy email must not expire another recovered request");
  sibling = { ...sibling, purpose: "RECOVERY", status: "PENDING" };
  await verifyAccountRecoveryEmail(requestId, key, code, now);
  assert.equal(emailProofWrites, 1, "ordinary legacy email verification still works");
  assert.equal(expiredSiblingWrites, 1, "ordinary legacy sibling clean-up still executes");
});
