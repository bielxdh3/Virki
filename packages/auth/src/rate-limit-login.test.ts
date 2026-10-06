import assert from "node:assert/strict";
import test from "node:test";
import { prisma, type Prisma } from "@bielos/database";
import { authenticateUserWithRateLimit, hashPassword } from "./index";
import { createLoginAccountRateLimitIdentifierHash, createRateLimitIdentifierHash, scopeLoginRateLimitEmail } from "./rate-limit-config";

type RateLimitRow = {
  identifierHash: string;
  attempts: number;
  windowStartedAt: Date;
  blockedUntil: Date | null;
  expiresAt: Date;
};

test("successful logins release their source reservations without clearing failed attempts", async () => {
  const now = new Date("2026-10-03T05:00:00.000Z");
  const sourceAddress = "203.0.113.20";
  const sourceIdentifier = `login-source-failure:v3:unscoped:${sourceAddress}`;
  const sourceHash = createRateLimitIdentifierHash(sourceIdentifier);
  const rows = new Map<string, RateLimitRow>([[sourceHash, {
    identifierHash: sourceHash,
    attempts: 29,
    windowStartedAt: now,
    blockedUntil: null,
    expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000)
  }]]);
  const user = {
    id: "user-a",
    email: "member@example.invalid",
    displayName: "Member",
    passwordHash: await hashPassword("valid-login-test-password"),
    role: "USER",
    isActive: true,
    accountStatus: "ACTIVE"
  };
  const transaction = {
    $queryRaw: async () => [],
    loginRateLimit: {
      findUnique: async ({ where }: { where: { identifierHash: string } }) => rows.get(where.identifierHash) ?? null,
      create: async ({ data }: { data: RateLimitRow }) => { rows.set(data.identifierHash, data); },
      update: async ({ where, data }: { where: { identifierHash: string }; data: Partial<RateLimitRow> }) => {
        const existing = rows.get(where.identifierHash);
        if (!existing) throw new Error("Expected rate-limit row.");
        rows.set(where.identifierHash, { ...existing, ...data });
      },
      deleteMany: async ({ where }: { where: { identifierHash: { in: string[] } } }) => {
        let count = 0;
        for (const identifierHash of where.identifierHash.in) {
          if (rows.delete(identifierHash)) count += 1;
        }
        return { count };
      }
    },
    user: { findUnique: async () => user }
  } as unknown as Prisma.TransactionClient;
  const testPrisma = prisma as unknown as {
    $transaction: (callback: (client: Prisma.TransactionClient) => Promise<unknown>) => Promise<unknown>;
    loginRateLimit: { deleteMany: (args: unknown) => Promise<{ count: number }> };
  };
  const originalTransaction = prisma.$transaction;
  const originalRateLimitDelegate = prisma.loginRateLimit;
  let transactionCount = 0;
  testPrisma.$transaction = async (callback) => {
    transactionCount += 1;
    const result = await callback(transaction);
    if (transactionCount === 4) throw new Error("Simulated lost commit acknowledgment.");
    return result;
  };
  testPrisma.loginRateLimit = { deleteMany: async () => ({ count: 0 }) };

  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const result = await authenticateUserWithRateLimit(user.email, "valid-login-test-password", now, sourceAddress);
      if (attempt === 0) {
        assert.equal(result.user?.id, user.id);
      } else {
        assert.deepEqual(result, { user: null, failureMode: "limiter-unavailable" });
      }
      assert.deepEqual(rows.get(sourceHash), {
        identifierHash: sourceHash,
        attempts: 29,
        windowStartedAt: now,
        blockedUntil: null,
        expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000)
      });
    }
  } finally {
    testPrisma.$transaction = originalTransaction as unknown as typeof testPrisma.$transaction;
    testPrisma.loginRateLimit = originalRateLimitDelegate as unknown as typeof testPrisma.loginRateLimit;
  }
});

test("a surface-scoped login treats other roles as missing accounts and keeps separate counters", async () => {
  const now = new Date("2026-10-03T05:00:00.000Z");
  const sourceAddress = "203.0.113.27";
  const rows = new Map<string, RateLimitRow>();
  const admin = {
    id: "admin-a",
    email: "owner@example.invalid",
    displayName: "Owner",
    passwordHash: await hashPassword("correct-admin-password"),
    role: "ADMIN",
    isActive: true,
    accountStatus: "ACTIVE"
  };
  const transaction = {
    $queryRaw: async () => [],
    loginRateLimit: {
      findUnique: async ({ where }: { where: { identifierHash: string } }) => rows.get(where.identifierHash) ?? null,
      create: async ({ data }: { data: RateLimitRow }) => { rows.set(data.identifierHash, data); },
      update: async ({ where, data }: { where: { identifierHash: string }; data: Partial<RateLimitRow> }) => {
        const existing = rows.get(where.identifierHash);
        if (!existing) throw new Error("Expected rate-limit row.");
        rows.set(where.identifierHash, { ...existing, ...data });
      },
      deleteMany: async ({ where }: { where: { identifierHash: { in: string[] } } }) => {
        let count = 0;
        for (const identifierHash of where.identifierHash.in) if (rows.delete(identifierHash)) count += 1;
        return { count };
      }
    },
    user: { findUnique: async () => admin }
  } as unknown as Prisma.TransactionClient;
  const testPrisma = prisma as unknown as {
    $transaction: (callback: (client: Prisma.TransactionClient) => Promise<unknown>) => Promise<unknown>;
    loginRateLimit: { deleteMany: (args: unknown) => Promise<{ count: number }> };
  };
  const originalTransaction = prisma.$transaction;
  const originalRateLimitDelegate = prisma.loginRateLimit;
  testPrisma.$transaction = async (callback) => callback(transaction);
  testPrisma.loginRateLimit = { deleteMany: async () => ({ count: 0 }) };

  try {
    const portal = await authenticateUserWithRateLimit(admin.email, "correct-admin-password", now, sourceAddress, "USER");
    assert.deepEqual(portal, { user: null, failureMode: "invalid-credentials" }, "the correct ADMIN password is rejected on the portal");

    const portalAccountHash = createLoginAccountRateLimitIdentifierHash(scopeLoginRateLimitEmail(admin.email, "USER"));
    const hubAccountHash = createLoginAccountRateLimitIdentifierHash(scopeLoginRateLimitEmail(admin.email, "ADMIN"));
    assert.notEqual(portalAccountHash, hubAccountHash);
    assert.equal(rows.get(portalAccountHash)?.attempts, 1, "the portal failure is counted on the portal scope");
    assert.equal(rows.has(hubAccountHash), false, "portal failures never touch the hub counter");
    const portalSourceHash = createRateLimitIdentifierHash(`login-source-failure:v3:USER:${sourceAddress}`);
    const hubSourceHash = createRateLimitIdentifierHash(`login-source-failure:v3:ADMIN:${sourceAddress}`);
    assert.equal(rows.get(portalSourceHash)?.attempts, 1, "portal failures use the portal source bucket");
    assert.equal(rows.has(hubSourceHash), false, "portal failures never touch the hub source bucket");

    const hub = await authenticateUserWithRateLimit(admin.email, "correct-admin-password", now, sourceAddress, "ADMIN");
    assert.equal(hub.user?.id, admin.id);
    assert.equal(rows.get(portalAccountHash)?.attempts, 1, "a hub success does not reset portal counters");
    assert.equal(rows.get(portalSourceHash)?.attempts, 1, "a hub success does not reset portal source counters");
  } finally {
    testPrisma.$transaction = originalTransaction as unknown as typeof testPrisma.$transaction;
    testPrisma.loginRateLimit = originalRateLimitDelegate as unknown as typeof testPrisma.loginRateLimit;
  }
});
