import assert from "node:assert/strict";
import test from "node:test";
import { prisma, type Prisma } from "@bielos/database";
import { authenticateUserWithRateLimit, hashPassword } from "./index";
import { createRateLimitIdentifierHash } from "./rate-limit-config";

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
  const sourceIdentifier = `login-source-failure:v2:${sourceAddress}`;
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
