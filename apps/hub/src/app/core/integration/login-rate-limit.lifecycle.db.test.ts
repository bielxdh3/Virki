import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";

import {
  authenticateUserWithRateLimit,
  checkLoginRateLimit,
  cleanupExpiredLoginRateLimits,
  hashPassword,
  recordFailedLogin
} from "@bielos/auth";
import { prisma } from "@bielos/database";

import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

const syntheticCredential = "replace-with-test-secret";
const originalRateLimitSecret = process.env.BIELOS_RATE_LIMIT_HASH_SECRET;

before(() => {
  process.env.BIELOS_RATE_LIMIT_HASH_SECRET = syntheticCredential;
});

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
});

after(async () => {
  restoreEnvironmentVariable("BIELOS_RATE_LIMIT_HASH_SECRET", originalRateLimitSecret);
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("separate identifiers retain independent buckets", async () => {
  const now = new Date("2026-07-14T12:00:00.000Z");
  const identifiers = ["member-a@example.invalid", "member-b@example.invalid"];

  await Promise.all(
    identifiers.flatMap((identifier) =>
      Array.from({ length: 6 }, () =>
        authenticateUserWithRateLimit(identifier, "synthetic-invalid-credential", now)
      )
    )
  );

  const buckets = await prisma.loginRateLimit.findMany({
    select: { identifierHash: true, attempts: true }
  });

  assert.equal(buckets.length, 2);
  assert.equal(new Set(buckets.map((bucket) => bucket.identifierHash)).size, 2);
  assert.equal(buckets.every((bucket) => bucket.attempts === 5), true);
});

test("the exact window boundary resets the next failed attempt to one", async () => {
  const identifier = "window-boundary@example.invalid";
  const startedAt = new Date("2026-07-14T12:00:00.000Z");
  const justBeforeReset = new Date("2026-07-14T12:14:59.999Z");
  const exactReset = new Date("2026-07-14T12:15:00.000Z");

  for (let attempt = 0; attempt < 5; attempt += 1) {
    await recordFailedLogin(identifier, startedAt);
  }

  assert.deepEqual(await checkLoginRateLimit(identifier, justBeforeReset), {
    allowed: false,
    retryAfterSeconds: 1
  });
  assert.deepEqual(await checkLoginRateLimit(identifier, exactReset), { allowed: true });

  await recordFailedLogin(identifier, exactReset);
  const bucket = await prisma.loginRateLimit.findFirst({
    select: { attempts: true, windowStartedAt: true, blockedUntil: true }
  });

  assert.equal(bucket?.attempts, 1);
  assert.equal(bucket?.windowStartedAt.toISOString(), exactReset.toISOString());
  assert.equal(bucket?.blockedUntil, null);
});

test("retention cleanup removes only expired rows without console output", async () => {
  const now = new Date("2026-07-15T12:00:00.000Z");
  await prisma.loginRateLimit.createMany({
    data: [
      {
        identifierHash: "a".repeat(64),
        attempts: 1,
        windowStartedAt: new Date("2026-07-14T11:00:00.000Z"),
        expiresAt: now
      },
      {
        identifierHash: "b".repeat(64),
        attempts: 1,
        windowStartedAt: new Date("2026-07-15T11:00:00.000Z"),
        expiresAt: new Date("2026-07-16T12:00:00.000Z")
      }
    ]
  });
  const printed: unknown[][] = [];
  const originalLog = console.log;
  const originalWarn = console.warn;

  try {
    console.log = (...values: unknown[]) => {
      printed.push(values);
    };
    console.warn = (...values: unknown[]) => {
      printed.push(values);
    };

    assert.equal(await cleanupExpiredLoginRateLimits(now), 1);
  } finally {
    console.log = originalLog;
    console.warn = originalWarn;
  }

  assert.equal(printed.length, 0);
  assert.deepEqual(
    await prisma.loginRateLimit.findMany({ select: { identifierHash: true } }),
    [{ identifierHash: "b".repeat(64) }]
  );
});

test("successful login after an expired window clears stale bucket state", async () => {
  const email = "expired-window-success@example.invalid";
  const now = new Date("2026-07-14T12:30:00.000Z");
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash: await hashPassword(syntheticCredential),
      role: "MEMBER",
      isActive: true
    },
    select: { id: true }
  });

  for (let attempt = 0; attempt < 5; attempt += 1) {
    await recordFailedLogin(email, new Date("2026-07-14T12:00:00.000Z"));
  }

  const result = await authenticateUserWithRateLimit(email, syntheticCredential, now);

  assert.equal(result.user?.id, user.id);
  assert.equal(await prisma.loginRateLimit.count(), 0);
});

test("inactive, passwordless, and unknown users remain generic and increment separate buckets", async () => {
  await prisma.user.createMany({
    data: [
      {
        email: "inactive@example.invalid",
        passwordHash: await hashPassword(syntheticCredential),
        role: "MEMBER",
        isActive: false
      },
      {
        email: "passwordless@example.invalid",
        passwordHash: null,
        role: "MEMBER",
        isActive: true
      }
    ]
  });

  const results = await Promise.all([
    authenticateUserWithRateLimit("inactive@example.invalid", syntheticCredential),
    authenticateUserWithRateLimit("passwordless@example.invalid", syntheticCredential),
    authenticateUserWithRateLimit("unknown@example.invalid", syntheticCredential)
  ]);
  const buckets = await prisma.loginRateLimit.findMany({
    select: { attempts: true, identifierHash: true }
  });

  assert.equal(
    results.every(
      (result) => result.user === null && result.failureMode === "invalid-credentials"
    ),
    true
  );
  assert.equal(buckets.length, 3);
  assert.equal(buckets.every((bucket) => bucket.attempts === 1), true);
  assert.equal(buckets.every((bucket) => /^[a-f0-9]{64}$/.test(bucket.identifierHash)), true);
  assert.equal(await prisma.session.count(), 0);
});

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}
