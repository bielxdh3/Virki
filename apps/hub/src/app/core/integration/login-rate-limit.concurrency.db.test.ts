import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";

import {
  authenticateUserWithRateLimit,
  checkLoginRateLimit,
  hashPassword,
  recordFailedLogin
} from "@bielos/auth";
import { prisma } from "@bielos/database";

import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

const identifier = "rate-limit-member@example.invalid";

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
});

after(async () => {
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("simultaneous failed logins retain every attempt up to the limit", async () => {
  const now = new Date("2026-07-14T12:00:00.000Z");

  await Promise.all(
    Array.from({ length: 12 }, () => recordFailedLogin(identifier, now))
  );

  const rows = await prisma.loginRateLimit.findMany({
    select: {
      identifierHash: true,
      attempts: true,
      blockedUntil: true
    }
  });

  assert.equal(rows.length, 1);
  assert.match(rows[0]?.identifierHash ?? "", /^[a-f0-9]{64}$/);
  assert.equal(rows[0]?.attempts, 5);
  assert.equal(rows[0]?.blockedUntil?.toISOString(), "2026-07-14T12:15:00.000Z");
  assert.deepEqual(await checkLoginRateLimit(identifier, now), {
    allowed: false,
    retryAfterSeconds: 900
  });
});

test("same-identifier authentication is serialized at the failure limit", async () => {
  const now = new Date("2026-07-14T12:00:00.000Z");
  const results = await Promise.all(
    Array.from({ length: 12 }, () =>
      authenticateUserWithRateLimit(identifier, "invalid-password", now)
    )
  );

  assert.equal(
    results.filter((result) => result.failureMode === "invalid-credentials").length,
    5
  );
  assert.equal(
    results.filter((result) => result.failureMode === "rate-limited").length,
    7
  );
  assert.equal(results.every((result) => result.user === null), true);
  assert.equal(
    (await prisma.loginRateLimit.findFirst({ select: { attempts: true } }))?.attempts,
    5
  );
});

test("successful authentication clears the normalized identifier bucket", async () => {
  const syntheticCredential = "replace-with-test-secret";
  const user = await prisma.user.create({
    data: {
      email: "rate-limit-success@example.invalid",
      passwordHash: await hashPassword(syntheticCredential),
      role: "MEMBER",
      isActive: true
    },
    select: { id: true }
  });

  const failed = await authenticateUserWithRateLimit(
    " RATE-LIMIT-SUCCESS@EXAMPLE.INVALID ",
    "synthetic-wrong-password"
  );
  assert.equal(failed.failureMode, "invalid-credentials");
  assert.equal(await prisma.loginRateLimit.count(), 1);

  const authenticated = await authenticateUserWithRateLimit(
    " RATE-LIMIT-SUCCESS@EXAMPLE.INVALID ",
    syntheticCredential
  );
  assert.equal(authenticated.user?.id, user.id);
  assert.equal(await prisma.loginRateLimit.count(), 0);
});
