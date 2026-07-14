import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";

import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { recordFailedLogin } from "@bielos/auth";
import { prisma } from "@bielos/database";

import { POST } from "../../api/login/route";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

const lockedIdentifier = "locked-rate-limit@example.invalid";
const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
const originalRateLimitSecret = process.env.BIELOS_RATE_LIMIT_HASH_SECRET;

before(() => {
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
  process.env.BIELOS_RATE_LIMIT_HASH_SECRET = "replace-with-test-secret";
});

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
});

after(async () => {
  restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
  restoreEnvironmentVariable("BIELOS_RATE_LIMIT_HASH_SECRET", originalRateLimitSecret);
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("a held identifier lock does not serialize a different login identifier", async () => {
  const lock = await holdLoginRateLimitLock(lockedIdentifier);

  try {
    const distinctResponse = await withBroadTimeout(
      POST(createLoginRequest("independent-rate-limit@example.invalid")),
      5_000
    );

    assertGenericLoginFailure(distinctResponse);
  } finally {
    lock.release();
    await lock.finished;
  }

  const buckets = await prisma.loginRateLimit.findMany({
    select: { attempts: true, identifierHash: true }
  });

  assert.equal(buckets.length, 2);
  assert.equal(new Set(buckets.map((bucket) => bucket.identifierHash)).size, 2);
});

test("same-identifier lock wait reaches the database lock timeout and fails closed", async () => {
  const lock = await holdLoginRateLimitLock(lockedIdentifier);

  try {
    const response = await withBroadTimeout(
      POST(createLoginRequest(lockedIdentifier)),
      12_000
    );
    const audits = await prisma.auditLog.findMany({
      where: { eventType: "AUTH_LOGIN_FAILURE" },
      select: { message: true, metadata: true }
    });

    assertGenericLoginFailure(response);
    assert.equal(await prisma.session.count(), 0);
    assert.equal(
      (await prisma.loginRateLimit.findFirst({ select: { attempts: true } }))?.attempts,
      1
    );
    assert.equal(audits.length, 1);
    assert.equal(audits[0]?.message, "Login rate limit unavailable.");
    assert.equal(JSON.stringify(audits).includes(lockedIdentifier), false);
  } finally {
    lock.release();
    await lock.finished;
  }
});

async function holdLoginRateLimitLock(identifier: string): Promise<{
  release: () => void;
  finished: Promise<void>;
}> {
  await recordFailedLogin(identifier, new Date());
  const row = await prisma.loginRateLimit.findFirstOrThrow({
    select: { identifierHash: true }
  });
  const ready = createDeferred();
  const release = createDeferred();
  const finished = prisma.$transaction(
    async (transaction) => {
      await transaction.$queryRaw`
        SELECT pg_advisory_xact_lock(hashtextextended(${row.identifierHash}, 0)) IS NULL AS "locked"
      `;
      ready.resolve();
      await release.promise;
    },
    { maxWait: 5_000, timeout: 30_000 }
  );

  await ready.promise;

  return {
    release: release.resolve,
    finished
  };
}

function createLoginRequest(identifier: string): Request {
  const formData = new FormData();
  formData.set("email", identifier);
  formData.set("password", "synthetic-invalid-credential");
  formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());

  return new Request("http://hub.example.invalid/api/login", {
    method: "POST",
    body: formData,
    headers: { "user-agent": "bielos-synthetic-timeout-test" }
  });
}

function assertGenericLoginFailure(response: Response): void {
  assert.equal(response.status, 303);
  const location = new URL(response.headers.get("location") ?? "http://invalid");
  assert.equal(location.pathname, "/login");
  assert.equal(location.searchParams.get("error"), "1");
  assert.equal(response.headers.has("set-cookie"), false);
}

async function withBroadTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error("Synthetic login operation exceeded its broad timeout.")),
          timeoutMs
        );
      })
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

function createDeferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });

  return { promise, resolve };
}

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}
