import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";

import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";

import { POST } from "../../api/login/route";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

const identifier = "rate-limit-route-concurrency@example.invalid";
const wrongPassword = "synthetic-wrong-password";
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

test("concurrent login route requests admit at most five password verifications", async () => {
  const responses = await Promise.all(
    Array.from({ length: 12 }, () => POST(createLoginRequest()))
  );
  const buckets = await prisma.loginRateLimit.findMany({
    select: { attempts: true, identifierHash: true }
  });
  const audits = await prisma.auditLog.findMany({
    where: { eventType: "AUTH_LOGIN_FAILURE" },
    select: { message: true, actorEmailHash: true, metadata: true }
  });
  const serializedAudits = JSON.stringify(audits);

  assert.equal(responses.every((response) => response.status === 303), true);
  assert.equal(
    responses.every((response) => {
      const location = new URL(response.headers.get("location") ?? "http://invalid");
      return location.pathname === "/login" && location.searchParams.get("error") === "1";
    }),
    true
  );
  assert.equal(buckets.length, 1);
  assert.equal(buckets[0]?.attempts, 5);
  assert.match(buckets[0]?.identifierHash ?? "", /^[a-f0-9]{64}$/);
  assert.equal(await prisma.session.count(), 0);
  assert.equal(audits.length, 12);
  assert.equal(audits.filter((audit) => audit.message === "Login failed.").length, 5);
  assert.equal(
    audits.filter((audit) => audit.message === "Login rate limit reached.").length,
    7
  );
  assert.equal(serializedAudits.includes(identifier), false);
  assert.equal(serializedAudits.includes(wrongPassword), false);
});

function createLoginRequest(): Request {
  const formData = new FormData();
  formData.set("email", identifier);
  formData.set("password", wrongPassword);
  formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());

  return new Request("http://hub.example.invalid/api/login", {
    method: "POST",
    body: formData,
    headers: { "user-agent": "bielos-synthetic-concurrency-test" }
  });
}

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}
