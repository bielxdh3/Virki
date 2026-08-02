import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";

import {
  hashPassword
} from "@bielos/auth";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { DEVICE_COOKIE_NAME } from "@bielos/auth/security";
import { prisma } from "@bielos/database";

import { POST } from "../../api/login/route";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

const syntheticCredential = "replace-with-test-secret";
const invalidCredential = "synthetic-invalid-credential";
const memberEmail = "rate-limit-test@example.invalid";
const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
const originalRateLimitSecret = process.env.BIELOS_RATE_LIMIT_HASH_SECRET;
const originalHubUrl = process.env.NEXT_PUBLIC_HUB_URL;
const originalNodeEnv = process.env.NODE_ENV;

before(() => {
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
  process.env.BIELOS_RATE_LIMIT_HASH_SECRET = syntheticCredential;
  process.env.NEXT_PUBLIC_HUB_URL = "https://hub.example.invalid";
});

beforeEach(async () => {
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
  process.env.BIELOS_RATE_LIMIT_HASH_SECRET = syntheticCredential;
  process.env.NEXT_PUBLIC_HUB_URL = "https://hub.example.invalid";
  await cleanCoreIntegrationTestData();
});

after(async () => {
  restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
  restoreEnvironmentVariable("BIELOS_RATE_LIMIT_HASH_SECRET", originalRateLimitSecret);
  restoreEnvironmentVariable("NEXT_PUBLIC_HUB_URL", originalHubUrl);
  restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("required Cloudflare Access rejects login before limiter or session state", async () => {
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";

  const response = await POST(createLoginRequest({
    email: memberEmail,
    password: syntheticCredential,
    csrfToken: createCsrfToken()
  }));

  assert.equal(response.status, 403);
  assert.equal(await prisma.loginRateLimit.count(), 0);
  assert.equal(await prisma.session.count(), 0);
});

test("missing or invalid CSRF rejects login without state changes", async () => {
  const missingResponse = await POST(createLoginRequest({
    email: memberEmail,
    password: syntheticCredential
  }));
  const invalidResponse = await POST(createLoginRequest({
    email: memberEmail,
    password: syntheticCredential,
    csrfToken: "invalid-test-token"
  }));

  assert.equal(missingResponse.status, 403);
  assert.equal(invalidResponse.status, 403);
  assert.equal(await prisma.loginRateLimit.count(), 0);
  assert.equal(await prisma.session.count(), 0);
});

test("first invalid login creates one hashed bucket and a sanitized generic audit", async () => {
  const wrongPassword = "synthetic-wrong-password";
  const response = await POST(createLoginRequest({
    email: memberEmail,
    password: wrongPassword,
    csrfToken: createCsrfToken()
  }));
  const bucket = await prisma.loginRateLimit.findFirst({
    select: { identifierHash: true, attempts: true }
  });
  const audits = await readLoginAudits();

  assertGenericLoginFailure(response);
  assert.equal(bucket?.attempts, 1);
  assert.match(bucket?.identifierHash ?? "", /^[a-f0-9]{64}$/);
  assert.equal(await prisma.session.count(), 0);
  assert.equal(audits.length, 1);
  assert.equal(audits[0]?.message, "Login failed.");
  assertSafeAuditRows(audits, [memberEmail, wrongPassword]);
});

test("six invalid route requests retain five attempts and remain generic", async () => {
  const wrongPassword = "synthetic-wrong-password";
  const responses = [];

  for (let attempt = 0; attempt < 6; attempt += 1) {
    responses.push(await POST(createLoginRequest({
      email: memberEmail,
      password: wrongPassword,
      csrfToken: createCsrfToken()
    })));
  }

  const bucket = await prisma.loginRateLimit.findFirst({
    select: { attempts: true, blockedUntil: true }
  });
  const audits = await readLoginAudits();

  responses.forEach(assertGenericLoginFailure);
  assert.equal(bucket?.attempts, 5);
  assert.equal(bucket?.blockedUntil instanceof Date, true);
  assert.equal(await prisma.session.count(), 0);
  assert.equal(audits.length, 6);
  assert.equal(audits.filter((audit) => audit.message === "Login failed.").length, 5);
  assert.equal(
    audits.filter((audit) => audit.message === "Login rate limit reached.").length,
    1
  );
  assertSafeAuditRows(audits, [memberEmail, wrongPassword]);
});

test("missing credentials use the unknown bucket without raw form storage", async () => {
  const response = await POST(createLoginRequest({ csrfToken: createCsrfToken() }));
  const bucket = await prisma.loginRateLimit.findFirst({
    select: { identifierHash: true, attempts: true }
  });
  const audits = await readLoginAudits();

  assertGenericLoginFailure(response);
  assert.equal(bucket?.attempts, 1);
  assert.match(bucket?.identifierHash ?? "", /^[a-f0-9]{64}$/);
  assert.equal(await prisma.session.count(), 0);
  assertSafeAuditRows(audits, [syntheticCredential]);
});

test("valid MEMBER login starts email verification, sets a device cookie, and clears the bucket", async () => {
  const user = await createSyntheticMember();
  await POST(createLoginRequest({
    email: memberEmail,
    password: invalidCredential,
    csrfToken: createCsrfToken()
  }));

  const response = await POST(createLoginRequest({
    email: ` ${memberEmail.toUpperCase()} `,
    password: syntheticCredential,
    csrfToken: createCsrfToken()
  }));
  const audits = await readLoginAudits();

  assert.equal(response.status, 303);
  const location = new URL(response.headers.get("location") ?? "http://invalid");
  assert.equal(location.origin, "https://hub.example.invalid");
  assert.equal(location.pathname, "/login/verify");
  assert.match(location.searchParams.get("ceremony") ?? "", /^[A-Za-z0-9_-]{32,}$/);
  assert.equal(location.searchParams.get("factor"), "email");
  assert.equal(await prisma.session.count({ where: { userId: user.id } }), 0);
  assert.equal(await prisma.loginRateLimit.count(), 0);
  assert.equal(
    response.headers.get("set-cookie")?.startsWith(`${DEVICE_COOKIE_NAME}=`) ?? false,
    true
  );
  assert.equal(response.headers.get("set-cookie")?.includes("HttpOnly") ?? false, true);
  assert.equal(response.headers.get("set-cookie")?.includes("SameSite=lax") ?? false, true);
  assert.equal(audits.filter((audit) => audit.eventType === "AUTH_LOGIN_SUCCESS").length, 1);
  assertSafeAuditRows(audits, [memberEmail, syntheticCredential]);
});

test("invalid production redirect configuration fails before limiter or session creation", async () => {
  await createSyntheticMember();

  try {
    setEnvironmentVariable("NODE_ENV", "production");
    delete process.env.NEXT_PUBLIC_HUB_URL;

    const response = await POST(createLoginRequest({
      email: memberEmail,
      password: syntheticCredential,
      csrfToken: createCsrfToken()
    }));

    assert.equal(response.status, 503);
    assert.equal(await response.text(), "Service unavailable");
    assert.equal(response.headers.get("location"), null);
    assert.equal(response.headers.has("set-cookie"), false);
    assert.equal(await prisma.loginRateLimit.count(), 0);
    assert.equal(await prisma.session.count(), 0);
    assert.equal((await readLoginAudits()).length, 0);
  } finally {
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
    process.env.NEXT_PUBLIC_HUB_URL = "https://hub.example.invalid";
  }
});

test("inactive user receives the generic response and records a limiter attempt", async () => {
  await createSyntheticMember(false);

  const response = await POST(createLoginRequest({
    email: memberEmail,
    password: syntheticCredential,
    csrfToken: createCsrfToken()
  }));

  assertGenericLoginFailure(response);
  assert.equal(await prisma.session.count(), 0);
  assert.equal(
    (await prisma.loginRateLimit.findFirst({ select: { attempts: true } }))?.attempts,
    1
  );
});

test("missing production limiter configuration fails closed with a generic route response", async () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalSecret = process.env.BIELOS_RATE_LIMIT_HASH_SECRET;

  try {
    setEnvironmentVariable("NODE_ENV", "production");
    delete process.env.BIELOS_RATE_LIMIT_HASH_SECRET;

    const response = await POST(createLoginRequest({
      email: memberEmail,
      password: syntheticCredential,
      csrfToken: createCsrfToken()
    }));
    const audits = await readLoginAudits();

    assertGenericLoginFailure(response);
    assert.equal(await prisma.loginRateLimit.count(), 0);
    assert.equal(await prisma.session.count(), 0);
    assert.equal(audits[0]?.message, "Login rate limit unavailable.");
    assertSafeAuditRows(audits, [memberEmail, syntheticCredential]);
  } finally {
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
    restoreEnvironmentVariable("BIELOS_RATE_LIMIT_HASH_SECRET", originalSecret);
  }
});

function createLoginRequest(input: {
  email?: string;
  password?: string;
  csrfToken?: string;
}): Request {
  const formData = new FormData();

  if (input.email !== undefined) {
    formData.set("email", input.email);
  }

  if (input.password !== undefined) {
    formData.set("password", input.password);
  }

  if (input.csrfToken !== undefined) {
    formData.set(CSRF_FORM_FIELD_NAME, input.csrfToken);
  }

  return new Request("http://hub.example.invalid/api/login", {
    method: "POST",
    body: formData,
    headers: { "user-agent": "bielos-synthetic-route-test" }
  });
}

async function createSyntheticMember(isActive = true): Promise<{ id: string }> {
  return prisma.user.create({
    data: {
      email: memberEmail,
      passwordHash: await hashPassword(syntheticCredential),
      role: "MEMBER",
      isActive
    },
    select: { id: true }
  });
}

async function readLoginAudits() {
  return prisma.auditLog.findMany({
    where: { eventType: { in: ["AUTH_LOGIN_FAILURE", "AUTH_LOGIN_SUCCESS"] } },
    select: {
      eventType: true,
      actorEmailHash: true,
      message: true,
      metadata: true
    },
    orderBy: { createdAt: "asc" }
  });
}

function assertGenericLoginFailure(response: Response): void {
  assert.equal(response.status, 303);
  const location = new URL(response.headers.get("location") ?? "http://invalid");
  assert.equal(location.origin, "https://hub.example.invalid");
  assert.equal(location.pathname, "/login");
  assert.equal(location.searchParams.get("error"), "1");
  assert.equal(response.headers.has("set-cookie"), false);
}

function assertSafeAuditRows(rows: Awaited<ReturnType<typeof readLoginAudits>>, forbidden: string[]) {
  const serialized = JSON.stringify(rows);

  for (const value of forbidden) {
    assert.equal(serialized.includes(value), false);
  }
}

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}

function setEnvironmentVariable(name: string, value: string): void {
  process.env[name] = value;
}
