import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { NextRequest } from "next/server";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { hashSessionToken, SESSION_COOKIE_NAME } from "@virki/auth";
import { prisma } from "@virki/database";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";

import { POST } from "./route";

test("native anonymous logout Origin flood is bounded without sampling a verified ADMIN denial", async () => {
  const keys = ["NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
    "VIRKI_HUB_URL", "VIRKI_HUB_HOSTNAME", "VIRKI_AUDIT_HASH_SECRET"] as const;
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const originalAudit = prisma.auditLog.create;
  const originalLookup = prisma.session.findUnique;
  const validToken = "A".repeat(43);
  const userToken = "B".repeat(43);
  let writes = 0;
  const auditEvents: Record<string, unknown>[] = [];
  try {
    Reflect.set(process.env, "NODE_ENV", "production");
    process.env.VIRKI_HUB_PERIMETER_MODE = "native";
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
    process.env.VIRKI_HUB_URL = "https://hub.biel.dev.br";
    process.env.VIRKI_HUB_HOSTNAME = "hub.biel.dev.br";
    process.env.VIRKI_AUDIT_HASH_SECRET = "22".repeat(32);
    prisma.auditLog.create = (async (input: { data: Record<string, unknown> }) => {
      writes += 1;
      auditEvents.push(input.data);
      return {};
    }) as unknown as typeof originalAudit;
    prisma.session.findUnique = (async (input: { where: { tokenHash: string } }) => {
      if (input.where.tokenHash !== hashSessionToken(validToken) &&
          input.where.tokenHash !== hashSessionToken(userToken)) return null;
      const admin = input.where.tokenHash === hashSessionToken(validToken);
      return {
        id: admin ? "verified-admin-session" : "verified-user-session", createdAt: new Date(), expiresAt: new Date(Date.now() + 60_000),
        revokedAt: null, authenticationMethods: ["pwd", "totp"],
        user: { id: admin ? "verified-admin" : "verified-user",
          email: "actor@example.invalid", displayName: "Actor",
          role: admin ? "ADMIN" : "USER", isActive: true, accountStatus: "ACTIVE" }
      };
    }) as unknown as typeof originalLookup;
    const hostile = { host: "hub.biel.dev.br", origin: "https://untrusted.invalid" };
    const crossRoleResponses = await Promise.all(Array.from({ length: 180 }, () =>
      POST(new NextRequest("https://hub.biel.dev.br/api/logout", {
        method: "POST", headers: { ...hostile, cookie: `${SESSION_COOKIE_NAME}=${userToken}` }
      }))));
    assert.ok(crossRoleResponses.every((response) => response.status === 403));
    assert.ok(writes <= 120, `valid USER session cannot escape native ADMIN audit limit, got ${writes}`);
    const responses = await Promise.all(Array.from({ length: 180 }, () =>
      POST(new NextRequest("https://hub.biel.dev.br/api/logout", { method: "POST", headers: hostile }))));
    assert.ok(responses.every((response) => response.status === 403));
    assert.ok(writes <= 120, `anonymous logout Origin flood must not write every event, got ${writes}`);
    const afterFlood = writes;
    const verified = await POST(new NextRequest("https://hub.biel.dev.br/api/logout", {
      method: "POST", headers: { ...hostile, cookie: `${SESSION_COOKIE_NAME}=${validToken}` }
    }));
    assert.equal(verified.status, 403);
    assert.equal(writes, afterFlood + 1, "verified ADMIN Origin denial must not be sampled after anonymous flood");
    assert.equal(auditEvents.at(-1)?.actorUserId, "verified-admin");
    assert.equal(auditEvents.at(-1)?.actorRole, "ADMIN");
  } finally {
    prisma.auditLog.create = originalAudit;
    prisma.session.findUnique = originalLookup;
    for (const key of keys) {
      const value = previous[key];
      if (value === undefined) delete process.env[key];
      else Reflect.set(process.env, key, value);
    }
  }
});

test("logout redirects to the configured public hub origin", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalAccessAudience = process.env.CLOUDFLARE_ACCESS_AUDIENCE;
  const originalTeamDomain = process.env.CLOUDFLARE_TEAM_DOMAIN;
  const originalHubUrl = process.env.VIRKI_HUB_URL;
  const originalHubHostname = process.env.VIRKI_HUB_HOSTNAME;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY;
  const originalPreviousCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
  let access: ProductionAccessAssertion | undefined;

  try {
    access = await createProductionAccessAssertion();
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
    process.env.CLOUDFLARE_ACCESS_AUDIENCE = access.audience;
    process.env.CLOUDFLARE_TEAM_DOMAIN = access.teamDomain;
    process.env.VIRKI_HUB_URL = "https://hub.example.invalid";
    process.env.VIRKI_HUB_HOSTNAME = "hub.example.invalid";
    process.env.VIRKI_CSRF_SIGNING_KEY = "11".repeat(32);
    delete process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
    setEnvironmentVariable("NODE_ENV", "production");
    const formData = new FormData();
    formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "logout" }));

    const response = await POST(new NextRequest("https://hub.example.invalid:3001/api/logout", {
      method: "POST",
      body: formData,
      headers: {
        host: "hub.example.invalid:3001",
        origin: "https://hub.example.invalid:3001",
        "cf-access-jwt-assertion": access.token
      }
    }));

    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "https://hub.example.invalid/login");
    assert.equal(response.headers.get("cache-control"), "no-store");
  } finally {
    access?.restore();
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_AUDIENCE", originalAccessAudience);
    restoreEnvironmentVariable("CLOUDFLARE_TEAM_DOMAIN", originalTeamDomain);
    restoreEnvironmentVariable("VIRKI_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("VIRKI_HUB_HOSTNAME", originalHubHostname);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY", originalCsrfKey);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY_PREVIOUS", originalPreviousCsrfKey);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

test("production logout redirects to the canonical host when the explicit public URL is unset", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalAccessAudience = process.env.CLOUDFLARE_ACCESS_AUDIENCE;
  const originalTeamDomain = process.env.CLOUDFLARE_TEAM_DOMAIN;
  const originalHubUrl = process.env.VIRKI_HUB_URL;
  const originalHubHostname = process.env.VIRKI_HUB_HOSTNAME;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY;
  const originalPreviousCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
  let access: ProductionAccessAssertion | undefined;

  try {
    access = await createProductionAccessAssertion();
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
    process.env.CLOUDFLARE_ACCESS_AUDIENCE = access.audience;
    process.env.CLOUDFLARE_TEAM_DOMAIN = access.teamDomain;
    process.env.VIRKI_CSRF_SIGNING_KEY = "11".repeat(32);
    delete process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
    setEnvironmentVariable("NODE_ENV", "production");
    delete process.env.VIRKI_HUB_URL;
    process.env.VIRKI_HUB_HOSTNAME = "hub.biel.dev.br";
    const formData = new FormData();
    formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "logout" }));

    const response = await POST(new NextRequest("http://hub:3001/api/logout", {
      method: "POST",
      body: formData,
      headers: {
        host: "hub.biel.dev.br:3001",
        origin: "https://hub.biel.dev.br:3001",
        "cf-access-jwt-assertion": access.token
      }
    }));
    const setCookie = response.headers.get("set-cookie") ?? "";

    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "https://hub.biel.dev.br/login");
    assert.equal(setCookie.startsWith(`${SESSION_COOKIE_NAME}=`), true);
    assert.equal(setCookie.includes("Max-Age=0"), true);
    assert.equal(setCookie.includes("HttpOnly"), true);
    assert.equal(setCookie.includes("Secure"), true);
    assert.equal(setCookie.includes("SameSite=lax"), true);
  } finally {
    access?.restore();
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_AUDIENCE", originalAccessAudience);
    restoreEnvironmentVariable("CLOUDFLARE_TEAM_DOMAIN", originalTeamDomain);
    restoreEnvironmentVariable("VIRKI_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("VIRKI_HUB_HOSTNAME", originalHubHostname);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY", originalCsrfKey);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY_PREVIOUS", originalPreviousCsrfKey);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

test("invalid production redirect configuration clears the cookie without an external redirect", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalAccessAudience = process.env.CLOUDFLARE_ACCESS_AUDIENCE;
  const originalTeamDomain = process.env.CLOUDFLARE_TEAM_DOMAIN;
  const originalHubUrl = process.env.VIRKI_HUB_URL;
  const originalHubHostname = process.env.VIRKI_HUB_HOSTNAME;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY;
  const originalPreviousCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
  let access: ProductionAccessAssertion | undefined;

  try {
    access = await createProductionAccessAssertion();
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
    process.env.CLOUDFLARE_ACCESS_AUDIENCE = access.audience;
    process.env.CLOUDFLARE_TEAM_DOMAIN = access.teamDomain;
    process.env.VIRKI_HUB_URL = "https://attacker.invalid";
    process.env.VIRKI_HUB_HOSTNAME = "hub.biel.dev.br";
    process.env.VIRKI_CSRF_SIGNING_KEY = "11".repeat(32);
    delete process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
    setEnvironmentVariable("NODE_ENV", "production");
    const formData = new FormData();
    formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "logout" }));

    const response = await POST(new NextRequest("http://hub:3001/api/logout", {
      method: "POST",
      body: formData,
      headers: {
        host: "hub.biel.dev.br:3001",
        origin: "https://hub.biel.dev.br:3001",
        "cf-access-jwt-assertion": access.token
      }
    }));
    const setCookie = response.headers.get("set-cookie") ?? "";

    assert.equal(response.status, 503);
    assert.equal(response.headers.get("location"), null);
    assert.equal(setCookie.startsWith(`${SESSION_COOKIE_NAME}=`), true);
    assert.equal(setCookie.includes("Max-Age=0"), true);
  } finally {
    access?.restore();
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_AUDIENCE", originalAccessAudience);
    restoreEnvironmentVariable("CLOUDFLARE_TEAM_DOMAIN", originalTeamDomain);
    restoreEnvironmentVariable("VIRKI_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("VIRKI_HUB_HOSTNAME", originalHubHostname);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY", originalCsrfKey);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY_PREVIOUS", originalPreviousCsrfKey);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

test("logout rejects a CSRF token issued for another form scope", async () => {
  const response = await postHubLogoutWithCsrfScope("account-security");

  assert.equal(response.status, 403);
  assert.equal(response.headers.get("location"), null);
});

test("logout accepts a logout-scoped CSRF token without a session cookie", async () => {
  const response = await postHubLogoutWithCsrfScope("logout");
  const setCookie = response.headers.get("set-cookie") ?? "";

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "https://hub.example.invalid/login");
  assert.equal(setCookie.startsWith(`${SESSION_COOKIE_NAME}=`), true);
  assert.equal(setCookie.includes("Max-Age=0"), true);
});

test("logout rejects a token bound to another session", async () => {
  const response = await postHubLogoutWithCsrfScope("logout", { tokenBoundTo: "session-a", cookie: "session-b" });

  assert.equal(response.status, 403);
});

test("logout rejects an unbound token when a session cookie is present", async () => {
  const response = await postHubLogoutWithCsrfScope("logout", { cookie: "session-b" });

  assert.equal(response.status, 403);
});

// The accepted path for a bound token with a matching cookie reaches getSessionByToken (database),
// so it is covered by validateCsrfToken/session-csrf unit tests rather than here.

async function postHubLogoutWithCsrfScope(scope: "logout" | "account-security", session?: { tokenBoundTo?: string; cookie?: string }): Promise<Response> {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalAccessAudience = process.env.CLOUDFLARE_ACCESS_AUDIENCE;
  const originalTeamDomain = process.env.CLOUDFLARE_TEAM_DOMAIN;
  const originalHubUrl = process.env.VIRKI_HUB_URL;
  const originalHubHostname = process.env.VIRKI_HUB_HOSTNAME;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY;
  const originalPreviousCsrfKey = process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
  let access: ProductionAccessAssertion | undefined;

  try {
    access = await createProductionAccessAssertion();
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
    process.env.CLOUDFLARE_ACCESS_AUDIENCE = access.audience;
    process.env.CLOUDFLARE_TEAM_DOMAIN = access.teamDomain;
    process.env.VIRKI_HUB_URL = "https://hub.example.invalid";
    process.env.VIRKI_HUB_HOSTNAME = "hub.example.invalid";
    process.env.VIRKI_CSRF_SIGNING_KEY = "11".repeat(32);
    delete process.env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS;
    setEnvironmentVariable("NODE_ENV", "production");
    const formData = new FormData();
    formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope, ...(session?.tokenBoundTo ? { binding: hashSessionToken(session.tokenBoundTo) } : {}) }));

    return await POST(new NextRequest("https://hub.example.invalid:3001/api/logout", {
      method: "POST",
      body: formData,
      headers: {
        host: "hub.example.invalid:3001",
        origin: "https://hub.example.invalid:3001",
        "cf-access-jwt-assertion": access.token,
        ...(session?.cookie ? { cookie: `${SESSION_COOKIE_NAME}=${session.cookie}` } : {})
      }
    }));
  } finally {
    access?.restore();
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_AUDIENCE", originalAccessAudience);
    restoreEnvironmentVariable("CLOUDFLARE_TEAM_DOMAIN", originalTeamDomain);
    restoreEnvironmentVariable("VIRKI_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("VIRKI_HUB_HOSTNAME", originalHubHostname);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY", originalCsrfKey);
    restoreEnvironmentVariable("VIRKI_CSRF_SIGNING_KEY_PREVIOUS", originalPreviousCsrfKey);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
}

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}

type ProductionAccessAssertion = { audience: string; teamDomain: string; token: string; restore: () => void };

async function createProductionAccessAssertion(): Promise<ProductionAccessAssertion> {
  const teamDomain = `https://${randomUUID()}.example.invalid`;
  const audience = randomUUID();
  const keyId = randomUUID();
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = (async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: keyId, use: "sig", alg: "RS256" }] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    })) as typeof fetch;
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: keyId })
      .setIssuer(teamDomain)
      .setAudience(audience)
      .setIssuedAt()
      .setNotBefore("0s")
      .setExpirationTime("2m")
      .sign(privateKey);
    return { audience, teamDomain, token, restore: () => { globalThis.fetch = originalFetch; } };
  } catch (error) {
    globalThis.fetch = originalFetch;
    throw error;
  }
}

function setEnvironmentVariable(name: string, value: string): void {
  process.env[name] = value;
}
