import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { NextRequest } from "next/server";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { SESSION_COOKIE_NAME } from "@bielos/auth";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";

import { POST } from "./route";

test("logout redirects to the configured public hub origin", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalAccessAudience = process.env.CLOUDFLARE_ACCESS_AUDIENCE;
  const originalTeamDomain = process.env.CLOUDFLARE_TEAM_DOMAIN;
  const originalHubUrl = process.env.BIELOS_HUB_URL;
  const originalHubHostname = process.env.BIELOS_HUB_HOSTNAME;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalCsrfKey = process.env.BIELOS_CSRF_SIGNING_KEY;
  const originalPreviousCsrfKey = process.env.BIELOS_CSRF_SIGNING_KEY_PREVIOUS;
  let access: ProductionAccessAssertion | undefined;

  try {
    access = await createProductionAccessAssertion();
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
    process.env.CLOUDFLARE_ACCESS_AUDIENCE = access.audience;
    process.env.CLOUDFLARE_TEAM_DOMAIN = access.teamDomain;
    process.env.BIELOS_HUB_URL = "https://hub.example.invalid";
    process.env.BIELOS_HUB_HOSTNAME = "hub.example.invalid";
    process.env.BIELOS_CSRF_SIGNING_KEY = "11".repeat(32);
    delete process.env.BIELOS_CSRF_SIGNING_KEY_PREVIOUS;
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
  } finally {
    access?.restore();
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_AUDIENCE", originalAccessAudience);
    restoreEnvironmentVariable("CLOUDFLARE_TEAM_DOMAIN", originalTeamDomain);
    restoreEnvironmentVariable("BIELOS_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("BIELOS_HUB_HOSTNAME", originalHubHostname);
    restoreEnvironmentVariable("BIELOS_CSRF_SIGNING_KEY", originalCsrfKey);
    restoreEnvironmentVariable("BIELOS_CSRF_SIGNING_KEY_PREVIOUS", originalPreviousCsrfKey);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

test("production logout redirects to the canonical host when the explicit public URL is unset", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalAccessAudience = process.env.CLOUDFLARE_ACCESS_AUDIENCE;
  const originalTeamDomain = process.env.CLOUDFLARE_TEAM_DOMAIN;
  const originalHubUrl = process.env.BIELOS_HUB_URL;
  const originalHubHostname = process.env.BIELOS_HUB_HOSTNAME;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalCsrfKey = process.env.BIELOS_CSRF_SIGNING_KEY;
  const originalPreviousCsrfKey = process.env.BIELOS_CSRF_SIGNING_KEY_PREVIOUS;
  let access: ProductionAccessAssertion | undefined;

  try {
    access = await createProductionAccessAssertion();
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
    process.env.CLOUDFLARE_ACCESS_AUDIENCE = access.audience;
    process.env.CLOUDFLARE_TEAM_DOMAIN = access.teamDomain;
    process.env.BIELOS_CSRF_SIGNING_KEY = "11".repeat(32);
    delete process.env.BIELOS_CSRF_SIGNING_KEY_PREVIOUS;
    setEnvironmentVariable("NODE_ENV", "production");
    delete process.env.BIELOS_HUB_URL;
    process.env.BIELOS_HUB_HOSTNAME = "hub.biel.dev.br";
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
    restoreEnvironmentVariable("BIELOS_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("BIELOS_HUB_HOSTNAME", originalHubHostname);
    restoreEnvironmentVariable("BIELOS_CSRF_SIGNING_KEY", originalCsrfKey);
    restoreEnvironmentVariable("BIELOS_CSRF_SIGNING_KEY_PREVIOUS", originalPreviousCsrfKey);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

test("invalid production redirect configuration clears the cookie without an external redirect", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalAccessAudience = process.env.CLOUDFLARE_ACCESS_AUDIENCE;
  const originalTeamDomain = process.env.CLOUDFLARE_TEAM_DOMAIN;
  const originalHubUrl = process.env.BIELOS_HUB_URL;
  const originalHubHostname = process.env.BIELOS_HUB_HOSTNAME;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalCsrfKey = process.env.BIELOS_CSRF_SIGNING_KEY;
  const originalPreviousCsrfKey = process.env.BIELOS_CSRF_SIGNING_KEY_PREVIOUS;
  let access: ProductionAccessAssertion | undefined;

  try {
    access = await createProductionAccessAssertion();
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
    process.env.CLOUDFLARE_ACCESS_AUDIENCE = access.audience;
    process.env.CLOUDFLARE_TEAM_DOMAIN = access.teamDomain;
    process.env.BIELOS_HUB_URL = "https://attacker.invalid";
    process.env.BIELOS_HUB_HOSTNAME = "hub.biel.dev.br";
    process.env.BIELOS_CSRF_SIGNING_KEY = "11".repeat(32);
    delete process.env.BIELOS_CSRF_SIGNING_KEY_PREVIOUS;
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
    restoreEnvironmentVariable("BIELOS_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("BIELOS_HUB_HOSTNAME", originalHubHostname);
    restoreEnvironmentVariable("BIELOS_CSRF_SIGNING_KEY", originalCsrfKey);
    restoreEnvironmentVariable("BIELOS_CSRF_SIGNING_KEY_PREVIOUS", originalPreviousCsrfKey);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

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
