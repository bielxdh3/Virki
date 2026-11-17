import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { POST } from "./route";
import { prisma } from "@virki/database";
import { recordSecurityDenial } from "../../../lib/audit-denial";

const ENV_KEYS = [
  "NODE_ENV",
  "VIRKI_HUB_PERIMETER_MODE",
  "CLOUDFLARE_ACCESS_JWT_REQUIRED",
  "VIRKI_HUB_URL",
  "VIRKI_HUB_HOSTNAME",
  "VIRKI_CSRF_SIGNING_KEY",
  "VIRKI_AUDIT_HASH_SECRET",
  "VIRKI_RATE_LIMIT_HASH_SECRET"
] as const;

function withEnv(overrides: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>, run: () => Promise<void>) {
  const before = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  return (async () => {
    try {
      for (const key of ENV_KEYS) {
        const value = overrides[key];
        if (value === undefined) delete process.env[key];
        else Reflect.set(process.env, key, value);
      }
      await run();
    } finally {
      for (const key of ENV_KEYS) {
        const value = before[key];
        if (value === undefined) delete process.env[key];
        else Reflect.set(process.env, key, value);
      }
    }
  })();
}

function loginBody(csrfToken: string): FormData {
  const form = new FormData();
  form.set(CSRF_FORM_FIELD_NAME, csrfToken);
  form.set("email", "admin@example.invalid");
  form.set("password", "not-the-password");
  return form;
}

test("production native Hub login enforces Origin and CSRF, rejects spoofed IP fallbacks, and keeps Access mode fail-closed", async () => {
  const baseEnv = {
    NODE_ENV: "production",
    VIRKI_HUB_URL: "https://hub.biel.dev.br",
    VIRKI_HUB_HOSTNAME: "hub.biel.dev.br",
    VIRKI_CSRF_SIGNING_KEY: "11".repeat(32),
    VIRKI_AUDIT_HASH_SECRET: "22".repeat(32),
    VIRKI_RATE_LIMIT_HASH_SECRET: "33".repeat(32)
  };

  // Access mode (default) still rejects missing Access assertion with 403.
  await withEnv({ ...baseEnv, VIRKI_HUB_PERIMETER_MODE: "access", CLOUDFLARE_ACCESS_JWT_REQUIRED: "true" }, async () => {
    const response = await POST(new NextRequest("https://hub.biel.dev.br/api/login", {
      method: "POST",
      headers: { host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br", "cf-connecting-ip": "203.0.113.10" },
      body: loginBody(createCsrfToken({ scope: "login" }))
    }));
    assert.equal(response.status, 403);
  });

  // Native mode allows reaching /api/login without Access JWT or edge proof, while enforcing Origin, CSRF, Host, and trusted client IP.
  await withEnv({ ...baseEnv, VIRKI_HUB_PERIMETER_MODE: "native", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false" }, async () => {
    // Unknown host is rejected (404).
    const unknownHost = await POST(new NextRequest("https://evil.invalid/api/login", {
      method: "POST",
      headers: { host: "evil.invalid", origin: "https://evil.invalid", "cf-connecting-ip": "203.0.113.10" },
      body: loginBody(createCsrfToken({ scope: "login" }))
    }));
    assert.equal(unknownHost.status, 404);

    // Cross-origin request is rejected (403).
    const badOrigin = await POST(new NextRequest("https://hub.biel.dev.br/api/login", {
      method: "POST",
      headers: { host: "hub.biel.dev.br", origin: "https://evil.invalid", "cf-connecting-ip": "203.0.113.10" },
      body: loginBody(createCsrfToken({ scope: "login" }))
    }));
    assert.equal(badOrigin.status, 403);

    // Missing/invalid CSRF is rejected (403).
    const badCsrf = await POST(new NextRequest("https://hub.biel.dev.br/api/login", {
      method: "POST",
      headers: { host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br", "cf-connecting-ip": "203.0.113.10" },
      body: loginBody("invalid-csrf-token")
    }));
    assert.equal(badCsrf.status, 403);

    // Missing cf-connecting-ip (even with X-Forwarded-For) fails closed safely at limiter-unavailable (303 error, never 403 Access denial and never trusts XFF).
    const missingIp = await POST(new NextRequest("https://hub.biel.dev.br/api/login", {
      method: "POST",
      headers: { host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br", "x-forwarded-for": "203.0.113.10" },
      body: loginBody(createCsrfToken({ scope: "login" }))
    }));
    assert.equal(missingIp.status, 303);
    assert.equal(missingIp.headers.get("location"), "https://hub.biel.dev.br/login?error=1");

    // Spoofed comma-separated cf-connecting-ip also fails closed safely.
    const spoofedIp = await POST(new NextRequest("https://hub.biel.dev.br/api/login", {
      method: "POST",
      headers: { host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br", "cf-connecting-ip": "203.0.113.10, 198.51.100.2" },
      body: loginBody(createCsrfToken({ scope: "login" }))
    }));
    assert.equal(spoofedIp.status, 303);
    assert.equal(spoofedIp.headers.get("location"), "https://hub.biel.dev.br/login?error=1");
  });
});

test("native pre-auth origin flood remains 403 without an unbounded audit database write per request", async () => {
  await withEnv({
    NODE_ENV: "production", VIRKI_HUB_PERIMETER_MODE: "native", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false",
    VIRKI_HUB_URL: "https://hub.biel.dev.br", VIRKI_HUB_HOSTNAME: "hub.biel.dev.br",
    VIRKI_CSRF_SIGNING_KEY: "11".repeat(32), VIRKI_AUDIT_HASH_SECRET: "22".repeat(32),
    VIRKI_RATE_LIMIT_HASH_SECRET: "33".repeat(32)
  }, async () => {
    const original = prisma.auditLog.create;
    let writes = 0;
    prisma.auditLog.create = (async () => { writes += 1; return {}; }) as unknown as typeof original;
    try {
      const responses = await Promise.all(Array.from({ length: 180 }, () => POST(new NextRequest(
        "https://hub.biel.dev.br/api/login", {
          method: "POST", headers: { host: "hub.biel.dev.br", origin: "https://untrusted.invalid" }
        }
      ))));
      assert.ok(responses.every((response) => response.status === 403), "every cross-origin request must remain denied");
      assert.ok(writes <= 120, `anonymous login audit writes must be capped, got ${writes}`);
      const afterAnonymousFlood = writes;
      await recordSecurityDenial(new Headers({ host: "hub.biel.dev.br" }), "admin-account-state", "csrf", {
        id: "verified-session", createdAt: new Date(), expiresAt: new Date(Date.now() + 60_000),
        authenticationMethods: ["pwd", "totp"],
        user: { id: "verified-admin", role: "ADMIN", email: "admin@example.invalid", displayName: "Admin" }
      });
      assert.equal(writes, afterAnonymousFlood + 1,
        "authenticated ADMIN denial audit must not inherit the anonymous flood budget");
      await recordSecurityDenial(new Headers({ host: "hub.biel.dev.br", origin: "https://untrusted.invalid" }), "admin-account-state", "csrf");
      assert.equal(writes, afterAnonymousFlood + 2,
        "a protected ADMIN Origin denial before session lookup must not be sampled by the public login budget");
      await recordSecurityDenial(new Headers({ host: "hub.biel.dev.br", origin: "https://untrusted.invalid" }), "account-recovery-approve", "csrf");
      assert.equal(writes, afterAnonymousFlood + 3,
        "ADMIN recovery approval must not be sampled by public login budget");
      await recordSecurityDenial(new Headers({ host: "portal.biel.dev.br" }), "portal-origin", "csrf");
      assert.equal(writes, afterAnonymousFlood + 4,
        "the USER portal's existing audit behavior must remain unchanged");
    } finally {
      prisma.auditLog.create = original;
    }
  });
});
