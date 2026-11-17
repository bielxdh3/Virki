import "next/dist/server/node-environment-baseline";
import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import test from "node:test";
import React from "react";
import { prisma } from "@virki/database";
import { hashPassword, hashSessionToken, SESSION_COOKIE_NAME } from "@virki/auth";
import { POST } from "./route";
import { shouldBoundNativePasskeyDenial } from "../../../lib/native-passkey-denial";

test("native ADMIN passkey audit selection budgets only unverified actors", () => {
  assert.equal(shouldBoundNativePasskeyDenial(true, "hub", undefined, true), true);
  assert.equal(shouldBoundNativePasskeyDenial(true, "hub", "USER", true), true);
  assert.equal(shouldBoundNativePasskeyDenial(true, "hub", "ADMIN", true), false,
    "a verified ADMIN must always use the full audit writer");
  assert.equal(shouldBoundNativePasskeyDenial(true, "hub", undefined, false), false,
    "legacy access must keep the original audit path");
  assert.equal(shouldBoundNativePasskeyDenial(false, "portal", "USER", true), false,
    "USER Portal must keep the original audit path");
});

test("native ADMIN passkey Origin flood is bounded while a verified ADMIN denial remains audited", async () => {
  const keys = ["NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
    "VIRKI_HUB_HOSTNAME", "VIRKI_PASSKEYS_ENABLED", "VIRKI_ADMIN_PASSKEYS_ENABLED",
    "VIRKI_AUDIT_HASH_SECRET"] as const;
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const originalAudit = prisma.auditLog.create;
  const originalLookup = prisma.session.findUnique;
  const validToken = "A".repeat(43);
  const userToken = "B".repeat(43);
  let writes = 0;
  const audits: Record<string, unknown>[] = [];
  try {
    Object.assign(process.env, {
      NODE_ENV: "production", VIRKI_HUB_PERIMETER_MODE: "native",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "false", VIRKI_HUB_HOSTNAME: "hub.biel.dev.br",
      VIRKI_PASSKEYS_ENABLED: "true", VIRKI_ADMIN_PASSKEYS_ENABLED: "true",
      VIRKI_AUDIT_HASH_SECRET: "22".repeat(32)
    });
    prisma.auditLog.create = (async (input: { data: Record<string, unknown> }) => {
      writes += 1;
      audits.push(input.data);
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
          role: admin ? "ADMIN" : "USER", email: "actor@example.invalid",
          displayName: "Actor", isActive: true, accountStatus: "ACTIVE" }
      };
    }) as unknown as typeof originalLookup;
    const request = (cookie?: string) => POST(new Request("https://hub.biel.dev.br/api/passkeys", {
      method: "POST", headers: {
        host: "hub.biel.dev.br", origin: "https://untrusted.invalid",
        "content-type": "application/json",
        ...(cookie ? { cookie: `${SESSION_COOKIE_NAME}=${cookie}` } : {})
      }, body: JSON.stringify({ action: "admin-register-options" })
    }));
    const crossRoleResponses = await Promise.all(Array.from({ length: 180 }, () => request(userToken)));
    assert.ok(crossRoleResponses.every((response) => response.status === 403));
    assert.ok(writes <= 120, `valid USER session cannot bypass native ADMIN passkey audit budget, got ${writes}`);
    const responses = await Promise.all(Array.from({ length: 180 }, () => request()));
    assert.ok(responses.every((response) => response.status === 403), "native ADMIN passkeys should reject every hostile Origin");
    assert.ok(writes <= 120, `native ADMIN passkey anonymous audit writes must be bounded, got ${writes}`);
    const afterFlood = writes;
    assert.equal((await request(validToken)).status, 403);
    assert.equal(writes, afterFlood + 1, "verified ADMIN Origin denial must remain audited after anonymous flood");
    assert.equal(audits.at(-1)?.actorUserId, "verified-admin");
    assert.equal(audits.at(-1)?.actorRole, "ADMIN");
  } finally {
    prisma.auditLog.create = originalAudit;
    prisma.session.findUnique = originalLookup;
    for (const key of keys) {
      const value = before[key];
      if (value === undefined) delete process.env[key];
      else Reflect.set(process.env, key, value);
    }
  }
});

test("same-Origin native ADMIN passkey proof rejection cannot generate unlimited anonymous audit writes", async () => {
  const keys = ["NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
    "VIRKI_HUB_HOSTNAME", "VIRKI_PASSKEYS_ENABLED", "VIRKI_ADMIN_PASSKEYS_ENABLED",
    "VIRKI_AUDIT_HASH_SECRET"] as const;
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const originalAudit = prisma.auditLog.create;
  const audits: Record<string, unknown>[] = [];
  try {
    Reflect.set(process.env, "NODE_ENV", "production");
    Object.assign(process.env, {
      VIRKI_HUB_PERIMETER_MODE: "native", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false",
      VIRKI_HUB_HOSTNAME: "hub.biel.dev.br", VIRKI_PASSKEYS_ENABLED: "true",
      VIRKI_ADMIN_PASSKEYS_ENABLED: "true", VIRKI_AUDIT_HASH_SECRET: "22".repeat(32)
    });
    prisma.auditLog.create = (async (input: { data: Record<string, unknown> }) => {
      audits.push(input.data);
      return {};
    }) as unknown as typeof originalAudit;
    const post = (cookie?: string) => POST(new Request("https://hub.biel.dev.br/api/passkeys", {
      method: "POST",
      body: JSON.stringify({ action: "admin-register-options", csrfToken: "invalid" }),
      headers: { host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br",
        "content-type": "application/json",
        ...(cookie ? { cookie: `${SESSION_COOKIE_NAME}=${cookie}` } : {}) }
    }));
    const anonymous = await Promise.all(Array.from({ length: 180 }, () => post()));
    assert.ok(anonymous.every((response) => response.status === 403));
    assert.ok(audits.length <= 120, `native anonymous passkey failures caused ${audits.length} AuditLog writes`);
  } finally {
    prisma.auditLog.create = originalAudit;
    for (const key of keys) {
      const value = before[key];
      if (value === undefined) delete process.env[key];
      else Reflect.set(process.env, key, value);
    }
  }
});

test("native ADMIN passkey with forged well-shaped cookie and bad CSRF must not start unlimited session SELECTs", async () => {
  Object.assign(globalThis, { AsyncLocalStorage, React });
  const { workAsyncStorage } = await import("next/dist/server/app-render/work-async-storage.external");
  const { workUnitAsyncStorage } = await import("next/dist/server/app-render/work-unit-async-storage.external");
  const { createRequestStoreForAPI } = await import("next/dist/server/async-storage/request-store");
  const { NextRequest } = await import("next/server");
  const keys = ["NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
    "VIRKI_HUB_HOSTNAME", "VIRKI_PASSKEYS_ENABLED", "VIRKI_ADMIN_PASSKEYS_ENABLED",
    "VIRKI_AUDIT_HASH_SECRET"] as const;
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const originalLookup = prisma.session.findUnique;
  const originalAudit = prisma.auditLog.create;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let lookups = 0;
  let writes = 0;
  try {
    Reflect.set(process.env, "NODE_ENV", "production");
    Object.assign(process.env, {
      VIRKI_HUB_PERIMETER_MODE: "native", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false",
      VIRKI_HUB_HOSTNAME: "hub.biel.dev.br", VIRKI_PASSKEYS_ENABLED: "true",
      VIRKI_ADMIN_PASSKEYS_ENABLED: "true", VIRKI_AUDIT_HASH_SECRET: "22".repeat(32)
    });
    prisma.session.findUnique = (async () => {
      lookups += 1;
      await gate;
      return null;
    }) as unknown as typeof originalLookup;
    prisma.auditLog.create = (async () => {
      writes += 1;
      return {};
    }) as unknown as typeof originalAudit;
    const invoke = async () => {
      const pathname = "/api/passkeys";
      const request = new NextRequest("https://hub.biel.dev.br/api/passkeys", {
        method: "POST",
        headers: { host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br",
          "content-type": "application/json", cookie: `${SESSION_COOKIE_NAME}=${"Z".repeat(43)}` },
        body: JSON.stringify({ action: "admin-rename", csrfToken: "invalid" })
      });
      const store = createRequestStoreForAPI(request, { pathname },
        { tags: [], expirationsByCacheKind: new Map() } as never, undefined, undefined, undefined);
      return workAsyncStorage.run({ route: pathname, incrementalCache: {}, cacheLifeProfiles: {} } as never,
        () => workUnitAsyncStorage.run(store, () => POST(request)));
    };
    // Register all rejections immediately so an early infrastructure error
    // cannot leave 30 unhandled promises while the test checks the SELECT cap.
    const requests = Array.from({ length: 30 }, () => invoke().then(
      response => ({ response, error: null as unknown }),
      error => ({ response: null as Response | null, error })
    ));
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.ok(lookups <= 8, `invalid-CSRF passkey traffic spawned ${lookups} concurrent session SELECTs`);
    release();
    const responses = await Promise.all(requests);
    for (const result of responses) if (result.error) throw result.error;
    assert.ok(responses.every((result) => result.response?.status === 403), "every forged cookie must remain denied");
    assert.ok(writes <= 120, `native passkey denials must stay inside the local audit budget, got ${writes}`);
  } finally {
    release();
    prisma.session.findUnique = originalLookup;
    prisma.auditLog.create = originalAudit;
    for (const key of keys) {
      const value = before[key];
      if (value === undefined) delete process.env[key];
      else Reflect.set(process.env, key, value);
    }
  }
});

test("ADMIN passkey login remains blocked and forged portal-host enrollment cannot reach hub", async (t) => {
  const oldUser = process.env.VIRKI_PASSKEYS_ENABLED;
  const oldAdmin = process.env.VIRKI_ADMIN_PASSKEYS_ENABLED;
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "true";
  t.after(() => {
    if (oldUser === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED; else process.env.VIRKI_PASSKEYS_ENABLED = oldUser;
    if (oldAdmin === undefined) delete process.env.VIRKI_ADMIN_PASSKEYS_ENABLED; else process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = oldAdmin;
  });
  async function request(host: string, action: string, origin = `https://${host}`) {
    return POST(new Request(`https://${host}/api/passkeys`, {
      method: "POST", headers: { host, origin, "content-type": "application/json" }, body: JSON.stringify({ action })
    }));
  }
  assert.equal((await request("hub.biel.dev.br", "login-options")).status, 404, "portal login action cannot run on hub");
  assert.equal((await request("hub.biel.dev.br", "login-verify")).status, 404, "hub never issues passkey login sessions");
  assert.equal((await request("portal.biel.dev.br", "admin-register-options")).status, 404, "portal cannot enroll ADMIN RP");
  assert.equal((await request("evil.hub.biel.dev.br", "admin-register-options")).status, 404, "spoofed hub host rejected");
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "false";
  assert.equal((await request("hub.biel.dev.br", "admin-register-options")).status, 404, "ADMIN flag closed before session/database access");
});

test("staging RP opt-in routes only the exact configured portal host, never production or a spoof", async (t) => {
  const keys = [
    "NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "VIRKI_STAGING_PASSKEY_RP_ENABLED",
    "VIRKI_PORTAL_HOSTNAME", "VIRKI_HUB_HOSTNAME",
    "VIRKI_PASSKEYS_ENABLED", "VIRKI_ADMIN_PASSKEYS_ENABLED"
  ] as const;
  const before = Object.fromEntries(keys.map(key => [key, process.env[key]])) as Record<typeof keys[number], string | undefined>;
  t.after(() => {
    for (const key of keys) {
      const value = before[key];
      if (value === undefined) delete process.env[key];
      else Reflect.set(process.env, key, value);
    }
  });
  const portal = "stage-portal.example.invalid";
  const hub = "stage-hub.example.invalid";
  Object.assign(process.env, {
    NODE_ENV: "production",
    VIRKI_HUB_PERIMETER_MODE: "native",
    VIRKI_STAGING_PASSKEY_RP_ENABLED: "true",
    VIRKI_PORTAL_HOSTNAME: portal,
    VIRKI_HUB_HOSTNAME: hub,
    VIRKI_PASSKEYS_ENABLED: "true",
    VIRKI_ADMIN_PASSKEYS_ENABLED: "true"
  });
  const probe = (host: string, action = "unsupported") => POST(new Request(`https://${host}/api/passkeys`, {
    method: "POST",
    headers: { host, origin: `https://${host}`, "content-type": "application/json" },
    body: JSON.stringify({ action })
  }));

  assert.equal((await probe(portal)).status, 400, "the exact staging portal reaches the unrecognized-action guard");
  assert.equal((await probe("portal.biel.dev.br")).status, 404, "production passkeys cannot be reached from staging");
  assert.equal((await probe(`evil.${portal}`)).status, 404, "subdomain spoofing never inherits a staging RP");
  assert.equal((await probe(hub)).status, 404, "USER RP cannot become the ADMIN host");
  assert.equal((await probe(portal, "admin-unsupported")).status, 404, "ADMIN RP cannot become the USER host");

  process.env.VIRKI_STAGING_PASSKEY_RP_ENABLED = "false";
  assert.equal((await probe(portal)).status, 404, "changing a hostname alone must never enable staging passkeys");
});

test("rejected passkey login and management ceremonies generate sanitized audit events outside failed transactions", async (t) => {
  const beforeFlag = process.env.VIRKI_PASSKEYS_ENABLED;
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  t.after(() => {
    if (beforeFlag === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED;
    else process.env.VIRKI_PASSKEYS_ENABLED = beforeFlag;
  });

  const events: Array<Record<string, unknown>> = [];
  function replaceMethod(target: object, name: string, method: unknown) {
    const original = Reflect.get(target, name);
    Object.defineProperty(target, name, { value: method, configurable: true, writable: true });
    t.after(() => Object.defineProperty(target, name, { value: original, configurable: true, writable: true }));
  }
  replaceMethod(prisma.auditLog, "create", async (input: { data: Record<string, unknown> }) => { events.push(input.data); return {}; });
  replaceMethod(prisma, "$transaction", async (callback: (tx: unknown) => Promise<unknown>) => callback({
    $queryRaw: async () => [],
    loginRateLimit: { findUnique: async () => null, create: async () => ({}) }
  }));
  const passwordHash = await hashPassword("correct-password");
  replaceMethod(prisma.user, "findUnique", async () => ({
    id: "target-user", email: "private@example.invalid", displayName: "Test User", role: "USER", isActive: true,
    accountStatus: "ACTIVE", passwordHash
  }));

  async function rejected(action: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}) {
    const response = await POST(new Request("https://portal.biel.dev.br/api/passkeys", {
      method: "POST", headers: {
        host: "portal.biel.dev.br", origin: "https://portal.biel.dev.br", "content-type": "application/json",
        "x-virki-audit-request-id": "35d3f69b-8c6e-4840-ae54-e1bd573c2926", ...headers
      }, body: JSON.stringify({ action, ...extra })
    }));
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: "Authentication rejected or service unavailable" });
  }

  await rejected("login-options", { email: "private@example.invalid", password: "wrong-password" }, { "cf-connecting-ip": "203.0.113.15" });
  await rejected("login-verify", { response: { id: "private-credential-id", response: { clientDataJSON: "invalid-assertion" } } });
  await rejected("rename", { id: "private-credential-id", password: "wrong-password", csrfToken: "invalid-csrf" });

  assert.deepEqual(events.map(item => [item.eventType, item.result]), [
    ["AUTH_LOGIN_FAILURE", "FAILURE"], ["AUTH_LOGIN_FAILURE", "FAILURE"], ["SECURITY_PROOF_REJECTED", "DENIED"]
  ]);
  assert.ok(events.every(item => item.resource === "identity.passkey"));
  assert.ok(events.every(item => item.requestId === "35d3f69b-8c6e-4840-ae54-e1bd573c2926"));
  assert.doesNotMatch(JSON.stringify(events), /private@example|wrong-password|private-credential-id|invalid-assertion|invalid-csrf/u);

  const originResponse = await POST(new Request("https://portal.biel.dev.br/api/passkeys", {
    method: "POST", headers: {
      host: "portal.biel.dev.br", origin: "https://attacker.invalid", "content-type": "application/json"
    }, body: JSON.stringify({ action: "login-options", email: "private@example.invalid", password: "wrong-password" })
  }));
  assert.equal(originResponse.status, 403);
  assert.deepEqual(await originResponse.json(), { error: "Rejected" });
  assert.equal(events.length, 4, "cross-origin passkey attempts must not evade the audit trail");
  assert.equal(events[3].eventType, "CSRF_DENIED");
  assert.equal(events[3].result, "DENIED");
  assert.doesNotMatch(JSON.stringify(events[3]), /private@example|wrong-password/u);
});
