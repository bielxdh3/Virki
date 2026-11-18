import assert from "node:assert/strict";
import test from "node:test";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { DEVICE_COOKIE_NAME } from "@virki/auth/security";
import { SESSION_COOKIE_NAME } from "@virki/auth";
import { prisma } from "@virki/database";
import { POST } from "./route";

test("native Hub invalid verification ceremony cannot amplify unbounded anonymous AuditLog writes", async () => {
  const keys = ["NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "VIRKI_HUB_URL", "VIRKI_HUB_HOSTNAME", "VIRKI_CSRF_SIGNING_KEY", "VIRKI_AUDIT_HASH_SECRET"] as const;
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const original = prisma.auditLog.create;
  const originalSessionLookup = prisma.session.findUnique;
  let writes = 0;
  try {
    Object.assign(process.env, {
      NODE_ENV: "production", VIRKI_HUB_PERIMETER_MODE: "native", VIRKI_HUB_URL: "https://hub.biel.dev.br",
      VIRKI_HUB_HOSTNAME: "hub.biel.dev.br", VIRKI_CSRF_SIGNING_KEY: "11".repeat(32),
      VIRKI_AUDIT_HASH_SECRET: "22".repeat(32)
    });
    prisma.auditLog.create = (async () => { writes++; return {}; }) as unknown as typeof original;
    const csrf = createCsrfToken({ scope: "login-verification" });
    const responses = await Promise.all(Array.from({ length: 180 }, () => {
      const form = new FormData();
      form.set(CSRF_FORM_FIELD_NAME, csrf);
      form.set("ceremony", "invalid-ceremony");
      form.set("factor", "email");
      form.set("code", "000000");
      return POST(new Request("https://hub.biel.dev.br/api/login/verify", {
        method: "POST", headers: {
          host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br",
          cookie: `${DEVICE_COOKIE_NAME}=plausible-device-token`
        }, body: form
      }));
    }));
    assert.ok(responses.every((response) => response.status === 303));
    assert.ok(writes <= 120, `invalid anonymous MFA verification may write at most 120 audits/minute/process; wrote ${writes}`);
    const afterFlood = writes;
    prisma.session.findUnique = (async () => ({
      id: "current-admin-session", createdAt: new Date(), expiresAt: new Date(Date.now() + 60_000),
      revokedAt: null, authenticationMethods: ["pwd", "otp", "mfa"],
      user: { id: "current-admin", email: "owner@example.invalid", displayName: "Admin",
        role: "ADMIN", isActive: true, accountStatus: "ACTIVE" }
    })) as unknown as typeof originalSessionLookup;
    const adminForm = new FormData();
    adminForm.set(CSRF_FORM_FIELD_NAME, csrf);
    adminForm.set("ceremony", "invalid-ceremony");
    adminForm.set("factor", "email");
    adminForm.set("code", "000000");
    const adminResponse = await POST(new Request("https://hub.biel.dev.br/api/login/verify", {
      method: "POST", headers: {
        host: "hub.biel.dev.br", origin: "https://hub.biel.dev.br",
        cookie: `${DEVICE_COOKIE_NAME}=plausible-device-token; ${SESSION_COOKIE_NAME}=${"a".repeat(43)}`
      }, body: adminForm
    }));
    assert.equal(adminResponse.status, 303);
    assert.equal(writes, afterFlood + 1, "genuine ADMIN sessions must bypass anonymous audit sampling");
  } finally {
    prisma.auditLog.create = original;
    prisma.session.findUnique = originalSessionLookup;
    for (const key of keys) {
      if (before[key] === undefined) delete process.env[key];
      else Reflect.set(process.env, key, before[key]);
    }
  }
});
