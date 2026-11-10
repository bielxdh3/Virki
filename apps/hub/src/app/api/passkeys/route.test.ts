import assert from "node:assert/strict";
import test from "node:test";
import { prisma } from "@virki/database";
import { hashPassword } from "@virki/auth";
import { POST } from "./route";

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
