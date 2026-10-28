import assert from "node:assert/strict";
import test from "node:test";
import { hashAuditSessionReference, hashSessionToken, SESSION_COOKIE_NAME } from "@virki/auth";
import { prisma } from "@virki/database";
import * as auditDenial from "./audit-denial";
import { recordSecurityDenial } from "./audit-denial";

test("CSRF and role denial envelope contains verified pseudonyms and no request body/forwarded data", async () => {
  const original = prisma.auditLog.create;
  const data: Record<string, unknown>[] = [];
  prisma.auditLog.create = (async (input: { data: Record<string, unknown> }) => { data.push(input.data); return {}; }) as unknown as typeof original;
  try {
    await recordSecurityDenial(new Headers({ "x-virki-audit-request-id": "c2245041-0904-4fa1-a6a8-053df5241d90", "x-forwarded-for": "203.0.113.1", authorization: "Bearer synthetic", cookie: "synthetic" }), "admin-account-state", "csrf", { id: "session-1", createdAt: new Date(), expiresAt: new Date(), authenticationMethods: ["pwd"], user: { id: "user-1", role: "USER", email: "private@example.invalid", displayName: "Private" } });
    assert.equal(data[0].eventType, "CSRF_DENIED");
    assert.equal(data[0].result, "DENIED");
    assert.equal(data[0].actorRole, "USER");
    assert.match(String(data[0].sessionRef), /^[a-f0-9]{64}$/u);
    assert.equal(data[0].requestId, "c2245041-0904-4fa1-a6a8-053df5241d90");
    assert.doesNotMatch(JSON.stringify(data), /private@example|203\.0\.113|Bearer|synthetic|session-1/u);
  } finally { prisma.auditLog.create = original; }
});

test("CSRF denial attribution requires a live session lookup and skips missing cookies", async () => {
  type SessionCsrfDenialRecorder = (requestHeaders: Pick<Headers, "get">, source: string, sessionToken?: string) => Promise<void>;
  const recordSessionCsrfDenial = (auditDenial as unknown as { recordSessionCsrfDenial?: SessionCsrfDenialRecorder }).recordSessionCsrfDenial;
  assert.equal(typeof recordSessionCsrfDenial, "function");
  if (!recordSessionCsrfDenial) return;

  const originalAuditCreate = prisma.auditLog.create;
  const originalSessionLookup = prisma.session.findUnique;
  const auditRows: Record<string, unknown>[] = [];
  const validToken = "A".repeat(43);
  const unknownToken = "C".repeat(43);
  const expiredToken = "B".repeat(43);
  let sessionLookups = 0;

  prisma.auditLog.create = (async (input: { data: Record<string, unknown> }) => { auditRows.push(input.data); return {}; }) as unknown as typeof originalAuditCreate;
  prisma.session.findUnique = (async (input: { where: { tokenHash: string } }) => {
    sessionLookups += 1;
    if (input.where.tokenHash === hashSessionToken(validToken)) {
      return {
        id: "verified-session",
        createdAt: new Date("2026-01-01T00:00:00Z"),
        expiresAt: new Date(Date.now() + 60_000),
        revokedAt: null,
        authenticationMethods: ["pwd"],
        user: { id: "verified-user", email: "private@example.invalid", displayName: "Private", role: "ADMIN", isActive: true, accountStatus: "ACTIVE" }
      };
    }
    if (input.where.tokenHash === hashSessionToken(expiredToken)) {
      return {
        id: "expired-session",
        createdAt: new Date("2026-01-01T00:00:00Z"),
        expiresAt: new Date("2026-01-02T00:00:00Z"),
        revokedAt: null,
        authenticationMethods: ["pwd"],
        user: { id: "expired-user", email: "expired@example.invalid", displayName: "Expired", role: "USER", isActive: true, accountStatus: "ACTIVE" }
      };
    }
    return null;
  }) as unknown as typeof originalSessionLookup;

  try {
    const headers = new Headers({ cookie: `${SESSION_COOKIE_NAME}=${validToken}`, origin: "https://hub.example.invalid", host: "hub.example.invalid" });
    await recordSessionCsrfDenial(headers, "account-security", validToken);
    await recordSessionCsrfDenial(new Headers({ cookie: `${SESSION_COOKIE_NAME}=attacker-controlled`, origin: "https://hub.example.invalid", host: "hub.example.invalid" }), "account-security", "attacker-controlled");
    await recordSessionCsrfDenial(new Headers({ cookie: `${SESSION_COOKIE_NAME}=${unknownToken}`, origin: "https://hub.example.invalid", host: "hub.example.invalid" }), "account-security", unknownToken);
    await recordSessionCsrfDenial(new Headers({ origin: "https://hub.example.invalid", host: "hub.example.invalid" }), "account-security");
    await recordSessionCsrfDenial(new Headers({ cookie: `${SESSION_COOKIE_NAME}=${expiredToken}`, origin: "https://hub.example.invalid", host: "hub.example.invalid" }), "account-security", expiredToken);

    assert.equal(sessionLookups, 3);
    assert.equal(auditRows.length, 5);
    assert.equal(auditRows[0].eventType, "CSRF_DENIED");
    assert.equal(auditRows[0].actorUserId, "verified-user");
    assert.equal(auditRows[0].actorRole, "ADMIN");
    assert.equal(auditRows[0].sessionRef, hashAuditSessionReference("verified-session"));
    assert.equal(auditRows[1].actorUserId, undefined);
    assert.equal(auditRows[2].actorUserId, undefined);
    assert.equal(auditRows[3].actorUserId, undefined);
    assert.equal(auditRows[4].actorUserId, undefined);
    assert.doesNotMatch(JSON.stringify(auditRows), /A{43}|attacker-controlled|B{43}|C{43}|private@example|expired@example/u);
  } finally {
    prisma.auditLog.create = originalAuditCreate;
    prisma.session.findUnique = originalSessionLookup;
  }
});
