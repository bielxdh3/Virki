import assert from "node:assert/strict";
import test from "node:test";
import { prisma } from "@virki/database";
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
