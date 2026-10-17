import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const recovery = readFileSync(new URL("../app/recover/actions.ts", import.meta.url), "utf8");
const accountSecurity = readFileSync(new URL("../app/account/security/actions.ts", import.meta.url), "utf8");
const admin = readFileSync(new URL("../app/admin/actions.ts", import.meta.url), "utf8");

function guardBranch(source: string, start: string, end: string): string {
  const startAt = source.indexOf(start);
  assert.notEqual(startAt, -1, `guard found: ${start}`);
  const endAt = source.indexOf(end, startAt);
  assert.notEqual(endAt, -1, `guard boundary found: ${end}`);
  return source.slice(startAt, endAt);
}

test("recovery approval audits origin, CSRF, Access/surface, and missing or non-ADMIN session exits", () => {
  const approval = guardBranch(recovery, "export async function approveRecoveryAction", "async function requireRecoveryAccess");
  assert.match(approval, /hasSameOrigin[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-approve", "csrf"\)[\s\S]*redirect\("\/login"\)/u);
  assert.match(approval, /getSurface[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-approve", "role"\)[\s\S]*redirect\("\/login"\)/u);
  assert.match(approval, /!session \|\| session\.user\.role !== "ADMIN"[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-approve", "role", session\)[\s\S]*redirect\("\/login"\)/u);
});

test("account security mutation guard audits origin, Access/surface, CSRF, and role exits", () => {
  const guard = guardBranch(accountSecurity, "async function requireAccountMutation", "function read(");
  assert.match(guard, /!hasSameOrigin[\s\S]*recordSecurityDenial\(requestHeaders, source, "csrf"\)[\s\S]*redirect\("\/login"\)/u);
  assert.match(guard, /surface === "unknown"[\s\S]*recordSecurityDenial\(requestHeaders, source, "role"\)[\s\S]*redirect\("\/login"\)/u);
  assert.match(guard, /validateSessionCsrfToken[\s\S]*recordSecurityDenial\(requestHeaders, source, "csrf"\)[\s\S]*redirect\("\/login"\)/u);
  assert.match(guard, /!session[\s\S]*recordSecurityDenial\(requestHeaders, source, "role"\)[\s\S]*redirect\("\/login"\)/u);
});

test("successful connection mutation writers persist verified ADMIN role and session reference", () => {
  const writes = admin.match(/writeAuditLogInTransaction\(transaction, \{ eventType: "PROJECT_CONNECTION_[A-Z]+"[\s\S]*?\}\);/gu) ?? [];
  assert.equal(writes.length, 4);
  for (const write of writes) {
    assert.match(write, /actorRole: "ADMIN"/u);
    assert.match(write, /sessionRef: hashAuditSessionReference\(actor\.id\)/u);
  }
  assert.match(admin, /actorRole: "ADMIN",\s*sessionRef: hashAuditSessionReference\(actor\.id\)/u);
});
