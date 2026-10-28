import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const recovery = readFileSync(new URL("../app/recover/actions.ts", import.meta.url), "utf8");
const accountSecurity = readFileSync(new URL("../app/account/security/actions.ts", import.meta.url), "utf8");
const adminMutation = readFileSync(new URL("./admin-mutation.ts", import.meta.url), "utf8");
const logout = readFileSync(new URL("../app/api/logout/route.ts", import.meta.url), "utf8");
const forbiddenPage = readFileSync(new URL("../app/forbidden.tsx", import.meta.url), "utf8");
const admin = readFileSync(new URL("../app/admin/actions.ts", import.meta.url), "utf8");

function guardBranch(source: string, start: string, end: string): string {
  const startAt = source.indexOf(start);
  assert.notEqual(startAt, -1, `guard found: ${start}`);
  const endAt = source.indexOf(end, startAt);
  assert.notEqual(endAt, -1, `guard boundary found: ${end}`);
  return source.slice(startAt, endAt);
}

test("recovery approval checks Hub/Access before origin, CSRF, and session authorization", () => {
  const approval = guardBranch(recovery, "export async function approveRecoveryAction", "async function requireRecoveryAccess");
  assertInOrder(approval, ["getSurface(requestHeaders)", "validateHubCloudflareAccess(requestHeaders, \"account-recovery-approve\")", "hasSameOrigin(requestHeaders)", "validateSessionCsrfTokenFor(", "recordSessionCsrfDenial(", "getCurrentSession()"]);
  assert.match(approval, /surface !== "hub"[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-approve", "role"\)[\s\S]*forbidden\(\)/u);
  assert.match(approval, /!hasSameOrigin\(requestHeaders\)[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-approve", "csrf"\)[\s\S]*forbidden\(\)/u);
  assert.match(approval, /validateSessionCsrfTokenFor\([\s\S]*recordSessionCsrfDenial\(requestHeaders, "account-recovery-approve"[\s\S]*forbidden\(\)/u);
  assert.match(approval, /!session \|\| session\.user\.role !== "ADMIN"[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-approve", "role", session\)[\s\S]*forbidden\(\)/u);
  assert.match(approval, /redirect\("\/admin\/security\?status=recovery#admin-content"\)/u);
});

test("Hub recovery actions check Cloudflare Access before origin and anonymous CSRF", () => {
  const guard = guardBranch(recovery, "async function requireRecoveryAccess", "function read(");
  assertInOrder(guard, [
    "getSurface(requestHeaders)",
    "expectedSurface === \"hub\" && !isCloudflareAccessAllowed",
    "validateHubCloudflareAccess(requestHeaders, \"account-recovery\")",
    "hasSameOrigin(requestHeaders)",
    "validateCsrfToken("
  ]);
  const surfaceRejection = guard.indexOf("if (!recoverySurfaceAllowed)");
  const hubAccessCheck = guard.indexOf("expectedSurface === \"hub\"");
  assert.ok(surfaceRejection !== -1 && surfaceRejection < hubAccessCheck, "disallowed recovery surfaces must be rejected before Hub Access and request CSRF checks");
  assert.match(guard, /if \(!recoverySurfaceAllowed\)[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-access", "role"\)[\s\S]*forbidden\(\)/u);
  assert.match(guard, /if \(expectedSurface === "hub" && !isCloudflareAccessAllowed[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-access", "role"\)[\s\S]*forbidden\(\)/u);
  assert.match(guard, /if \(!hasSameOrigin\(requestHeaders\)[\s\S]*recordSecurityDenial\(requestHeaders, "account-recovery-access", "csrf"\)[\s\S]*forbidden\(\)/u);
});

test("account security mutation guard checks surface/Access, origin, CSRF, and session/role in order", () => {
  const guard = guardBranch(accountSecurity, "async function requireAccountMutation", "function read(");
  assertInOrder(guard, ["getSurface(requestHeaders)", "validateHubCloudflareAccess(requestHeaders, source)", "hasSameOrigin(requestHeaders)", "validateSessionCsrfTokenFor(", "recordSessionCsrfDenial(", "getCurrentSession()"]);
  assert.match(guard, /surface === "unknown"[\s\S]*recordSecurityDenial\(requestHeaders, source, "role"\)[\s\S]*forbidden\(\)/u);
  assert.match(guard, /!hasSameOrigin\(requestHeaders\)[\s\S]*recordSecurityDenial\(requestHeaders, source, "csrf"\)[\s\S]*forbidden\(\)/u);
  assert.match(guard, /validateSessionCsrfTokenFor\([\s\S]*recordSessionCsrfDenial\(requestHeaders, source[\s\S]*forbidden\(\)/u);
  assert.match(guard, /!session[\s\S]*recordSecurityDenial\(requestHeaders, source, "role"\)[\s\S]*forbidden\(\)/u);
});

test("shared Hub admin mutation guard attributes CSRF denials only after Access and origin checks", () => {
  const guard = guardBranch(adminMutation, "export async function requireAdminMutation", "function getAdminCsrfScope");
  assertInOrder(guard, ["getSurface(requestHeaders)", "validateHubCloudflareAccess(requestHeaders, source)", "hasSameOrigin(requestHeaders)", "validateSessionCsrfTokenFor(", "recordSessionCsrfDenial(", "getCurrentSession()"]);
  assert.match(guard, /!hasSameOrigin\(requestHeaders\)[\s\S]*recordSecurityDenial\(requestHeaders, source, "csrf"\)[\s\S]*forbidden\(\)/u);
  assert.match(guard, /recordSessionCsrfDenial\(requestHeaders, source, sessionToken\)[\s\S]*forbidden\(\)/u);
  assert.match(guard, /!session \|\| !isAdminRole\(session\.user\.role\)[\s\S]*recordSecurityDenial\(requestHeaders, source, "role", session\)[\s\S]*forbidden\(\)/u);
});

test("logout CSRF failures use validated-cookie attribution and an explicit 403 response", () => {
  const denial = guardBranch(logout, "if (!csrfResult.valid)", "const currentSession");
  assert.match(denial, /recordSessionCsrfDenial\(request\.headers, "logout-csrf", sessionToken\)/u);
  assert.match(denial, /new NextResponse\("Forbidden", \{ status: 403 \}\)/u);
  assert.match(forbiddenPage, /<h1>Acesso negado<\/h1>/u);
  assert.doesNotMatch(forbiddenPage, /sess[aã]o administrativa/u);
});

function assertInOrder(source: string, markers: string[]): void {
  let previous = -1;
  for (const marker of markers) {
    const position = source.indexOf(marker);
    assert.notEqual(position, -1, `guard includes ${marker}`);
    assert.ok(position > previous, `guard orders ${marker} after its prior check`);
    previous = position;
  }
}

test("successful connection mutation writers persist verified ADMIN role and session reference", () => {
  const writes = admin.match(/writeAuditLogInTransaction\(transaction, \{ eventType: "PROJECT_CONNECTION_[A-Z]+"[\s\S]*?\}\);/gu) ?? [];
  assert.equal(writes.length, 4);
  for (const write of writes) {
    assert.match(write, /actorRole: "ADMIN"/u);
    assert.match(write, /sessionRef: hashAuditSessionReference\(actor\.id\)/u);
  }
  assert.match(admin, /actorRole: "ADMIN",\s*sessionRef: hashAuditSessionReference\(actor\.id\)/u);
});
