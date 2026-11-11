import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// Source contracts for DB boundaries that cannot be executed without a
// disposable PostgreSQL migration. These do not establish runtime race proof.
const service = readFileSync(new URL("./recovery-email-rebind.ts", import.meta.url), "utf8");
const security = readFileSync(new URL("./security.ts", import.meta.url), "utf8");
const hub = readFileSync(new URL("../../../apps/hub/src/app/account/security/actions.ts", import.meta.url), "utf8");
const sql = readFileSync(new URL("../../database/prisma/migrations/20261109163000_recovery_email_rebind/migration.sql", import.meta.url), "utf8");

test("bootstrap recovery provenance is an exact unique FK bound in the consuming transaction", () => {
  assert.match(sql, /AccountRecoveryRequest_bootstrapSessionId_key/u);
  assert.match(sql, /FOREIGN KEY \("bootstrapSessionId"\) REFERENCES "Session"/u);
  assert.match(security, /bootstrapSessionId: null[\s\S]*bootstrapSessionId: bootstrap\.id/u);
  assert.match(service, /bootstrapSessionId: actor\.id/u);
  assert.doesNotMatch(service, /consumedAt:\s*session\.createdAt/u);
});

test("post-reset rebind rejects EMAIL-proven recovery and pre-reset replacement mailbox provenance", () => {
  assert.match(service, /purpose:\s*"RECOVERY"/u);
  assert.match(service, /NOT:\s*\{\s*recoveryProofs:\s*\{\s*has:\s*"EMAIL"/u);
  assert.match(service, /recoveryNewEmail:\s*null/u);
  assert.match(service, /recoveryNewEmailVerifiedAt:\s*null/u);
});

test("session, role and mailbox checks precede atomic one-winner claim with DB-clock expiry", () => {
  assert.match(service, /SELECT "id" FROM "Session"[\s\S]*"revokedAt" IS NULL[\s\S]*clock_timestamp\(\) AT TIME ZONE 'UTC'[\s\S]*FOR UPDATE/u);
  assert.match(service, /user\.email !== actor\.user\.email/u);
  assert.match(service, /request\.oldEmailHash !== hashEmailAddress/u);
  assert.match(service, /"consumedAt" IS NULL AND "revokedAt" IS NULL[\s\S]*"expiresAt" > \(clock_timestamp\(\) AT TIME ZONE 'UTC'\)/u);
  assert.match(service, /SET "consumedAt" = \(clock_timestamp\(\) AT TIME ZONE 'UTC'\)/u);
  assert.doesNotMatch(service, /(?:"expiresAt"\s*>|"createdAt"\s*[<>]=?|"consumedAt"\s*=)\s*clock_timestamp\(\)/u);
  assert.match(service, /if \(claimed !== 1\) throw ERROR/u);
  assert.match(service, /where: \{[\s\S]*email: user\.email, emailNormalized: user\.emailNormalized/u);
});

test("sensitive actions enforce same-origin, session-bound CSRF and recovery-only authentication", () => {
  assert.match(hub, /startRecoveryEmailRebindAction[\s\S]*requireAccountMutation/u);
  assert.match(hub, /confirmRecoveryEmailRebindAction[\s\S]*requireAccountMutation/u);
  assert.match(hub, /if \(!isRecoveryEmailRebindSession\(session\)\)/u);
  assert.match(hub, /!hasSameOrigin\(requestHeaders\)/u);
  assert.match(hub, /validateSessionCsrfTokenFor\(sessionToken/u);
  assert.match(service, /consumeRebindLimit\(actor, "verify", actor\.id\)/u);
  assert.match(service, /recipientEmail: newEmail/u);
});
