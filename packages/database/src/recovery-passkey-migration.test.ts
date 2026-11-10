import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("database admits owner-bound recovery WebAuthn ceremonies without weakening login or registration", () => {
  const migration = readFileSync(
    new URL("../prisma/migrations/20261109161500_recovery_passkey_challenge/migration.sql", import.meta.url),
    "utf8"
  );
  assert.match(migration, /"ceremony" IN \('REGISTRATION', 'AUTHENTICATION', 'RECOVERY'\)/u);
  assert.match(migration, /"ceremony" = 'REGISTRATION' AND "userId" IS NOT NULL AND "sessionId" IS NOT NULL/u);
  assert.match(migration, /"ceremony" = 'AUTHENTICATION' AND "sessionId" IS NULL/u);
  assert.match(migration, /"ceremony" = 'RECOVERY' AND "userId" IS NOT NULL AND "sessionId" IS NULL AND "proofHash" IS NOT NULL/u);
  assert.doesNotMatch(migration, /DROP TABLE|TRUNCATE|DELETE FROM/u);
});
