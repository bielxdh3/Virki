import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  AdministrationMutationError,
  AdministrativePasswordReuseError,
  ELEVATION_SCOPES,
  ELEVATION_SCOPE_ACTIONS,
  UI_ELEVATION_SCOPES,
  isElevationCeremonyOpen,
  requireSecurityElevationInTransaction,
  resolveElevationDuration
} from "./administration";

test("raw administrative expiry checks normalize timestamptz parameters to UTC for Prisma timestamp columns", () => {
  // Prisma persists DateTime as TIMESTAMP(3) without a time zone. Raw Date
  // parameters are timestamptz: a non-UTC PostgreSQL TimeZone otherwise
  // shifts expiration boundaries and can grant stale security elevation.
  const files = [
    ["./elevation-authorization.ts", 3],
    ["./administration.ts", 4]
  ] as const;
  for (const [file, expectedChecks] of files) {
    const source = readFileSync(new URL(file, import.meta.url), "utf8");
    const safeChecks = source.match(/"expiresAt"\s*>\s*\(\$\{(?:now|checkedAt)\} AT TIME ZONE 'UTC'\)/gu) ?? [];
    assert.equal(safeChecks.length, expectedChecks, `${file} must normalize every raw security expiry comparison`);
    assert.doesNotMatch(source, /"expiresAt"\s*>\s*\$\{(?:now|checkedAt)\}/u, "raw expiry checks must not depend on PostgreSQL server timezone");
  }
});

test("an elevation email code expires after ten minutes even when the elevation itself is long-lived", () => {
  const sentAt = new Date("2026-08-01T10:00:00.000Z");
  const manual = resolveElevationDuration({ kind: "MANUAL", confirmed: true }, sentAt);
  const day = resolveElevationDuration({ kind: "TIMED", minutes: 1440 }, sentAt);
  for (const { expiresAt } of [manual, day]) {
    const ceremony = { createdAt: sentAt, expiresAt };
    assert.equal(isElevationCeremonyOpen(ceremony, new Date("2026-08-01T10:09:59.000Z")), true);
    assert.equal(isElevationCeremonyOpen(ceremony, new Date("2026-08-01T10:10:00.000Z")), false);
    assert.equal(isElevationCeremonyOpen(ceremony, new Date("2026-08-02T09:00:00.000Z")), false);
  }
  assert.equal(isElevationCeremonyOpen({ createdAt: sentAt, expiresAt: new Date("2026-08-01T10:05:00.000Z") }, new Date("2026-08-01T10:06:00.000Z")), false);
});

test("elevation duration requires explicit bounded or confirmed manual mode", () => {
  const now = new Date("2026-08-01T10:00:00.000Z");
  assert.deepEqual(resolveElevationDuration({ kind: "TIMED", minutes: 60 }, now), { manualUntilRevoked: false, expiresAt: new Date("2026-08-01T11:00:00.000Z") });
  assert.equal(resolveElevationDuration({ kind: "MANUAL", confirmed: true }, now).manualUntilRevoked, true);
  assert.throws(() => resolveElevationDuration({ kind: "MANUAL", confirmed: false }, now));
  assert.throws(() => resolveElevationDuration({ kind: "TIMED", minutes: 30 as never }, now));
});

test("elevation scope map exposes only implemented UI actions", () => {
  assert.deepEqual(ELEVATION_SCOPES, [
    "ACCOUNT_STATE_CHANGE",
    "PROJECT_ACCESS_CHANGE",
    "PROJECT_CONNECTION_MANAGE",
    "ADMIN_CREDENTIAL_CHANGE",
    "ADMIN_RECOVERY_REGENERATE"
  ]);
  assert.deepEqual(UI_ELEVATION_SCOPES, ELEVATION_SCOPES);
  assert.equal(ELEVATION_SCOPE_ACTIONS.PROJECT_ACCESS_CHANGE.ui, true);
  assert.equal(ELEVATION_SCOPE_ACTIONS.PROJECT_CONNECTION_MANAGE.ui, true);
  assert.equal(ELEVATION_SCOPE_ACTIONS.ADMIN_CREDENTIAL_CHANGE.ui, true);
  assert.equal(ELEVATION_SCOPE_ACTIONS.ADMIN_RECOVERY_REGENERATE.ui, true);
});

test("administrative password reuse is a specific mutation rejection", () => {
  const error = new AdministrativePasswordReuseError();
  assert.ok(error instanceof AdministrationMutationError);
  assert.equal(error.name, "AdministrativePasswordReuseError");
});

test("TOTP recovery of the separate ADMIN credential revokes old passkeys without disabling login TOTP", () => {
  const source = readFileSync(new URL("./administration.ts", import.meta.url), "utf8");
  const start = source.indexOf("export async function recoverAdministrativeCredentialWithTotp(");
  const end = source.indexOf("/** Start a distinct ADMIN credential-recovery proof", start);
  assert.ok(start >= 0 && end > start, "expected isolated administrative TOTP recovery method");
  const method = source.slice(start, end);
  assert.match(method, /transaction\.passkeyCredential\.updateMany\(/u);
  assert.match(method, /where:\s*\{ userId: input\.actor\.id, revokedAt: null \}/u);
  assert.match(method, /data:\s*\{ revokedAt: checkedAt \}/u);
  assert.match(method, /transaction\.passkeyChallenge\.deleteMany\(/u);
  assert.doesNotMatch(method, /transaction\.totpFactor\.(?:deleteMany|updateMany)\([^\n]*status:\s*"REVOKED"/u);
});

test("all three separate ADMIN-credential recovery methods revoke old passkey proofs", () => {
  const source = readFileSync(new URL("./administration.ts", import.meta.url), "utf8");
  for (const [startName, endName] of [
    ["recoverAdministrativeCredential", "recoverAdministrativeCredentialWithTotp"],
    ["recoverAdministrativeCredentialWithTotp", "startAdministrativeEmailRecovery"],
    ["completeAdministrativeEmailRecovery", "createEmailElevationCeremony"]
  ]) {
    const start = source.indexOf(`export async function ${startName}(`);
    const end = source.indexOf(endName === "createEmailElevationCeremony" ? `async function ${endName}(` : `export async function ${endName}(`, start);
    assert.ok(start >= 0 && end > start, `${startName} source interval must exist`);
    const method = source.slice(start, end);
    assert.match(method, /transaction\.passkeyCredential\.updateMany\(/u, `${startName}: old passkeys must be revoked`);
    assert.match(method, /revokedAt:\s*null/u, `${startName}: only active passkeys should be affected`);
    assert.match(method, /transaction\.passkeyChallenge\.deleteMany\(/u, `${startName}: pending assertions must be invalidated`);
    assert.match(method, /transaction\.session\.updateMany\(/u, `${startName}: sibling sessions must be revoked`);
    assert.match(method, /revokeUserAuthenticationProofsInTransaction\(/u, `${startName}: trusted devices and pending challenges must be invalidated`);
    assert.match(method, /revokeUserOidcArtifactsInTransaction\(/u, `${startName}: OIDC artifacts must be invalidated`);
  }
});

for (const lockTarget of ["session", "elevation"] as const) test(`transactional elevation rechecks ${lockTarget} expiry after a lock wait`, async () => {
  const now = new Date();
  const expiresAt = new Date(Date.now() + 120);
  const sessionExpiresAt = lockTarget === "session" ? expiresAt : new Date(Date.now() + 60_000);
  const elevationExpiresAt = lockTarget === "elevation" ? expiresAt : new Date(Date.now() + 60_000);
  const waitUntilExpired = async () => {
    const remaining = expiresAt.getTime() - Date.now() + 10;
    if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  };
  const transaction = {
    $queryRaw: async (parts: TemplateStringsArray, ...values: unknown[]) => {
      const sql = parts.join("");
      if (sql.includes('FROM "User" WHERE "id"') && sql.includes("FOR UPDATE")) return [{ id: "admin-id" }];
      if (sql.includes('FROM "AdministrativeCredential"')) return [{ passwordHash: "fixture", keyVersion: 1, status: "ACTIVE", revokedAt: null }];
      if (sql.includes('FROM "User" u JOIN "Session"') && sql.includes("FOR UPDATE OF u, s")) {
        if (lockTarget === "session") await waitUntilExpired();
        return [{ id: "session" }]; // The SELECT predicate was evaluated before its row-lock wait.
      }
      if (sql.includes('FROM "User" u JOIN "Session"')) {
        const checkedAt = values.filter((value): value is Date => value instanceof Date).at(-1) ?? now;
        return sessionExpiresAt > checkedAt ? [{ id: "session" }] : [];
      }
      if (sql.includes('FROM "SecurityElevation"') && sql.includes("FOR UPDATE")) {
        if (lockTarget === "elevation") await waitUntilExpired();
        return [{ id: "elevation", credentialKeyVersion: 1 }]; // The SELECT predicate was evaluated before its row-lock wait.
      }
      if (sql.includes('FROM "SecurityElevation"')) {
        const checkedAt = values.filter((value): value is Date => value instanceof Date).at(-1) ?? now;
        return elevationExpiresAt > checkedAt ? [{ id: "elevation" }] : [];
      }
      throw new Error("Unexpected SQL in the elevation authorization test.");
    }
  };

  await assert.rejects(
    requireSecurityElevationInTransaction(transaction as never, "admin-id", "session-id", "ADMIN_RECOVERY_REGENERATE", now),
    AdministrationMutationError
  );
});

for (const credentialState of ["current", "rotated", "revoked", "missing-version"] as const) test(`transactional elevation checks ${credentialState} administrative credential`, async () => {
  const transaction = {
    $queryRaw: async (parts: TemplateStringsArray) => {
      const sql = parts.join("");
      if (sql.includes('FROM "User" WHERE "id"')) return [{ id: "admin-id" }];
      if (sql.includes('FROM "User" u JOIN "Session"')) return [{ id: "session-id" }];
      if (sql.includes('FROM "AdministrativeCredential"')) return [{ passwordHash: "fixture", keyVersion: credentialState === "rotated" ? 2 : 1, status: credentialState === "revoked" ? "REVOKED" : "ACTIVE", revokedAt: credentialState === "revoked" ? new Date() : null }];
      if (sql.includes('FROM "SecurityElevation"') && sql.includes("FOR UPDATE")) return [{ id: "elevation-id", credentialKeyVersion: credentialState === "missing-version" ? null : 1 }];
      if (sql.includes('FROM "SecurityElevation"')) return [{ id: "elevation-id" }];
      throw new Error(`Unexpected SQL: ${sql}`);
    }
  };
  const authorization = requireSecurityElevationInTransaction(transaction as never, "admin-id", "session-id", "ADMIN_RECOVERY_REGENERATE", new Date());
  if (credentialState === "current") await authorization;
  else await assert.rejects(authorization, AdministrationMutationError);
});
