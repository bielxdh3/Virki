import assert from "node:assert/strict";
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
