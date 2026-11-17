import { assertStagingMfaRuntimeIdentity, StagingMfaBootstrapError } from "./staging-mfa-bootstrap-guard.mjs";

/**
 * Read-only probe of the local loopback DB session supplied by a protected
 * operator. This does NOT attest a deployed Hub PID, Tunnel, PG system ID,
 * SMTP provider or the owner's physical TOTP.
 */
export async function probeStagingMfaLocalDatabase(prisma, expected) {
  const identity = await prisma.$queryRaw`
    SELECT current_database() AS "database",
      current_user AS "role",
      session_user AS "sessionRole",
      current_setting('server_version_num')::integer AS "pgVersion",
      inet_server_addr()::text AS "host",
      inet_server_port()::integer AS "port",
      pg_get_userbyid(database.datdba) AS "owner",
      EXISTS(
        SELECT 1 FROM pg_roles
        WHERE rolname = 'virki_migrator'
          AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
          AND NOT rolcreaterole AND NOT rolbypassrls
      ) AS "migratorPresent",
      (
        has_database_privilege(current_user, current_database(), 'CREATE')
        OR has_schema_privilege(current_user, 'public', 'CREATE')
      ) AS "runtimeCanCreate",
      (
        CASE WHEN to_regclass('public."_prisma_migrations"') IS NULL
        THEN FALSE
        ELSE NOT has_table_privilege(current_user, 'public."_prisma_migrations"', 'SELECT')
        END
      ) AS "migrationLedgerRestricted",
      (
        to_regclass('public."User"') IS NOT NULL
        AND to_regclass('public."Session"') IS NOT NULL
        AND to_regclass('public."TotpFactor"') IS NOT NULL
        AND to_regclass('public."AuditLog"') IS NOT NULL
        AND to_regclass('public."EmailOutboxMessage"') IS NOT NULL
        AND to_regclass('public."DeviceChallenge"') IS NOT NULL
      ) AS "schemaReady"
    FROM pg_database AS database
    WHERE database.datname = current_database()
  `;
  if (!Array.isArray(identity) || identity.length !== 1) throw new StagingMfaBootstrapError();
  assertStagingMfaRuntimeIdentity(identity[0], expected);
  if (identity[0].sessionRole !== "virki_runtime" ||
      !Number.isInteger(identity[0].pgVersion) ||
      identity[0].pgVersion < 180000 || identity[0].pgVersion >= 190000) {
    throw new StagingMfaBootstrapError();
  }

  // Only COUNT queries: never fetch PII, token or recovery material.
  // This checks SELECT availability only, not INSERT/UPDATE/DELETE grants.
  const counts = await Promise.all([
    prisma.user.count(),
    prisma.session.count(),
    prisma.auditLog.count(),
    prisma.emailOutboxMessage.count()
  ]);
  if (counts.some((count) => !Number.isSafeInteger(count) || count < 0) ||
      counts[0] !== 0 || counts[1] !== 0) {
    // A possibly initialized database requires manual reconciliation.
    throw new StagingMfaBootstrapError();
  }
  return true;
}
