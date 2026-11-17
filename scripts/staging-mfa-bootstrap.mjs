#!/usr/bin/env node
/**
 * Attended first-ADMIN bootstrap for a disposable, already migrated MFA
 * staging database. Never changes production's first-admin bootstrap rules.
 *
 * The test owner must obtain the one-time credentials from the private file
 * on the staging operator's computer. No password or TOTP seed is printed.
 */
import { randomBytes } from "node:crypto";
import { existsSync, realpathSync, statfsSync, statSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertStagingMfaBootstrapEnvironment,
  assertStagingMfaRuntimeIdentity,
  isStagingDirectoryOutsideRepository,
  isNativeLinuxCredentialFilesystem,
  stagingCredentialSecurityRoot,
  StagingMfaBootstrapError
} from "./lib/staging-mfa-bootstrap-guard.mjs";
import { withPrivateMfaCredentialFile } from "./lib/staging-mfa-credential-file.mjs";

async function main() {
  const expected = assertStagingMfaBootstrapEnvironment(process.env);
  // Only the approved WSL/Linux Node 22 POSIX-metadata environment is supported.
  // Native Windows Node mode bits are not a reliable credential ACL proof.
  if (process.platform !== "linux" || Number(process.versions.node.split(".")[0]) !== 22 ||
      process.argv.length !== 2 ||
      !process.stdin.isTTY || !process.stdout.isTTY) {
    throw new StagingMfaBootstrapError();
  }

  const privateDir = process.env.VIRKI_STAGING_MFA_CREDENTIAL_DIR;
  if (!privateDir || !isAbsolute(privateDir)) throw new StagingMfaBootstrapError();
  const realDir = realpathSync(privateDir);
  const dirStat = statSync(realDir);
  const repo = realpathSync(resolve(fileURLToPath(new URL("..", import.meta.url))));
  const securityRoot = stagingCredentialSecurityRoot(repo);
  if (!dirStat.isDirectory() || (dirStat.mode & 0o077) !== 0 ||
      (process.getuid && dirStat.uid !== process.getuid()) ||
      !isNativeLinuxCredentialFilesystem(statfsSync(realDir).type) ||
      !isStagingDirectoryOutsideRepository(securityRoot, realDir)) {
    throw new StagingMfaBootstrapError();
  }
  const credentialPath = join(realDir, "mfa-admin-credentials.txt");
  if (existsSync(credentialPath)) throw new StagingMfaBootstrapError();

  // Validated context precedes importing code that can access the database.
  const { prisma } = await import("@virki/database");
  try {
    const rows = await prisma.$queryRaw`
      SELECT current_database() AS "database",
        current_user AS "role",
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
    if (!Array.isArray(rows) || rows.length !== 1) throw new StagingMfaBootstrapError();
    assertStagingMfaRuntimeIdentity(rows[0], expected);
    await Promise.all([prisma.user.count(), prisma.auditLog.count()]);

    const prompt = createInterface({ input: process.stdin, output: process.stdout });
    let confirmation;
    try {
      console.log("Disposable staging ADMIN only. Confirm the real test mailbox and approved SMTP before continuing.");
      console.log("Credentials are saved to a private file and are never displayed in the terminal.");
      confirmation = await prompt.question("Type CREATE-STAGING-ADMIN to continue: ");
    } finally {
      prompt.close();
    }
    if (confirmation !== "CREATE-STAGING-ADMIN") throw new StagingMfaBootstrapError();

    const password = randomBytes(36).toString("base64url");
    try {
      const text = [
        "Virki — disposable MFA staging ADMIN credentials",
        "URL: https://" + expected.hostname + "/login",
        "Email: " + expected.recipient,
        "Password: " + password,
        "First login verifies email; configure TOTP yourself at /account/security.",
        "Delete this credential file and retire the disposable database after testing."
      ].join("\n") + "\n";
      await withPrivateMfaCredentialFile(credentialPath, text, async () => {
        const { bootstrapFirstAdmin } = await import("../packages/auth/src/bootstrap-first-admin.ts");
        await bootstrapFirstAdmin({
          email: expected.recipient,
          displayName: "ADMIN descartável (staging MFA)",
          password
        });
      });
    } catch {
      throw new StagingMfaBootstrapError();
    }
    console.log("STAGING_MFA_ADMIN_CREATED: one-time credential stored in the operator's private directory.");
    console.log("Do not send the credential file via Git, chat, logs or issue comments.");
  } finally {
    await prisma.$disconnect();
  }
}

main().catch(() => {
  console.error("STAGING_MFA_BOOTSTRAP_NOT_COMPLETED");
  process.exitCode = 1;
});
