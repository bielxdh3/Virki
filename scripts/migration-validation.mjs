import assert from "node:assert/strict";
import { cp, mkdtemp, mkdir, readFile, rm, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { PrismaClient } from "@prisma/client";

const repositoryRoot = process.cwd();
const migrationsRoot = path.join(repositoryRoot, "packages", "database", "prisma", "migrations");
const transitionName = "20260922090000_total_identity_security_rebaseline";
const containerName = `bielos-migration-validation-${process.pid}`;
const databaseName = "bielos_migration_validation";
const databaseUser = "bielos_validation";
const databasePassword = "migration-validation-only";
let containerStarted = false;
let temporaryDirectory;
let client;

try {
  const legacyDirectories = (await readdir(migrationsRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name !== transitionName)
    .map((entry) => entry.name)
    .sort();
  assert.equal(legacyDirectories.length, 14, "Expected the production's fourteen applied migrations before transition.");

  runDocker([
    "run", "--detach", "--name", containerName, "--publish", "127.0.0.1::5432",
    "--env", `POSTGRES_DB=${databaseName}`, "--env", `POSTGRES_USER=${databaseUser}`,
    "--env", `POSTGRES_PASSWORD=${databasePassword}`,
    "--health-cmd", `pg_isready -U ${databaseUser} -d ${databaseName}`,
    "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "60",
    "postgres:17-alpine",
  ]);
  containerStarted = true;
  await waitForDatabase();
  const port = readPublishedPort();
  const databaseUrl = buildDatabaseUrl(port);

  temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "bielos-migration-validation-"));
  const temporaryPrismaDirectory = path.join(temporaryDirectory, "prisma");
  const temporaryMigrationsDirectory = path.join(temporaryPrismaDirectory, "migrations");
  await mkdir(temporaryMigrationsDirectory, { recursive: true });
  await writeFile(path.join(temporaryPrismaDirectory, "schema.prisma"), await readFile(path.join(repositoryRoot, "packages", "database", "prisma", "schema.prisma")));
  await cp(path.join(migrationsRoot, "migration_lock.toml"), path.join(temporaryMigrationsDirectory, "migration_lock.toml"));
  for (const migration of legacyDirectories) {
    await cp(path.join(migrationsRoot, migration), path.join(temporaryMigrationsDirectory, migration), { recursive: true });
  }

  await deployMigrations(path.join(temporaryPrismaDirectory, "schema.prisma"), databaseUrl);
  assert.equal(runSql("SELECT count(*) FROM \"_prisma_migrations\" WHERE \"finished_at\" IS NOT NULL AND \"rolled_back_at\" IS NULL"), "14");
  runSql(seedLegacyIdentity());

  await cp(path.join(migrationsRoot, transitionName), path.join(temporaryMigrationsDirectory, transitionName), { recursive: true });
  await deployMigrations(path.join(temporaryPrismaDirectory, "schema.prisma"), databaseUrl);
  assert.equal(runSql("SELECT count(*) FROM \"_prisma_migrations\" WHERE \"finished_at\" IS NOT NULL AND \"rolled_back_at\" IS NULL"), "15");

  client = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  await client.$connect();
  await verifyPreservedIdentity();
  await verifyRemovedProductSchema();
  await verifyMigrationStatus(path.join(temporaryPrismaDirectory, "schema.prisma"), databaseUrl);
} finally {
  await client?.$disconnect();
  if (containerStarted) spawnSync("docker", ["rm", "--force", "--volumes", containerName], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
  if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true });
}

async function verifyPreservedIdentity() {
  const admin = await client.user.findUnique({ where: { id: "validation-admin" } });
  const user = await client.user.findUnique({ where: { id: "validation-user" } });
  assert.equal(admin?.role, "ADMIN");
  assert.equal(admin?.passwordHash, "legacy-password-hash-admin");
  assert.equal(admin?.secondFactorMethod, "TOTP");
  assert.equal(user?.role, "USER");
  assert.equal(user?.passwordHash, "legacy-password-hash-user");

  const factor = await client.totpFactor.findUnique({ where: { userId: "validation-admin" } });
  assert.equal(factor?.secretCiphertext, "legacy-encrypted-totp-secret");
  assert.equal(factor?.status, "ACTIVE");
  assert.equal(await client.recoveryCode.count({ where: { userId: "validation-admin" } }), 1);
  assert.equal(await client.administrativeCredential.count({ where: { userId: "validation-admin" } }), 1);
  assert.equal(await client.administrativeRecoveryCode.count({ where: { userId: "validation-admin" } }), 1);

  const session = await client.session.findUnique({ where: { id: "validation-session" } });
  assert.ok(session?.revokedAt instanceof Date);
  assert.equal(await client.deviceChallenge.count(), 0);
  const trustedDevice = await client.trustedDevice.findUnique({ where: { id: "validation-device" } });
  assert.equal(trustedDevice?.status, "REVOKED");
  assert.equal(trustedDevice?.rememberedUntil, null);
  const elevation = await client.securityElevation.findUnique({ where: { id: "validation-elevation" } });
  assert.equal(elevation?.status, "REVOKED");

  assert.equal(await client.auditLog.count({ where: { eventType: "AUTH_LOGIN_SUCCESS" } }), 1);
  assert.equal(await client.auditLog.count({ where: { eventType: "MODULE_ACCESS_GRANTED" } }), 0);
  assert.equal(await client.emailOutboxMessage.count({ where: { id: "validation-auth-email" } }), 1);
  assert.equal(await client.emailOutboxMessage.count({ where: { id: "validation-legacy-email" } }), 0);
  assert.equal(await client.emailDeliveryAttempt.count({ where: { messageId: "validation-legacy-email" } }), 0);
}

async function verifyRemovedProductSchema() {
  const rows = await client.$queryRaw`
    SELECT
      to_regclass('"AccountApplication"') IS NULL AS intake_removed,
      to_regclass('"ModuleCatalog"') IS NULL AS modules_removed,
      to_regclass('"GymForgeParticipant"') IS NULL AS gymforge_removed,
      to_regclass('"Project"') IS NULL AS old_project_model_removed,
      to_regclass('"ProjectConnection"') IS NOT NULL AS connection_model_created,
      to_regclass('"OidcArtifact"') IS NOT NULL AS oidc_artifact_model_created
  `;
  assert.deepEqual(rows[0], {
    intake_removed: true,
    modules_removed: true,
    gymforge_removed: true,
    old_project_model_removed: true,
    connection_model_created: true,
    oidc_artifact_model_created: true,
  });
}

async function verifyMigrationStatus(schemaPath, databaseUrl) {
  const result = spawnSync(process.execPath, [prismaCliPath(), "migrate", "status", "--schema", schemaPath], {
    cwd: repositoryRoot,
    env: { ...process.env, DATABASE_URL: databaseUrl },
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("Validated migration history is not in sync.");
}

function deployMigrations(schemaPath, databaseUrl) {
  const result = spawnSync(process.execPath, [prismaCliPath(), "migrate", "deploy", "--schema", schemaPath], {
    cwd: repositoryRoot,
    env: { ...process.env, DATABASE_URL: databaseUrl },
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("Disposable production migration validation failed.");
}

function prismaCliPath() {
  return path.join(repositoryRoot, "node_modules", "prisma", "build", "index.js");
}

function runSql(sql) {
  const result = spawnSync("docker", ["exec", "-i", containerName, "psql", "-U", databaseUser, "-d", databaseName, "-At", "-v", "VERBOSITY=sqlstate", "-v", "ON_ERROR_STOP=1"], {
    input: sql,
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const diagnostic = `${result.stdout?.toString() ?? ""}\n${result.stderr?.toString() ?? ""}`;
    const sqlState = diagnostic.match(/ERROR:\s*([0-9A-Z]{5}):/u)?.[1];
    const category = /null value|not-null constraint/iu.test(diagnostic) ? "missing-required-fixture-field"
      : /foreign key/iu.test(diagnostic) ? "fixture-foreign-key"
        : /duplicate key|unique constraint/iu.test(diagnostic) ? "fixture-unique-key"
          : /invalid input value for enum/iu.test(diagnostic) ? "fixture-enum-value"
            : /does not exist/iu.test(diagnostic) ? "missing-schema-object"
              : result.error && "code" in result.error && typeof result.error.code === "string" ? result.error.code
                : "database-rejected-fixture";
    throw new Error(`Disposable migration validation SQL failed (${sqlState ?? category}).`);
  }
  return result.stdout.trim();
}

function seedLegacyIdentity() {
  return `
BEGIN;
INSERT INTO "User" ("id", "email", "emailNormalized", "displayName", "passwordHash", "role", "isActive", "accountStatus", "emailVerifiedAt", "secondFactorMethod", "createdAt", "updatedAt") VALUES
  ('validation-admin', 'admin@validation.invalid', 'admin@validation.invalid', 'Validation administrator', 'legacy-password-hash-admin', 'OWNER'::"UserRole", true, 'ACTIVE'::"AccountStatus", CURRENT_TIMESTAMP, 'TOTP'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-user', 'user@validation.invalid', 'user@validation.invalid', 'Validation user', 'legacy-password-hash-user', 'MEMBER'::"UserRole", true, 'ACTIVE'::"AccountStatus", CURRENT_TIMESTAMP, 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "TotpFactor" ("id", "userId", "secretCiphertext", "keyVersion", "status", "confirmedAt", "createdAt", "updatedAt") VALUES ('validation-totp', 'validation-admin', 'legacy-encrypted-totp-secret', 1, 'ACTIVE'::"SecurityFactorStatus", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "RecoveryCode" ("id", "userId", "codeHash") VALUES ('validation-recovery', 'validation-admin', 'legacy-recovery-code-hash');
INSERT INTO "AdministrativeCredential" ("id", "userId", "passwordHash", "status", "createdAt", "updatedAt") VALUES ('validation-admin-credential', 'validation-admin', 'legacy-admin-credential-hash', 'ACTIVE'::"AdministrativeCredentialStatus", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "AdministrativeRecoveryCode" ("id", "userId", "codeHash") VALUES ('validation-admin-recovery', 'validation-admin', 'legacy-admin-recovery-hash');
INSERT INTO "Session" ("id", "sessionKey", "userId", "tokenHash", "expiresAt", "createdAt", "updatedAt") VALUES ('validation-session', 'validation-session-key', 'validation-admin', 'legacy-session-token-hash', CURRENT_TIMESTAMP + INTERVAL '1 day', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "DeviceChallenge" ("id", "userId", "ceremonyId", "deviceIdHash", "codeHash", "expiresAt") VALUES ('validation-challenge', 'validation-admin', 'validation-ceremony', 'legacy-device-hash', 'legacy-challenge-hash', CURRENT_TIMESTAMP + INTERVAL '10 minutes');
INSERT INTO "TrustedDevice" ("id", "deviceKey", "userId", "deviceIdHash", "label", "status", "rememberedUntil", "strongVerifiedAt", "createdAt", "updatedAt") VALUES ('validation-device', 'validation-device-key', 'validation-admin', 'legacy-device-hash', 'Validation device', 'TRUSTED'::"TrustedDeviceStatus", CURRENT_TIMESTAMP + INTERVAL '30 days', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "SecurityElevation" ("id", "requestKey", "userId", "sessionId", "protocolVersion", "scope", "challengeHash", "status", "expiresAt", "createdAt", "updatedAt") VALUES ('validation-elevation', 'validation-elevation-key', 'validation-admin', 'validation-session', 1, 'ACCOUNT_STATE_CHANGE', 'legacy-challenge-hash', 'ACTIVE'::"SecurityElevationStatus", CURRENT_TIMESTAMP + INTERVAL '10 minutes', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "AuditLog" ("id", "eventType", "actorUserId", "result", "resource", "message", "metadata") VALUES
  ('validation-auth-audit', 'AUTH_LOGIN_SUCCESS', 'validation-admin', 'SUCCESS', 'auth.session', 'Authentication succeeded.', '{"test":true}'::jsonb),
  ('validation-legacy-audit', 'MODULE_ACCESS_GRANTED', 'validation-admin', 'SUCCESS', 'legacy.module', 'Legacy event.', '{"test":true}'::jsonb);
INSERT INTO "EmailOutboxMessage" ("id", "idempotencyKey", "kind", "recipientEmail", "locale", "payload", "createdAt", "updatedAt") VALUES
  ('validation-auth-email', 'validation-auth-email-key', 'PASSWORD_CHANGED'::"EmailMessageKind", 'admin@validation.invalid', 'en', '{"test":true}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-legacy-email', 'validation-legacy-email-key', 'APPLICATION_EMAIL_VERIFICATION'::"EmailMessageKind", 'user@validation.invalid', 'en', '{"test":true}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "EmailDeliveryAttempt" ("id", "messageId", "attempt", "status") VALUES ('validation-legacy-email-attempt', 'validation-legacy-email', 1, 'FAILED'::"DeliveryAttemptStatus");
COMMIT;
`;
}

async function waitForDatabase() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const result = spawnSync("docker", ["inspect", "--format", "{{.State.Health.Status}}", containerName], { encoding: "utf8", windowsHide: true, timeout: 10_000 });
    if (result.status === 0 && result.stdout.trim() === "healthy") return;
    await delay(1_000);
  }
  throw new Error("Disposable PostgreSQL did not become healthy.");
}

function readPublishedPort() {
  const result = spawnSync("docker", ["port", containerName, "5432/tcp"], { encoding: "utf8", windowsHide: true, timeout: 10_000 });
  const match = result.status === 0 ? result.stdout.match(/127\.0\.0\.1:(\d+)/u) : null;
  if (!match) throw new Error("Disposable PostgreSQL port is not loopback-bound.");
  return match[1];
}

function buildDatabaseUrl(port) {
  const url = new URL("postgresql://127.0.0.1");
  url.username = databaseUser;
  url.password = databasePassword;
  url.port = port;
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function runDocker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error("Disposable migration validation Docker command failed.");
}
