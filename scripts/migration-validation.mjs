import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdtemp, mkdir, readFile, rm, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { PrismaClient } from "@prisma/client";

const repositoryRoot = process.cwd();
const migrationsRoot = path.join(repositoryRoot, "packages", "database", "prisma", "migrations");
const baselineName = "0_init";
const transitionName = "20260922090000_total_identity_security_rebaseline";
const containerName = `virki-migration-validation-${process.pid}`;
const databaseName = "virki_migration_validation";
const databaseUser = "virki_validation";
const databasePassword = "migration-validation-only";
let containerStarted = false;
let temporaryDirectory;
let client;
let validationError;

try {
  const migrationDirectories = (await readdir(migrationsRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const baselinePlan = migrationDirectories[0] === baselineName && !migrationDirectories.includes(transitionName);
  const transitionPlan = migrationDirectories.includes(transitionName);
  assert.ok(baselinePlan || transitionPlan, "Expected the clean baseline with forward migrations or the production transition plan.");
  const legacyDirectories = transitionPlan ? migrationDirectories.filter((name) => name !== transitionName) : [];
  if (transitionPlan) assert.equal(legacyDirectories.length, 14, "Expected the production's fourteen applied migrations before transition.");
  const additiveDirectories = baselinePlan ? migrationDirectories.filter((name) => name !== baselineName) : [];

  runDocker([
    "run", "--detach", "--name", containerName, "--publish", "127.0.0.1::5432",
    "--env", `POSTGRES_DB=${databaseName}`, "--env", `POSTGRES_USER=${databaseUser}`,
    "--env", `POSTGRES_PASSWORD=${databasePassword}`,
    "--health-cmd", `pg_isready -h 127.0.0.1 -U ${databaseUser} -d ${databaseName}`,
    "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "60",
    "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24",
  ]);
  containerStarted = true;
  await waitForDatabase();
  const port = readPublishedPort();
  const databaseUrl = buildDatabaseUrl(port);

  runSql("CREATE ROLE virki_audit_maintenance NOLOGIN");

  temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "virki-migration-validation-"));
  const temporaryPrismaDirectory = path.join(temporaryDirectory, "prisma");
  const temporaryMigrationsDirectory = path.join(temporaryPrismaDirectory, "migrations");
  await mkdir(temporaryMigrationsDirectory, { recursive: true });
  await writeFile(path.join(temporaryPrismaDirectory, "schema.prisma"), await readFile(path.join(repositoryRoot, "packages", "database", "prisma", "schema.prisma")));
  await cp(path.join(migrationsRoot, "migration_lock.toml"), path.join(temporaryMigrationsDirectory, "migration_lock.toml"));
  for (const migration of baselinePlan ? [baselineName] : legacyDirectories) {
    await cp(path.join(migrationsRoot, migration), path.join(temporaryMigrationsDirectory, migration), { recursive: true });
  }

  const schemaPath = path.join(temporaryPrismaDirectory, "schema.prisma");
  if (baselinePlan) {
    await deployMigrations(schemaPath, databaseUrl);
    assert.equal(runSql("SELECT count(*)::text || '|' || count(*) FILTER (WHERE \"finished_at\" IS NULL AND \"rolled_back_at\" IS NULL)::text || '|' || count(*) FILTER (WHERE \"rolled_back_at\" IS NOT NULL)::text || '|' || count(*) FILTER (WHERE \"migration_name\" = '0_init')::text FROM \"_prisma_migrations\""), "1|0|0|1", "Expected the clean baseline to be applied first to a fresh database.");
    if (additiveDirectories.length > 0) {
      client = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      await client.$connect();
      runSql(seedRecoveryOutbox());
      runSql(seedMigrationTransformFixtures());
      const recoveryBefore = await readRecoveryOutboxState();
      assert.equal(recoveryBefore.length, 1);
      assert.match(recoveryBefore[0].idempotencyKey, /^account-recovery:[A-Za-z0-9_-]{32}$/u, "Expected a legacy recovery outbox key that the migration must rewrite.");
      assert.equal(await client.deviceChallenge.count(), 3, "Expected every challenge fixture to exist before the additive migration.");
      assert.equal(await client.accountRecoveryRequest.count(), 3, "Expected every recovery request fixture to exist before the additive migration.");

      for (const migration of additiveDirectories) {
        await cp(path.join(migrationsRoot, migration), path.join(temporaryMigrationsDirectory, migration), { recursive: true });
      }
      await deployMigrations(schemaPath, databaseUrl);
      assert.equal(runSql("SELECT count(*)::text || '|' || count(*) FILTER (WHERE \"finished_at\" IS NOT NULL AND \"rolled_back_at\" IS NULL)::text || '|' || count(*) FILTER (WHERE \"finished_at\" IS NULL AND \"rolled_back_at\" IS NULL)::text || '|' || count(*) FILTER (WHERE \"rolled_back_at\" IS NOT NULL)::text FROM \"_prisma_migrations\""), `${migrationDirectories.length}|${migrationDirectories.length}|0|0`, "Expected every committed additive migration to apply once without rewriting migration history.");
      const recoveryAfter = await readRecoveryOutboxState();
      assert.deepEqual(recoveryAfter, recoveryBefore.map((message) => ({
        ...message,
        idempotencyKey: `account-recovery-migrated:${message.id}`,
      })), "Additive migrations must rewrite legacy recovery keys and preserve all other message and delivery-attempt fields.");
      await verifyMigrationTransformations();
    } else {
      assert.equal(runSql("SELECT count(*)::text || '|' || count(*) FILTER (WHERE \"finished_at\" IS NOT NULL AND \"rolled_back_at\" IS NULL)::text || '|' || count(*) FILTER (WHERE \"finished_at\" IS NULL AND \"rolled_back_at\" IS NULL)::text || '|' || count(*) FILTER (WHERE \"rolled_back_at\" IS NOT NULL)::text FROM \"_prisma_migrations\""), `${migrationDirectories.length}|${migrationDirectories.length}|0|0`, "Expected all committed migrations to apply to a fresh database.");
    }
    if (!client) {
      client = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      await client.$connect();
    }
    await verifyRemovedProductSchema();
    await verifyCurrentSchema(schemaPath, databaseUrl);
    await verifyMigrationStatus(schemaPath, databaseUrl);
  } else {
    await deployMigrations(schemaPath, databaseUrl);
    assert.equal(runSql("SELECT count(*) FROM \"_prisma_migrations\" WHERE \"finished_at\" IS NOT NULL AND \"rolled_back_at\" IS NULL"), "14");
    runSql(seedLegacyIdentity());

    await cp(path.join(migrationsRoot, transitionName), path.join(temporaryMigrationsDirectory, transitionName), { recursive: true });
    await deployMigrations(schemaPath, databaseUrl);
    assert.equal(runSql("SELECT count(*) FROM \"_prisma_migrations\" WHERE \"finished_at\" IS NOT NULL AND \"rolled_back_at\" IS NULL"), "15");

    client = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    await client.$connect();
    await verifyPreservedIdentity();
    await verifyRemovedProductSchema();
    await verifyMigrationStatus(schemaPath, databaseUrl);
  }
} catch (error) {
  validationError = error;
}

const cleanupErrors = [];
try {
  await client?.$disconnect();
} catch (error) {
  cleanupErrors.push(error);
}
if (containerStarted) {
  let result;
  try {
    result = spawnSync("docker", ["rm", "--force", "--volumes", containerName], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
  } catch (error) {
    cleanupErrors.push(new Error("Disposable migration validation container cleanup could not be started.", { cause: error }));
  }
  if (result && (result.error || result.status !== 0)) {
    const detail = result.error?.message ?? `exit status ${result.status ?? "unknown"}`;
    cleanupErrors.push(new Error(`Disposable migration validation container cleanup failed (${detail}).`, result.error ? { cause: result.error } : undefined));
  }
}
if (temporaryDirectory) {
  try {
    await rm(temporaryDirectory, { recursive: true, force: true });
  } catch (error) {
    cleanupErrors.push(error);
  }
}
if (validationError && cleanupErrors.length > 0) {
  throw new AggregateError([validationError, ...cleanupErrors], "Migration validation failed and cleanup also failed; both errors are preserved.");
}
if (validationError) throw validationError;
if (cleanupErrors.length === 1) throw cleanupErrors[0];
if (cleanupErrors.length > 1) throw new AggregateError(cleanupErrors, "Disposable migration validation cleanup failed.");

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

async function readRecoveryOutboxState() {
  return client.emailOutboxMessage.findMany({
    where: { kind: "ACCOUNT_RECOVERY" },
    orderBy: { id: "asc" },
    select: {
      id: true,
      idempotencyKey: true,
      kind: true,
      recipientEmail: true,
      locale: true,
      payload: true,
      status: true,
      attemptCount: true,
      availableAt: true,
      sentAt: true,
      terminalFailedAt: true,
      createdAt: true,
      updatedAt: true,
      deliveryAttempts: {
        orderBy: { attempt: "asc" },
        select: { id: true, attempt: true, status: true, errorCode: true, attemptedAt: true },
      },
    },
  });
}

async function verifyMigrationTransformations() {
  const challenges = await client.deviceChallenge.findMany({
    where: { id: { in: ["validation-challenge-pending", "validation-challenge-verified", "validation-challenge-consumed"] } },
    orderBy: { id: "asc" },
    select: { id: true, status: true, consumedAt: true },
  });
  assert.equal(await client.deviceChallenge.count(), 3, "Migration must preserve all device challenge rows.");
  assert.deepEqual(challenges.map(({ id, status }) => ({ id, status })), [
    { id: "validation-challenge-consumed", status: "VERIFIED" },
    { id: "validation-challenge-pending", status: "REVOKED" },
    { id: "validation-challenge-verified", status: "REVOKED" },
  ], "Migration must revoke only unconsumed pending or verified device challenges.");
  assert.ok(challenges.find(({ id }) => id === "validation-challenge-consumed")?.consumedAt instanceof Date);

  const requestKeys = {
    "validation-recovery-normalized": "recovery-key-normalized-fixture",
    "validation-recovery-fallback": "recovery-key-fallback-fixture",
  };
  const recoveryRequests = await client.accountRecoveryRequest.findMany({
    where: { id: { in: Object.keys(requestKeys) } },
    orderBy: { id: "asc" },
    select: {
      id: true,
      requestKeyHash: true,
      emailAddressHash: true,
      userId: true,
      status: true,
      user: { select: { email: true, emailNormalized: true } },
    },
  });
  assert.equal(await client.accountRecoveryRequest.count(), 3, "Migration must preserve all account recovery request rows.");
  assert.deepEqual(recoveryRequests.map(({ id, userId, status }) => ({ id, userId, status })), [
    { id: "validation-recovery-fallback", userId: "validation-recovery-fallback-user", status: "APPROVED" },
    { id: "validation-recovery-normalized", userId: "validation-recovery-normalized-user", status: "PENDING" },
  ], "Migration must preserve recovery request identity and status.");
  for (const request of recoveryRequests) {
    assert.equal(request.requestKeyHash, sha256(requestKeys[request.id]), "Migration must hash each recovery request key without changing its row identity.");
    const email = request.user.emailNormalized ?? request.user.email;
    assert.equal(request.emailAddressHash, sha256(email.trim().toLowerCase()), "Migration must hash the email belonging to the linked recovery request user.");
  }

  await verifyUnresolvedLegacyStateFixtures();
}

async function verifyUnresolvedLegacyStateFixtures() {
  const users = await client.user.findMany({
    where: { id: { in: ["validation-email-null", "validation-email-case-upper", "validation-email-case-lower", "validation-email-unicode", "validation-account-diverged-active", "validation-account-diverged-inactive"] } },
    orderBy: { id: "asc" },
    select: { id: true, email: true, emailNormalized: true, isActive: true, accountStatus: true },
  });
  assert.deepEqual(users, [
    { id: "validation-account-diverged-active", email: "active-flag@fixture.invalid", emailNormalized: "active-flag@fixture.invalid", isActive: true, accountStatus: "INACTIVE" },
    { id: "validation-account-diverged-inactive", email: "inactive-flag@fixture.invalid", emailNormalized: "inactive-flag@fixture.invalid", isActive: false, accountStatus: "ACTIVE" },
    { id: "validation-email-case-lower", email: "case@fixture.invalid", emailNormalized: "case@fixture.invalid", isActive: true, accountStatus: "ACTIVE" },
    { id: "validation-email-case-upper", email: "Case@fixture.invalid", emailNormalized: "Case@fixture.invalid", isActive: true, accountStatus: "ACTIVE" },
    { id: "validation-email-null", email: "Nullable@fixture.invalid", emailNormalized: null, isActive: true, accountStatus: "ACTIVE" },
    { id: "validation-email-unicode", email: "İndex@fixture.invalid", emailNormalized: "i̇ndex@fixture.invalid", isActive: true, accountStatus: "ACTIVE" },
  ], "Migration must preserve legacy nullable/case/Unicode email values and divergent account-state flags pending a canonical repair rule.");

  const orphanedElevation = await client.securityElevation.findUnique({
    where: { id: "validation-elevation-orphan-session" },
    select: { sessionId: true, status: true, user: { select: { id: true } } },
  });
  assert.deepEqual(orphanedElevation, {
    sessionId: "validation-missing-session",
    status: "ACTIVE",
    user: { id: "validation-recovery-normalized-user" },
  }, "Migrations must preserve an orphaned session reference without guessing whether the legacy row should be deleted or revoked.");
  assert.equal(await client.session.count({ where: { id: "validation-missing-session" } }), 0);

  const stalledMessage = await client.emailOutboxMessage.findUnique({
    where: { id: "validation-stalled-email" },
    select: {
      status: true,
      attemptCount: true,
      updatedAt: true,
      processingLeaseExpiresAt: true,
      deliveryAttempts: { orderBy: { attempt: "asc" }, select: { attempt: true, status: true } },
    },
  });
  assert.equal(stalledMessage?.status, "PROCESSING");
  assert.equal(stalledMessage?.attemptCount, 2);
  assert.equal(stalledMessage?.processingLeaseExpiresAt?.getTime(), stalledMessage?.updatedAt.getTime(), "The processing lease migration uses updatedAt to seed existing PROCESSING rows.");
  assert.deepEqual(stalledMessage?.deliveryAttempts, [
    { attempt: 1, status: "FAILED" },
    { attempt: 2, status: "FAILED" },
  ], "Migration must preserve bounded retry history for a stalled message.");

  const orphanedGrantor = await client.userProjectGrant.findUnique({
    where: { id: "validation-orphan-grantor" },
    select: { grantedByUserId: true, revokedAt: true },
  });
  assert.equal(orphanedGrantor?.grantedByUserId, "validation-missing-grantor", "Migration must not invent a grantor or erase an unreferenced grantor value.");

  const reviewedRecovery = await client.accountRecoveryRequest.findUnique({
    where: { id: "validation-reviewed-recovery" },
    select: { reviewedByUserId: true, reviewedByUser: { select: { id: true } } },
  });
  assert.deepEqual(reviewedRecovery, {
    reviewedByUserId: "validation-recovery-normalized-user",
    reviewedByUser: { id: "validation-recovery-normalized-user" },
  }, "Migration must preserve the reviewer relation attached to an approved recovery request.");
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function verifyRemovedProductSchema() {
  const rows = await client.$queryRaw`
    SELECT
      to_regclass('"AccountApplication"') IS NULL AS intake_removed,
      to_regclass('"IntakePublicModuleCatalog"') IS NULL AS intake_view_removed,
      to_regprocedure('virki_intake_activate_application(text,text,text,timestamp without time zone)') IS NULL AS intake_activation_function_removed,
      to_regprocedure('virki_intake_enqueue_email_message(text,text,text,jsonb,timestamp without time zone)') IS NULL AS intake_email_function_removed,
      to_regclass('"ModuleCatalog"') IS NULL AS modules_removed,
      to_regclass('"GymForgeParticipant"') IS NULL AS gymforge_removed,
      to_regclass('"Project"') IS NULL AS old_project_model_removed,
      to_regclass('"ProjectConnection"') IS NOT NULL AS connection_model_created,
      to_regclass('"OidcArtifact"') IS NOT NULL AS oidc_artifact_model_created
  `;
  assert.deepEqual(rows[0], {
    intake_removed: true,
    intake_view_removed: true,
    intake_activation_function_removed: true,
    intake_email_function_removed: true,
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

function verifyCurrentSchema(schemaPath, databaseUrl) {
  const result = spawnSync(process.execPath, [prismaCliPath(), "migrate", "diff", "--from-url", databaseUrl, "--to-schema-datamodel", schemaPath, "--exit-code"], {
    cwd: repositoryRoot,
    env: { ...process.env, DATABASE_URL: databaseUrl },
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("Fresh baseline schema does not match the current Prisma datamodel.");
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
  if (result.error || result.status !== 0) {
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    const sqlState = output.match(/database error code:\s*([0-9A-Z]{5})/iu)?.[1]
      ?? output.match(/SQLSTATE[\s:]+([0-9A-Z]{5})/iu)?.[1];
    const prismaCode = output.match(/\bP\d{4}\b/u)?.[0];
    const processCode = result.error && "code" in result.error && typeof result.error.code === "string" ? result.error.code : undefined;
    const dependency = describeDependencyFailure(output);
    throw new Error(`Disposable production migration validation failed (${sqlState ?? prismaCode ?? processCode ?? "unknown"}${dependency ? `: ${dependency}` : ""}).`);
  }
}

function prismaCliPath() {
  return path.join(repositoryRoot, "node_modules", "prisma", "build", "index.js");
}

function describeDependencyFailure(output) {
  if (!/\b2BP01\b/u.test(output)) return undefined;
  const target = output.match(/cannot drop (table|type) "([A-Za-z0-9_]+)" because other objects depend on it/iu);
  if (!target) return "dependent-object";
  const detail = output.match(/DETAIL:\s*(?:constraint "([A-Za-z0-9_]+)" on table "([A-Za-z0-9_]+)"|column "([A-Za-z0-9_]+)" of table "([A-Za-z0-9_]+)") depends on (?:table|type) "[A-Za-z0-9_]+"/iu);
  const object = detail
    ? detail[1] ? `constraint ${detail[1]} on ${detail[2]}` : `column ${detail[3]} on ${detail[4]}`
    : "unclassified-dependent-object";
  return `cannot-drop-${target[1].toLowerCase()}-${target[2]} (${object})`;
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

function seedRecoveryOutbox() {
  return `
INSERT INTO "EmailOutboxMessage" ("id", "idempotencyKey", "kind", "recipientEmail", "locale", "payload", "status", "attemptCount", "availableAt", "createdAt", "updatedAt") VALUES
  ('validation-account-recovery-email', 'account-recovery:0123456789abcdefghijklmnopqrstuv', 'ACCOUNT_RECOVERY'::"EmailMessageKind", 'user@validation.invalid', 'en', '{"version":1,"publicValues":{"displayName":"Validation user"},"protectedValues":{"ciphertext":"opaque-encrypted-recovery-payload","iv":"validation-iv","tag":"validation-tag"}}'::jsonb, 'RETRYABLE_FAILURE'::"OutboxMessageStatus", 2, CURRENT_TIMESTAMP + INTERVAL '5 minutes', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "EmailDeliveryAttempt" ("id", "messageId", "attempt", "status", "errorCode", "attemptedAt") VALUES
  ('validation-account-recovery-attempt-1', 'validation-account-recovery-email', 1, 'FAILED'::"DeliveryAttemptStatus", 'transport-failure', CURRENT_TIMESTAMP - INTERVAL '2 minutes'),
  ('validation-account-recovery-attempt-2', 'validation-account-recovery-email', 2, 'FAILED'::"DeliveryAttemptStatus", 'transport-failure', CURRENT_TIMESTAMP - INTERVAL '1 minute');
`;
}

function seedMigrationTransformFixtures() {
  return `
BEGIN;
INSERT INTO "User" ("id", "email", "emailNormalized", "displayName", "passwordHash", "role", "isActive", "accountStatus", "secondFactorMethod", "createdAt", "updatedAt") VALUES
  ('validation-recovery-normalized-user', 'Primary@validation.invalid', 'primary@validation.invalid', 'Primary recovery fixture', 'fixture-password-hash', 'USER'::"UserRole", true, 'ACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-recovery-fallback-user', 'Fallback@validation.invalid', NULL, 'Fallback recovery fixture', 'fixture-password-hash', 'USER'::"UserRole", true, 'ACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-email-null', 'Nullable@fixture.invalid', NULL, 'Nullable email fixture', 'fixture-password-hash', 'USER'::"UserRole", true, 'ACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-email-case-upper', 'Case@fixture.invalid', 'Case@fixture.invalid', 'Uppercase email fixture', 'fixture-password-hash', 'USER'::"UserRole", true, 'ACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-email-case-lower', 'case@fixture.invalid', 'case@fixture.invalid', 'Lowercase email fixture', 'fixture-password-hash', 'USER'::"UserRole", true, 'ACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-email-unicode', 'İndex@fixture.invalid', 'i̇ndex@fixture.invalid', 'Unicode email fixture', 'fixture-password-hash', 'USER'::"UserRole", true, 'ACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-account-diverged-active', 'active-flag@fixture.invalid', 'active-flag@fixture.invalid', 'Divergent active fixture', 'fixture-password-hash', 'USER'::"UserRole", true, 'INACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-account-diverged-inactive', 'inactive-flag@fixture.invalid', 'inactive-flag@fixture.invalid', 'Divergent inactive fixture', 'fixture-password-hash', 'USER'::"UserRole", false, 'ACTIVE'::"AccountStatus", 'EMAIL'::"SecondFactorMethod", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "SecurityElevation" ("id", "requestKey", "userId", "sessionId", "protocolVersion", "scope", "challengeHash", "status", "expiresAt", "createdAt", "updatedAt") VALUES
  ('validation-elevation-orphan-session', 'validation-orphan-elevation-key', 'validation-recovery-normalized-user', 'validation-missing-session', 1, 'ACCOUNT_STATE_CHANGE', 'fixture-challenge-hash', 'ACTIVE'::"SecurityElevationStatus", CURRENT_TIMESTAMP + INTERVAL '10 minutes', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "EmailOutboxMessage" ("id", "idempotencyKey", "kind", "recipientEmail", "locale", "payload", "status", "attemptCount", "availableAt", "createdAt", "updatedAt") VALUES
  ('validation-stalled-email', 'validation-stalled-email-key', 'PASSWORD_CHANGED'::"EmailMessageKind", 'nullable@fixture.invalid', 'en', '{"fixture":true}'::jsonb, 'PROCESSING'::"OutboxMessageStatus", 2, CURRENT_TIMESTAMP - INTERVAL '2 hours', CURRENT_TIMESTAMP - INTERVAL '2 hours', CURRENT_TIMESTAMP - INTERVAL '2 hours');
INSERT INTO "EmailDeliveryAttempt" ("id", "messageId", "attempt", "status", "errorCode", "attemptedAt") VALUES
  ('validation-stalled-attempt-1', 'validation-stalled-email', 1, 'FAILED'::"DeliveryAttemptStatus", 'fixture-retry', CURRENT_TIMESTAMP - INTERVAL '3 hours'),
  ('validation-stalled-attempt-2', 'validation-stalled-email', 2, 'FAILED'::"DeliveryAttemptStatus", 'fixture-retry', CURRENT_TIMESTAMP - INTERVAL '2 hours');
INSERT INTO "ProjectConnection" ("id", "name", "slug", "origin", "clientId", "clientSecretCiphertext", "redirectUris", "createdAt", "updatedAt") VALUES
  ('validation-grant-connection', 'Validation connection', 'validation-grant', 'https://fixture.invalid', 'validation-grant-client', 'fixture-secret-ciphertext', '[]'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO "UserProjectGrant" ("id", "userId", "connectionId", "grantedByUserId", "createdAt") VALUES
  ('validation-orphan-grantor', 'validation-email-null', 'validation-grant-connection', 'validation-missing-grantor', CURRENT_TIMESTAMP);
INSERT INTO "DeviceChallenge" ("id", "userId", "ceremonyId", "deviceIdHash", "codeHash", "status", "expiresAt", "consumedAt") VALUES
  ('validation-challenge-pending', 'validation-recovery-normalized-user', 'validation-ceremony-pending', 'fixture-device-hash', 'fixture-code-hash', 'PENDING'::"DeviceChallengeStatus", CURRENT_TIMESTAMP + INTERVAL '10 minutes', NULL),
  ('validation-challenge-verified', 'validation-recovery-normalized-user', 'validation-ceremony-verified', 'fixture-device-hash', 'fixture-code-hash', 'VERIFIED'::"DeviceChallengeStatus", CURRENT_TIMESTAMP + INTERVAL '10 minutes', NULL),
  ('validation-challenge-consumed', 'validation-recovery-normalized-user', 'validation-ceremony-consumed', 'fixture-device-hash', 'fixture-code-hash', 'VERIFIED'::"DeviceChallengeStatus", CURRENT_TIMESTAMP + INTERVAL '10 minutes', CURRENT_TIMESTAMP);
INSERT INTO "AccountRecoveryRequest" ("id", "requestKey", "userId", "emailChallengeHash", "status", "expiresAt", "createdAt", "updatedAt") VALUES
  ('validation-recovery-normalized', 'recovery-key-normalized-fixture', 'validation-recovery-normalized-user', 'fixture-email-challenge-hash', 'PENDING'::"RecoveryRequestStatus", CURRENT_TIMESTAMP + INTERVAL '1 day', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-recovery-fallback', 'recovery-key-fallback-fixture', 'validation-recovery-fallback-user', 'fixture-email-challenge-hash', 'APPROVED'::"RecoveryRequestStatus", CURRENT_TIMESTAMP + INTERVAL '1 day', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('validation-reviewed-recovery', 'reviewed-recovery-key-fixture', 'validation-email-null', 'fixture-email-challenge-hash', 'APPROVED'::"RecoveryRequestStatus", CURRENT_TIMESTAMP + INTERVAL '1 day', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
UPDATE "AccountRecoveryRequest" SET "reviewedByUserId" = 'validation-recovery-normalized-user' WHERE "id" = 'validation-reviewed-recovery';
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
