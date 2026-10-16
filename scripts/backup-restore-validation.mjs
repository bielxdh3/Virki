import assert from "node:assert/strict";
import { cp, mkdtemp, mkdir, readFile, rm, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { PrismaClient } from "@prisma/client";
import { describeBackupMigrationFailure } from "./lib/backup-migration-diagnostics.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsRoot = path.join(repositoryRoot, "packages", "database", "prisma", "migrations");
const transitionName = "20260922090000_total_identity_security_rebaseline";
const containerName = `virki-backup-validation-${process.pid}`;
const databaseName = "virki_backup_test";
const restoreDatabaseName = "virki_restore_test";
const databaseUser = "virki_backup_test";
const databasePassword = "backup-validation-only";
let containerStarted = false;
let temporaryDirectory;
let sourceClient;
let restoredClient;
let validationError;

try {
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
  runSql("CREATE ROLE virki_audit_maintenance NOLOGIN");

  const port = readPublishedPort();
  const sourceUrl = buildDatabaseUrl(port, databaseName);
  const migrations = await readdir(migrationsRoot, { withFileTypes: true });
  const transitionPresent = migrations.some((entry) => entry.isDirectory() && entry.name === transitionName);
  const baselinePresent = migrations.some((entry) => entry.isDirectory() && entry.name === "0_init");

  if (transitionPresent) {
    temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "virki-backup-validation-"));
    const temporaryPrismaDirectory = path.join(temporaryDirectory, "prisma");
    const temporaryMigrationsDirectory = path.join(temporaryPrismaDirectory, "migrations");
    await mkdir(temporaryMigrationsDirectory, { recursive: true });
    await writeFile(path.join(temporaryPrismaDirectory, "schema.prisma"), await readFile(path.join(repositoryRoot, "packages", "database", "prisma", "schema.prisma")));
    await cp(path.join(migrationsRoot, "migration_lock.toml"), path.join(temporaryMigrationsDirectory, "migration_lock.toml"));
    for (const entry of migrations.filter((item) => item.isDirectory() && item.name !== transitionName)) {
      await cp(path.join(migrationsRoot, entry.name), path.join(temporaryMigrationsDirectory, entry.name), { recursive: true });
    }
    await migrate(temporaryPrismaDirectory, sourceUrl, "source-legacy");
    runSql("INSERT INTO \"User\" (\"id\",\"email\",\"emailNormalized\",\"displayName\",\"passwordHash\",\"role\",\"accountStatus\",\"emailVerifiedAt\",\"secondFactorMethod\",\"createdAt\",\"updatedAt\") VALUES ('backup-admin','admin@backup.invalid','admin@backup.invalid','Backup administrator','legacy-password-hash','OWNER'::\"UserRole\",'ACTIVE'::\"AccountStatus\",CURRENT_TIMESTAMP,'EMAIL'::\"SecondFactorMethod\",CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)");
    await cp(path.join(migrationsRoot, transitionName), path.join(temporaryMigrationsDirectory, transitionName), { recursive: true });
    await migrate(temporaryPrismaDirectory, sourceUrl, "source-transition");
  } else if (baselinePresent) {
    await migrate(path.join(repositoryRoot, "packages", "database", "prisma"), sourceUrl, "source-baseline");
  } else {
    throw new Error("Backup validation migration plan is missing.");
  }

  sourceClient = new PrismaClient({ datasources: { db: { url: sourceUrl } } });
  await sourceClient.$connect();
  await seedRepresentativeData();
  const expectedMigrations = await readMigrations(sourceClient);
  assert.ok(expectedMigrations.length > 0);

  temporaryDirectory ??= await mkdtemp(path.join(os.tmpdir(), "virki-backup-validation-"));
  const dumpPath = path.join(temporaryDirectory, "virki-validation.dump");
  const dump = runDockerBinary(["exec", "-i", containerName, "pg_dump", "-U", databaseUser, "-d", databaseName, "--format=custom", "--no-owner", "--no-privileges"]);
  assert.ok(dump.length > 0);
  await writeFile(dumpPath, dump, { mode: 0o600 });

  runDocker(["exec", containerName, "createdb", "-U", databaseUser, restoreDatabaseName]);
  runDockerBinary(["exec", "-i", containerName, "pg_restore", "--exit-on-error", "--clean", "--if-exists", "--no-owner", "--no-privileges", "-U", databaseUser, "-d", restoreDatabaseName], dump);

  const restoredUrl = buildDatabaseUrl(port, restoreDatabaseName);
  restoredClient = new PrismaClient({ datasources: { db: { url: restoredUrl } } });
  await restoredClient.$connect();
  assert.deepEqual(await readMigrations(restoredClient), expectedMigrations);
  await migrate(path.join(repositoryRoot, "packages", "database", "prisma"), restoredUrl, "restored");
  await verifyRestoredData();
} catch (error) {
  validationError = error;
}

const cleanupErrors = [];
try {
  await restoredClient?.$disconnect();
} catch (error) {
  cleanupErrors.push(error);
}
try {
  await sourceClient?.$disconnect();
} catch (error) {
  cleanupErrors.push(error);
}
if (containerStarted) {
  let result;
  try {
    result = spawnSync("docker", ["rm", "--force", "--volumes", containerName], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
  } catch (error) {
    cleanupErrors.push(new Error("Disposable backup validation container cleanup could not be started.", { cause: error }));
  }
  if (result && (result.error || result.status !== 0)) {
    const detail = result.error?.message ?? `exit status ${result.status ?? "unknown"}`;
    cleanupErrors.push(new Error(`Disposable backup validation container cleanup failed (${detail}).`, result.error ? { cause: result.error } : undefined));
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
  throw new AggregateError([validationError, ...cleanupErrors], "Backup validation failed and cleanup also failed; both errors are preserved.");
}
if (validationError) throw validationError;
if (cleanupErrors.length === 1) throw cleanupErrors[0];
if (cleanupErrors.length > 1) throw new AggregateError(cleanupErrors, "Disposable backup validation cleanup failed.");

async function seedRepresentativeData() {
  let admin = await sourceClient.user.findUnique({ where: { id: "backup-admin" } });
  admin ??= await sourceClient.user.create({
    data: {
      id: "backup-admin",
      email: "admin@backup.invalid",
      emailNormalized: "admin@backup.invalid",
      displayName: "Backup validation administrator",
      passwordHash: "backup-admin-password-hash",
      role: "ADMIN",
      accountStatus: "ACTIVE",
      emailVerifiedAt: new Date(),
      secondFactorMethod: "EMAIL",
    },
  });
  assert.ok(admin);
  const user = await sourceClient.user.create({
    data: {
      id: "backup-user",
      email: "user@backup.invalid",
      emailNormalized: "user@backup.invalid",
      displayName: "Backup validation user",
      passwordHash: "backup-password-hash",
      role: "USER",
      emailVerifiedAt: new Date(),
    },
  });
  const connection = await sourceClient.projectConnection.create({
    data: {
      id: "backup-connection",
      name: "Backup validation connection",
      slug: "backup-validation-connection",
      origin: "https://client.backup.invalid",
      clientId: "backup-client-id",
      clientSecretCiphertext: "encrypted-backup-client-secret",
      redirectUris: ["https://client.backup.invalid/callback"],
      createdByUserId: admin.id,
    },
  });
  await sourceClient.userProjectGrant.create({ data: { id: "backup-grant", userId: user.id, connectionId: connection.id, grantedByUserId: admin.id } });
  await sourceClient.session.create({
    data: {
      id: "backup-session",
      userId: user.id,
      tokenHash: "backup-session-token-hash",
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  await sourceClient.totpFactor.create({
    data: {
      id: "backup-totp",
      userId: user.id,
      secretCiphertext: "encrypted-backup-totp-secret",
      keyVersion: 1,
      status: "ACTIVE",
      confirmedAt: new Date(),
    },
  });
  await sourceClient.recoveryCode.create({ data: { id: "backup-recovery", userId: user.id, codeHash: "backup-recovery-hash" } });
  await sourceClient.trustedDevice.create({
    data: {
      id: "backup-device",
      userId: user.id,
      deviceIdHash: "backup-device-hash",
      status: "TRUSTED",
      rememberedUntil: new Date(Date.now() + 60_000),
      strongVerifiedAt: new Date(),
    },
  });
  await sourceClient.deviceChallenge.create({
    data: {
      id: "backup-device-challenge",
      userId: user.id,
      ceremonyId: "backup-device-challenge-ceremony",
      deviceIdHash: "backup-device-challenge-device-hash",
      emailAddressHash: "backup-device-challenge-email-hash",
      codeHash: "backup-device-challenge-code-hash",
      emailVerifiedAt: new Date("2026-01-02T03:04:05.000Z"),
      status: "VERIFIED",
      expiresAt: new Date("2027-01-02T03:04:05.000Z"),
    },
  });
  await sourceClient.accountRecoveryRequest.create({
    data: {
      id: "backup-account-recovery-request",
      userId: user.id,
      requestKeyHash: "backup-recovery-request-key-hash",
      emailAddressHash: "backup-recovery-request-email-hash",
      emailChallengeHash: "backup-recovery-request-challenge-hash",
      emailVerifiedAt: new Date("2026-02-03T04:05:06.000Z"),
      status: "APPROVED",
      expiresAt: new Date("2027-02-03T04:05:06.000Z"),
      reviewedByUserId: admin.id,
      approvedAt: new Date("2026-02-03T04:05:07.000Z"),
    },
  });
  await sourceClient.oidcArtifact.create({
    data: {
      id: "backup-artifact",
      model: "AuthorizationCode",
      idHash: "backup-artifact-hash",
      payloadCiphertext: "encrypted-backup-oidc-artifact",
      clientIdHash: "backup-client-hash",
      accountIdHash: "backup-account-hash",
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  await sourceClient.auditLog.create({
    data: {
      id: "backup-audit",
      eventType: "AUTH_LOGIN_SUCCESS",
      actorUserId: user.id,
      result: "SUCCESS",
      resource: "auth.session",
      message: "Authentication succeeded.",
      metadata: { validation: true },
    },
  });
  await sourceClient.emailOutboxMessage.create({
    data: {
      id: "backup-account-recovery-email",
      idempotencyKey: "account-recovery:backup-validation-request",
      kind: "ACCOUNT_RECOVERY",
      recipientEmail: user.email,
      locale: "en",
      payload: {
        version: 1,
        publicValues: { displayName: "Backup validation user" },
        protectedValues: {
          ciphertext: "opaque-encrypted-recovery-payload",
          iv: "backup-validation-iv",
          tag: "backup-validation-tag",
        },
      },
      status: "RETRYABLE_FAILURE",
      attemptCount: 2,
      availableAt: new Date(Date.now() + 5 * 60_000),
      deliveryAttempts: {
        create: [
          { id: "backup-recovery-attempt-1", attempt: 1, status: "FAILED", errorCode: "transport-failure" },
          { id: "backup-recovery-attempt-2", attempt: 2, status: "FAILED", errorCode: "transport-failure" },
        ],
      },
    },
  });
}

async function verifyRestoredData() {
  const admin = await restoredClient.user.findUnique({ where: { id: "backup-admin" } });
  assert.equal(admin?.role, "ADMIN");
  assert.ok(admin?.passwordHash);
  assert.equal((await restoredClient.user.findUnique({ where: { id: "backup-user" } }))?.email, "user@backup.invalid");
  assert.equal((await restoredClient.projectConnection.findUnique({ where: { id: "backup-connection" } }))?.clientId, "backup-client-id");
  assert.equal(await restoredClient.userProjectGrant.count({ where: { id: "backup-grant" } }), 1);
  assert.equal(await restoredClient.session.count({ where: { id: "backup-session" } }), 1);
  assert.equal((await restoredClient.totpFactor.findUnique({ where: { userId: "backup-user" } }))?.secretCiphertext, "encrypted-backup-totp-secret");
  assert.equal(await restoredClient.recoveryCode.count({ where: { id: "backup-recovery" } }), 1);
  assert.equal((await restoredClient.trustedDevice.findUnique({ where: { id: "backup-device" } }))?.status, "TRUSTED");
  const sourceChallenge = await sourceClient.deviceChallenge.findUnique({ where: { id: "backup-device-challenge" } });
  const challenge = await restoredClient.deviceChallenge.findUnique({ where: { id: "backup-device-challenge" } });
  assert.ok(sourceChallenge, "Source device challenge must exist before backup.");
  assert.ok(challenge, "Restored device challenge must exist.");
  assert.deepEqual(challenge, sourceChallenge, "Backup restore must preserve every device challenge field.");
  assert.equal(challenge?.userId, "backup-user");
  assert.equal(challenge?.status, "VERIFIED");
  assert.equal(challenge?.deviceIdHash, "backup-device-challenge-device-hash");
  assert.equal(challenge?.emailAddressHash, "backup-device-challenge-email-hash");
  assert.equal(challenge?.codeHash, "backup-device-challenge-code-hash");
  const sourceRecoveryRequest = await sourceClient.accountRecoveryRequest.findUnique({ where: { id: "backup-account-recovery-request" } });
  const recoveryRequest = await restoredClient.accountRecoveryRequest.findUnique({ where: { id: "backup-account-recovery-request" } });
  assert.ok(sourceRecoveryRequest, "Source account recovery request must exist before backup.");
  assert.ok(recoveryRequest, "Restored account recovery request must exist.");
  assert.deepEqual(recoveryRequest, sourceRecoveryRequest, "Backup restore must preserve every account recovery request field.");
  assert.equal(recoveryRequest?.userId, "backup-user");
  assert.equal(recoveryRequest?.reviewedByUserId, "backup-admin");
  assert.equal(recoveryRequest?.status, "APPROVED");
  assert.equal(recoveryRequest?.requestKeyHash, "backup-recovery-request-key-hash");
  assert.equal(recoveryRequest?.emailAddressHash, "backup-recovery-request-email-hash");
  assert.equal(recoveryRequest?.emailChallengeHash, "backup-recovery-request-challenge-hash");
  assert.equal((await restoredClient.oidcArtifact.findUnique({ where: { id: "backup-artifact" } }))?.payloadCiphertext, "encrypted-backup-oidc-artifact");
  assert.equal(await restoredClient.auditLog.count({ where: { id: "backup-audit", eventType: "AUTH_LOGIN_SUCCESS" } }), 1);
  const recoveryMessage = await restoredClient.emailOutboxMessage.findUnique({
    where: { id: "backup-account-recovery-email" },
    include: { deliveryAttempts: { orderBy: { attempt: "asc" } } },
  });
  assert.deepEqual(recoveryMessage?.payload, {
    version: 1,
    publicValues: { displayName: "Backup validation user" },
    protectedValues: {
      ciphertext: "opaque-encrypted-recovery-payload",
      iv: "backup-validation-iv",
      tag: "backup-validation-tag",
    },
  });
  assert.equal(recoveryMessage?.status, "RETRYABLE_FAILURE");
  assert.equal(recoveryMessage?.attemptCount, 2);
  assert.equal(recoveryMessage?.deliveryAttempts.length, 2);
  assert.deepEqual(recoveryMessage?.deliveryAttempts.map(({ attempt, status, errorCode }) => ({ attempt, status, errorCode })), [
    { attempt: 1, status: "FAILED", errorCode: "transport-failure" },
    { attempt: 2, status: "FAILED", errorCode: "transport-failure" },
  ]);
}

async function migrate(prismaDirectory, databaseUrl, stage) {
  const prismaCli = path.join(repositoryRoot, "node_modules", "prisma", "build", "index.js");
  const result = spawnSync(process.execPath, [prismaCli, "migrate", "deploy", "--schema", path.join(prismaDirectory, "schema.prisma")], {
    cwd: repositoryRoot,
    env: { ...process.env, DATABASE_URL: databaseUrl },
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error(describeBackupMigrationFailure(result, stage));
}

async function readMigrations(databaseClient) {
  const rows = await databaseClient.$queryRaw`SELECT "migration_name" FROM "_prisma_migrations" ORDER BY "started_at" ASC`;
  return rows.map((row) => row.migration_name);
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
  if (!match) throw new Error("Disposable PostgreSQL port was not loopback-bound.");
  return match[1];
}

function buildDatabaseUrl(port, database) {
  const url = new URL("postgresql://127.0.0.1");
  url.username = databaseUser;
  url.password = databasePassword;
  url.port = port;
  url.pathname = `/${database}`;
  return url.toString();
}

function runSql(sql) {
  const result = spawnSync("docker", ["exec", "-i", containerName, "psql", "-U", databaseUser, "-d", databaseName, "-v", "ON_ERROR_STOP=1"], {
    input: sql,
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("Disposable backup validation SQL failed.");
}

function runDocker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error("Disposable backup validation Docker command failed.");
}

function runDockerBinary(args, input) {
  const result = spawnSync("docker", args, { input, encoding: null, windowsHide: true, timeout: 120_000, maxBuffer: 100 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error("Disposable PostgreSQL backup command failed.");
  return result.stdout;
}
