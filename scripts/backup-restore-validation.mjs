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
const containerName = `bielos-backup-validation-${process.pid}`;
const databaseName = "bielos_backup_test";
const restoreDatabaseName = "bielos_restore_test";
const databaseUser = "bielos_backup_test";
const databasePassword = "backup-validation-only";
let containerStarted = false;
let temporaryDirectory;
let sourceClient;
let restoredClient;

try {
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
  const sourceUrl = buildDatabaseUrl(port, databaseName);
  const migrations = await readdir(migrationsRoot, { withFileTypes: true });
  const transitionPresent = migrations.some((entry) => entry.isDirectory() && entry.name === transitionName);
  const baselinePresent = migrations.some((entry) => entry.isDirectory() && entry.name === "0_init");

  if (transitionPresent) {
    temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "bielos-backup-validation-"));
    const temporaryPrismaDirectory = path.join(temporaryDirectory, "prisma");
    const temporaryMigrationsDirectory = path.join(temporaryPrismaDirectory, "migrations");
    await mkdir(temporaryMigrationsDirectory, { recursive: true });
    await writeFile(path.join(temporaryPrismaDirectory, "schema.prisma"), await readFile(path.join(repositoryRoot, "packages", "database", "prisma", "schema.prisma")));
    await cp(path.join(migrationsRoot, "migration_lock.toml"), path.join(temporaryMigrationsDirectory, "migration_lock.toml"));
    for (const entry of migrations.filter((item) => item.isDirectory() && item.name !== transitionName)) {
      await cp(path.join(migrationsRoot, entry.name), path.join(temporaryMigrationsDirectory, entry.name), { recursive: true });
    }
    await migrate(temporaryPrismaDirectory, sourceUrl);
    runSql("INSERT INTO \"User\" (\"id\",\"email\",\"emailNormalized\",\"displayName\",\"passwordHash\",\"role\",\"accountStatus\",\"emailVerifiedAt\",\"secondFactorMethod\",\"createdAt\",\"updatedAt\") VALUES ('backup-admin','admin@backup.invalid','admin@backup.invalid','Backup administrator','legacy-password-hash','OWNER'::\"UserRole\",'ACTIVE'::\"AccountStatus\",CURRENT_TIMESTAMP,'EMAIL'::\"SecondFactorMethod\",CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)");
    await cp(path.join(migrationsRoot, transitionName), path.join(temporaryMigrationsDirectory, transitionName), { recursive: true });
    await migrate(temporaryPrismaDirectory, sourceUrl);
  } else if (baselinePresent) {
    await migrate(path.join(repositoryRoot, "packages", "database", "prisma"), sourceUrl);
  } else {
    throw new Error("Backup validation migration plan is missing.");
  }

  sourceClient = new PrismaClient({ datasources: { db: { url: sourceUrl } } });
  await sourceClient.$connect();
  await seedRepresentativeData();
  const expectedMigrations = await readMigrations(sourceClient);
  assert.ok(expectedMigrations.length > 0);

  temporaryDirectory ??= await mkdtemp(path.join(os.tmpdir(), "bielos-backup-validation-"));
  const dumpPath = path.join(temporaryDirectory, "bielos-validation.dump");
  const dump = runDockerBinary(["exec", "-i", containerName, "pg_dump", "-U", databaseUser, "-d", databaseName, "--format=custom", "--no-owner", "--no-privileges"]);
  assert.ok(dump.length > 0);
  await writeFile(dumpPath, dump, { mode: 0o600 });

  runDocker(["exec", containerName, "createdb", "-U", databaseUser, restoreDatabaseName]);
  runDockerBinary(["exec", "-i", containerName, "pg_restore", "--clean", "--if-exists", "--no-owner", "--no-privileges", "-U", databaseUser, "-d", restoreDatabaseName], dump);

  const restoredUrl = buildDatabaseUrl(port, restoreDatabaseName);
  restoredClient = new PrismaClient({ datasources: { db: { url: restoredUrl } } });
  await restoredClient.$connect();
  assert.deepEqual(await readMigrations(restoredClient), expectedMigrations);
  await migrate(path.join(repositoryRoot, "packages", "database", "prisma"), restoredUrl);
  await verifyRestoredData();
} finally {
  await restoredClient?.$disconnect();
  await sourceClient?.$disconnect();
  if (containerStarted) spawnSync("docker", ["rm", "--force", "--volumes", containerName], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
  if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true });
}

async function seedRepresentativeData() {
  const admin = await sourceClient.user.findUnique({ where: { id: "backup-admin" } });
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
}

async function verifyRestoredData() {
  assert.equal((await restoredClient.user.findUnique({ where: { id: "backup-user" } }))?.email, "user@backup.invalid");
  assert.equal((await restoredClient.projectConnection.findUnique({ where: { id: "backup-connection" } }))?.clientId, "backup-client-id");
  assert.equal(await restoredClient.userProjectGrant.count({ where: { id: "backup-grant" } }), 1);
  assert.equal(await restoredClient.session.count({ where: { id: "backup-session" } }), 1);
  assert.equal((await restoredClient.totpFactor.findUnique({ where: { userId: "backup-user" } }))?.secretCiphertext, "encrypted-backup-totp-secret");
  assert.equal(await restoredClient.recoveryCode.count({ where: { id: "backup-recovery" } }), 1);
  assert.equal((await restoredClient.trustedDevice.findUnique({ where: { id: "backup-device" } }))?.status, "TRUSTED");
  assert.equal((await restoredClient.oidcArtifact.findUnique({ where: { id: "backup-artifact" } }))?.payloadCiphertext, "encrypted-backup-oidc-artifact");
  assert.equal(await restoredClient.auditLog.count({ where: { id: "backup-audit", eventType: "AUTH_LOGIN_SUCCESS" } }), 1);
}

async function migrate(prismaDirectory, databaseUrl) {
  const prismaCli = path.join(repositoryRoot, "node_modules", "prisma", "build", "index.js");
  const result = spawnSync(process.execPath, [prismaCli, "migrate", "deploy", "--schema", path.join(prismaDirectory, "schema.prisma")], {
    cwd: repositoryRoot,
    env: { ...process.env, DATABASE_URL: databaseUrl },
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("Disposable backup migration deployment failed.");
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

function runDocker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error("Disposable backup validation Docker command failed.");
}

function runDockerBinary(args, input) {
  const result = spawnSync("docker", args, { input, encoding: null, windowsHide: true, timeout: 120_000, maxBuffer: 100 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error("Disposable PostgreSQL backup command failed.");
  return result.stdout;
}
