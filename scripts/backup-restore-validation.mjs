import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { PrismaClient } from "@prisma/client";

const containerName = `bielos-backup-validation-${process.pid}`;
const databaseName = "bielos_backup_test";
const restoreDatabaseName = "bielos_restore_test";
const databaseUser = "bielos_backup_test";
const databasePassword = "backup-validation-only";
const npmCli = process.env.npm_execpath;
let containerStarted = false;
let temporaryDirectory;
let sourceClient;
let restoredClient;

try {
  if (!npmCli) {
    throw new Error("Backup validation must run through npm.");
  }

  runDocker([
    "run",
    "--detach",
    "--name",
    containerName,
    "--publish",
    "127.0.0.1::5432",
    "--env",
    `POSTGRES_DB=${databaseName}`,
    "--env",
    `POSTGRES_USER=${databaseUser}`,
    "--env",
    `POSTGRES_PASSWORD=${databasePassword}`,
    "--health-cmd",
    `pg_isready -U ${databaseUser} -d ${databaseName}`,
    "--health-interval",
    "1s",
    "--health-timeout",
    "3s",
    "--health-retries",
    "30",
    "postgres:17-alpine"
  ]);
  containerStarted = true;
  await waitForDatabase();

  const port = readPublishedPort();
  const sourceUrl = buildDatabaseUrl(port, databaseName);
  await migrate(sourceUrl);
  sourceClient = new PrismaClient({ datasources: { db: { url: sourceUrl } } });

  await seedRepresentativeData();
  const expectedMigrations = await readMigrations(sourceClient);
  assert.ok(expectedMigrations.length > 0);

  temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "bielos-backup-validation-"));
  const dumpPath = path.join(temporaryDirectory, "bielos-validation.dump");
  const dump = runDockerBinary([
    "exec",
    "-i",
    containerName,
    "pg_dump",
    "-U",
    databaseUser,
    "-d",
    databaseName,
    "--format=custom",
    "--no-owner",
    "--no-privileges"
  ]);
  assert.ok(dump.length > 0);
  await writeFile(dumpPath, dump, { mode: 0o600 });

  runDocker(["exec", containerName, "createdb", "-U", databaseUser, restoreDatabaseName]);
  runDockerBinary([
    "exec",
    "-i",
    containerName,
    "pg_restore",
    "--clean",
    "--if-exists",
    "--no-owner",
    "--no-privileges",
    "-U",
    databaseUser,
    "-d",
    restoreDatabaseName
  ], dump);

  const restoredUrl = buildDatabaseUrl(port, restoreDatabaseName);
  restoredClient = new PrismaClient({ datasources: { db: { url: restoredUrl } } });
  await restoredClient.$connect();
  assert.deepEqual(await readMigrations(restoredClient), expectedMigrations);
  await migrate(restoredUrl);
  await verifyRestoredData();
} finally {
  await restoredClient?.$disconnect();
  await sourceClient?.$disconnect();
  if (containerStarted) {
    spawnSync("docker", ["rm", "--force", containerName], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 60_000
    });
  }
  if (temporaryDirectory) {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

async function migrate(databaseUrl) {
  const result = spawnSync(process.execPath, [npmCli, "run", "prisma:migrate:deploy"], {
    cwd: process.cwd(),
    env: { ...process.env, DATABASE_URL: databaseUrl },
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error("Disposable migration deployment failed.");
  }
}

async function seedRepresentativeData() {
  await sourceClient.user.create({
    data: {
      id: "backup-validation-user",
      email: "backup-validation-user@example.invalid",
      emailNormalized: "backup-validation-user@example.invalid",
      displayName: "Backup validation user"
    }
  });
  await sourceClient.project.create({
    data: {
      id: "backup-validation-project",
      name: "Backup validation project",
      slug: "backup-validation-project",
      status: "ACTIVE"
    }
  });
  await sourceClient.gymForgeParticipant.create({
    data: {
      id: "backup-validation-participant",
      displayName: "Backup validation participant"
    }
  });
  await sourceClient.gymForgeExercise.create({
    data: {
      id: "backup-validation-exercise",
      name: "Backup validation exercise"
    }
  });
}

async function verifyRestoredData() {
  assert.equal(
    (await restoredClient.user.findUnique({ where: { id: "backup-validation-user" } }))?.email,
    "backup-validation-user@example.invalid"
  );
  assert.equal(
    (await restoredClient.project.findUnique({ where: { id: "backup-validation-project" } }))?.slug,
    "backup-validation-project"
  );
  assert.equal(
    (await restoredClient.gymForgeParticipant.findUnique({ where: { id: "backup-validation-participant" } }))?.displayName,
    "Backup validation participant"
  );
  assert.equal(
    (await restoredClient.gymForgeExercise.findUnique({ where: { id: "backup-validation-exercise" } }))?.name,
    "Backup validation exercise"
  );
}

async function readMigrations(client) {
  const rows = await client.$queryRaw`SELECT "migration_name" FROM "_prisma_migrations" ORDER BY "started_at" ASC`;
  return rows.map((row) => row.migration_name);
}

async function waitForDatabase() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const result = spawnSync(
      "docker",
      ["inspect", "--format", "{{.State.Health.Status}}", containerName],
      { encoding: "utf8", windowsHide: true, timeout: 10_000 }
    );
    if (result.status === 0 && result.stdout.trim() === "healthy") {
      return;
    }
    await delay(1_000);
  }
  throw new Error("Disposable PostgreSQL did not become healthy.");
}

function readPublishedPort() {
  const result = spawnSync("docker", ["port", containerName, "5432/tcp"], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 10_000
  });
  if (result.status !== 0) {
    throw new Error("Disposable PostgreSQL port could not be read.");
  }
  const match = result.stdout.match(/127\.0\.0\.1:(\d+)/u);
  if (!match) {
    throw new Error("Disposable PostgreSQL port was not loopback-bound.");
  }
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
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error("Disposable Docker validation command failed.");
  }
}

function runDockerBinary(args, input) {
  const result = spawnSync("docker", args, {
    input,
    encoding: null,
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 100 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error("Disposable PostgreSQL backup command failed.");
  }
  return result.stdout;
}
