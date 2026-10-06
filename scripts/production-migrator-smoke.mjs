import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const image = process.env.BIELOS_MIGRATOR_IMAGE?.trim();
if (!image || !/^bielos-migrator-ci:[0-9a-f]{40}$/u.test(image)) {
  throw new Error("Migrator smoke requires an exact-revision CI image.");
}

const id = randomUUID();
const network = `bielos-migrator-smoke-${id}`;
const databaseContainer = `bielos-migrator-db-${id}`;
const databaseHost = `database-${id}`;
const databaseUser = "bielos_bootstrap";
const databaseName = "bielos_validation";
const bootstrapPassword = randomBytes(32).toString("hex");
const runtimePassword = randomBytes(32).toString("hex");
const migratorPassword = randomBytes(32).toString("hex");
const auditMaintenancePassword = randomBytes(32).toString("hex");
const migrationUrl = `postgresql://bielos_migrator:${migratorPassword}@${databaseHost}:5432/${databaseName}?schema=public`;
const roleSetupPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "infra", "postgres-init", "10-bielos-database-roles.sh");
const postgresImage = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
let networkCreated = false;
let databaseCreated = false;
let failure = false;
let cleanupFailure = false;

try {
  requireDocker(["network", "create", "--internal", network]);
  networkCreated = true;
  requireDocker([
    "run", "--detach", "--name", databaseContainer,
    "--network", network, "--network-alias", databaseHost,
    "--label", `org.bielos.validation=${id}`,
    "--env", "POSTGRES_USER", "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB",
    "--env", "BIELOS_RUNTIME_DB_PASSWORD", "--env", "BIELOS_MIGRATOR_DB_PASSWORD", "--env", "BIELOS_AUDIT_MAINTENANCE_DB_PASSWORD",
    "--volume", `${roleSetupPath}:/docker-entrypoint-initdb.d/10-bielos-database-roles.sh:ro`,
    postgresImage,
  ], {
    env: {
      ...process.env,
      POSTGRES_USER: databaseUser,
      POSTGRES_PASSWORD: bootstrapPassword,
      POSTGRES_DB: databaseName,
      BIELOS_RUNTIME_DB_PASSWORD: runtimePassword,
      BIELOS_MIGRATOR_DB_PASSWORD: migratorPassword,
      BIELOS_AUDIT_MAINTENANCE_DB_PASSWORD: auditMaintenancePassword,
    },
  });
  databaseCreated = true;
  await waitForDatabase();
  const migratorEnv = { ...process.env, MIGRATION_DATABASE_URL: migrationUrl };
  const runtimeSafetyArgs = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m"];
  requireDocker(["run", ...runtimeSafetyArgs, "--rm", "--network", network, "--env", "MIGRATION_DATABASE_URL", image, "npm", "run", "prisma:migrate:deploy"], { env: migratorEnv });
  requireDocker(["run", ...runtimeSafetyArgs, "--rm", "--network", network, "--env", "MIGRATION_DATABASE_URL", image, "npm", "run", "prisma:migrate:status"], { env: migratorEnv });
} catch {
  failure = true;
} finally {
  if (databaseCreated && !runDocker(["rm", "--force", "--volumes", databaseContainer]).ok) cleanupFailure = true;
  if (networkCreated && !runDocker(["network", "rm", network]).ok) cleanupFailure = true;
}

if (failure || cleanupFailure) {
  throw new Error(cleanupFailure
    ? "Production migrator image smoke failed or disposable database cleanup could not be confirmed."
    : "Production migrator image could not apply and verify migrations on a disposable database.");
}

console.log(JSON.stringify({ status: "passed", migratorImage: image, migrationsApplied: true, disposableDatabaseRemoved: true }));

async function waitForDatabase() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (runDocker(["exec", databaseContainer, "pg_isready", "-h", "127.0.0.1", "-U", databaseUser, "-d", databaseName], { timeout: 10_000 }).ok) return;
    await delay(1_000);
  }
  throw new Error("Disposable PostgreSQL database did not become ready.");
}

function requireDocker(args, options = {}) {
  if (!runDocker(args, options).ok) throw new Error("Docker command failed.");
}

function runDocker(args, options = {}) {
  const result = spawnSync("docker", args, {
    env: options.env ?? process.env,
    encoding: "utf8",
    windowsHide: true,
    timeout: options.timeout ?? 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  return { ok: !result.error && result.status === 0 };
}
