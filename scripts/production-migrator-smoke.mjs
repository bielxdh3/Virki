import { randomBytes, randomUUID } from "node:crypto";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { createDisposableDockerSession } from "./lib/disposable-docker-session.mjs";

const image = process.env.VIRKI_MIGRATOR_IMAGE?.trim();
if (!image || !/^virki-migrator-ci:[0-9a-f]{40}$/u.test(image)) {
  throw new Error("Migrator smoke requires an exact-revision CI image.");
}

const id = randomUUID();
const network = `virki-migrator-smoke-${id}`;
const databaseContainer = `virki-migrator-db-${id}`;
const deployContainer = `virki-migrator-deploy-${id}`;
const statusContainer = `virki-migrator-status-${id}`;
const databaseHost = `database-${id}`;
const databaseUser = "virki_bootstrap";
const databaseName = "virki_validation";
const bootstrapPassword = randomBytes(32).toString("hex");
const runtimePassword = randomBytes(32).toString("hex");
const migratorPassword = randomBytes(32).toString("hex");
const auditMaintenancePassword = randomBytes(32).toString("hex");
const migrationUrl = `postgresql://virki_migrator:${migratorPassword}@${databaseHost}:5432/${databaseName}?schema=public`;
const roleSetupPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "infra", "postgres-init", "10-virki-database-roles.sh");
const postgresImage = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
let failure = false;
let cleanupFailure = false;
const session = createDisposableDockerSession({
  kind: "migrator", owner: id,
  containers: [databaseContainer, deployContainer, statusContainer], network,
});

try {
  session.mutate("create-network", ["network", "create", "--internal", "--label", `org.virki.validation=${id}`, network]);
  session.mutate("create-database", [
    "run", "--detach", "--name", databaseContainer,
    "--network", network, "--network-alias", databaseHost,
    "--label", `org.virki.validation=${id}`,
    "--env", "POSTGRES_USER", "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB",
    "--env", "VIRKI_RUNTIME_DB_PASSWORD", "--env", "VIRKI_MIGRATOR_DB_PASSWORD", "--env", "VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
    "--volume", `${roleSetupPath}:/docker-entrypoint-initdb.d/10-virki-database-roles.sh:ro`,
    postgresImage,
  ], {
    env: {
      ...process.env,
      POSTGRES_USER: databaseUser,
      POSTGRES_PASSWORD: bootstrapPassword,
      POSTGRES_DB: databaseName,
      VIRKI_RUNTIME_DB_PASSWORD: runtimePassword,
      VIRKI_MIGRATOR_DB_PASSWORD: migratorPassword,
      VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD: auditMaintenancePassword,
    },
  });
  await waitForDatabase();
  const migratorEnv = { ...process.env, MIGRATION_DATABASE_URL: migrationUrl };
  const runtimeSafetyArgs = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m"];
  session.mutate("run-deploy", ["run", ...runtimeSafetyArgs, "--rm", "--name", deployContainer, "--network", network, "--label", `org.virki.validation=${id}`, "--env", "MIGRATION_DATABASE_URL", image, "npm", "run", "prisma:migrate:deploy"], { env: migratorEnv });
  session.mutate("run-status", ["run", ...runtimeSafetyArgs, "--rm", "--name", statusContainer, "--network", network, "--label", `org.virki.validation=${id}`, "--env", "MIGRATION_DATABASE_URL", image, "npm", "run", "prisma:migrate:status"], { env: migratorEnv });
} catch {
  failure = true;
} finally {
  try { session.cleanup(); } catch { cleanupFailure = true; }
  try { session.finish(!failure && !cleanupFailure); } catch { cleanupFailure = true; }
}

if (failure || cleanupFailure) {
  throw new Error(cleanupFailure
    ? "Production migrator image smoke failed or disposable database cleanup could not be confirmed."
    : "Production migrator image could not apply and verify migrations on a disposable database.");
}

console.log(JSON.stringify({ status: "passed", migratorImage: image, migrationsApplied: true,
  disposableDatabaseRemoved: true, disposableRunId: id }));

async function waitForDatabase() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (runDocker(["exec", databaseContainer, "pg_isready", "-h", "127.0.0.1", "-U", databaseUser, "-d", databaseName], { timeout: 10_000 }).ok) return;
    await delay(1_000);
  }
  throw new Error("Disposable PostgreSQL database did not become ready.");
}

function runDocker(args, options = {}) {
  const result = dockerResult(args, options);
  return { ok: !result.error && result.status === 0 };
}

function dockerResult(args, options = {}) {
  return session.invoke(args, options);
}
