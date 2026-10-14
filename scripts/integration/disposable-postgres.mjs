// Starts or stops a loopback-only, tmpfs-backed PostgreSQL for local database integration tests.
// CI runs the same suite against the authenticated-e2e job's disposable database instead.
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const image = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const containerName = "virki-integration-postgres-local";
const database = "virki_integration_test";
const envFile = path.join(os.tmpdir(), "virki-integration-database.env");

function docker(args, options = {}) {
  const result = spawnSync("docker", args, { encoding: "utf8", windowsHide: true, timeout: 120_000, ...options });
  if (result.error || result.status !== 0) throw new Error(`docker ${args[0]} failed.`);
  return result.stdout.trim();
}

const command = process.argv[2];
if (command === "stop") {
  spawnSync("docker", ["rm", "--force", "--volumes", containerName], { windowsHide: true });
  process.exit(0);
}
if (command !== "start") {
  console.error("Usage: node scripts/integration/disposable-postgres.mjs start|stop");
  process.exit(1);
}

const secret = () => randomBytes(32).toString("hex");
const passwords = { bootstrap: secret(), runtime: secret(), migrator: secret(), audit: secret(), test: secret() };
docker([
  "run", "--detach", "--rm", "--name", containerName,
  "--publish", "127.0.0.1::5432",
  "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m",
  "--health-cmd", `pg_isready -h 127.0.0.1 -U virki_bootstrap -d ${database}`,
  "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "90",
  "--env", `POSTGRES_DB=${database}`,
  "--env", "POSTGRES_USER=virki_bootstrap",
  "--env", `POSTGRES_PASSWORD=${passwords.bootstrap}`,
  "--env", `VIRKI_RUNTIME_DB_PASSWORD=${passwords.runtime}`,
  "--env", `VIRKI_MIGRATOR_DB_PASSWORD=${passwords.migrator}`,
  "--env", `VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD=${passwords.audit}`,
  "--env", `VIRKI_E2E_DATABASE_PASSWORD=${passwords.test}`,
  "--volume", `${path.join(root, "infra", "postgres-init", "10-virki-database-roles.sh")}:/docker-entrypoint-initdb.d/10-virki-database-roles.sh:ro`,
  "--volume", `${path.join(root, "scripts", "e2e", "20-virki-e2e-runtime-test-role.sh")}:/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh:ro`,
  image
]);

let healthy = false;
for (let attempt = 0; attempt < 90 && !healthy; attempt += 1) {
  healthy = docker(["inspect", "--format", "{{.State.Health.Status}}", containerName]) === "healthy";
  if (!healthy) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1_000);
}
if (!healthy) throw new Error("Disposable PostgreSQL did not become healthy.");
const mapped = docker(["port", containerName, "5432/tcp"]).split("\n")[0];
if (!mapped.startsWith("127.0.0.1:")) throw new Error("Disposable PostgreSQL port is not loopback-bound.");
const port = mapped.slice("127.0.0.1:".length);
const url = (role, password) => `postgresql://${role}:${password}@127.0.0.1:${port}/${database}?schema=public`;

const migrate = spawnSync(process.execPath, [path.join(root, "packages", "database", "scripts", "prisma-migrate.mjs"), "deploy"], {
  cwd: path.join(root, "packages", "database"),
  env: { ...process.env, MIGRATION_DATABASE_URL: url("virki_migrator", passwords.migrator) },
  stdio: "inherit",
  windowsHide: true
});
if (migrate.status !== 0) throw new Error("Committed migrations could not be applied.");

writeFileSync(envFile, [
  `VIRKI_INTEGRATION_DATABASE_URL=${url("virki_runtime_test", passwords.test)}`,
  "VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable",
  ""
].join("\n"), { mode: 0o600 });
chmodSync(envFile, 0o600);
console.log(`Disposable PostgreSQL ready. Environment written to ${envFile}`);
