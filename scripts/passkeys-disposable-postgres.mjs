// A unique, self-owned PostgreSQL container for #58 protocol/adversarial tests.
// Never reuses or stops the repository's shared integration container.
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const name = `virki-passkeys-${randomUUID().slice(0, 12)}`;
const secret = () => randomBytes(32).toString("hex");
const passwords = { bootstrap: secret(), runtime: secret(), migrator: secret(), audit: secret(), test: secret() };
const db = "virki_passkey_test";
let started = false;

function docker(args, max = 60_000) {
  const result = spawnSync("docker", args, { cwd: root, encoding: "utf8", windowsHide: true, timeout: max });
  if (result.error || result.status !== 0) throw new Error(`Disposable docker ${args[0]} failed: ${result.stderr?.slice(0, 1000) ?? "unknown"}`);
  return result.stdout.trim();
}

try {
  docker([
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql:rw,noexec,nosuid,nodev,size=512m",
    "--health-cmd", `pg_isready -h 127.0.0.1 -U virki_bootstrap -d ${db}`,
    "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "90",
    "--env", `POSTGRES_DB=${db}`, "--env", "POSTGRES_USER=virki_bootstrap",
    "--env", `POSTGRES_PASSWORD=${passwords.bootstrap}`,
    "--env", `VIRKI_RUNTIME_DB_PASSWORD=${passwords.runtime}`,
    "--env", `VIRKI_MIGRATOR_DB_PASSWORD=${passwords.migrator}`,
    "--env", `VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD=${passwords.audit}`,
    "--env", `VIRKI_E2E_DATABASE_PASSWORD=${passwords.test}`,
    "--volume", `${path.join(root, "infra", "postgres-init", "10-virki-database-roles.sh")}:/docker-entrypoint-initdb.d/10-virki-database-roles.sh:ro`,
    "--volume", `${path.join(root, "scripts", "e2e", "20-virki-e2e-runtime-test-role.sh")}:/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh:ro`,
    "postgres:18.6-alpine3.24"
  ], 90_000);
  started = true;
  let healthy = false;
  for (let i = 0; i < 90; i++) {
    const status = docker(["inspect", "--format", "{{.State.Health.Status}}", name]);
    if (status === "healthy") { healthy = true; break; }
    if (status === "unhealthy") throw new Error("Disposable PostgreSQL initialization failed");
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1_000);
  }
  if (!healthy) throw new Error("Disposable PostgreSQL did not become healthy");
  const mapped = docker(["port", name, "5432/tcp"]).split("\n")[0];
  if (!/^127\.0\.0\.1:\d+$/u.test(mapped)) throw new Error("Database port was not exclusively loopback-bound");
  const port = mapped.slice("127.0.0.1:".length);
  const url = (role, password) => `postgresql://${role}:${password}@127.0.0.1:${port}/${db}?schema=public`;
  const env = {
    ...process.env, NODE_ENV: "test", VIRKI_INTEGRATION_ENABLED: "true",
    VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
    VIRKI_PASSKEYS_ENABLED: "true",
    VIRKI_PASSKEYS_NON_UTC_REQUIRED: "true",
    DATABASE_URL: url("virki_runtime_test", passwords.test),
    MIGRATION_DATABASE_URL: url("virki_migrator", passwords.migrator),
    VIRKI_OIDC_ADAPTER_KEY: randomBytes(32).toString("hex")
  };
  const migrate = spawnSync(process.execPath, [path.join(root, "packages", "database", "scripts", "prisma-migrate.mjs"), "deploy"], { cwd: root, env, stdio: "inherit", windowsHide: true, timeout: 180_000 });
  if (migrate.status !== 0 || migrate.error) throw new Error("Disposable migration failed");
  // Force the database session away from UTC so TIMESTAMP vs TIMESTAMPTZ
  // conversion mistakes cannot masquerade as correct session expiry checks.
  docker(["exec", name, "psql", "--username", "virki_bootstrap", "--dbname", db,
    "--set", "ON_ERROR_STOP=1", "--command", `ALTER DATABASE ${db} SET TIMEZONE TO 'America/Porto_Velho'`]);
  const tsxCli = createRequire(import.meta.url).resolve("tsx/cli");
  const suite = spawnSync(process.execPath, [tsxCli, "--test", "packages/auth/src/passkeys.integration.test.ts"], { cwd: root, env, stdio: "inherit", windowsHide: true, timeout: 180_000 });
  if (suite.status !== 0 || suite.error) throw new Error("Passkey disposable integration suite failed");
  console.log("PASS #58 isolated PostgreSQL migration + adversarial WebAuthn integration");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Passkey test harness failed");
  process.exitCode = 1;
} finally {
  if (started) {
    try { docker(["rm", "--force", "--volumes", name]); } catch { console.error("Could not remove the uniquely named disposable container"); process.exitCode = 1; }
  }
}
