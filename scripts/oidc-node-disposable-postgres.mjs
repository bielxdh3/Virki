// Isolated, fail-closed integration proof for @virki/oidc-node on real PostgreSQL 18.
// Usage: node scripts/oidc-node-disposable-postgres.mjs
// No production connection strings, volume mounts or shared Docker resources are used.
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const container = `virki-oidc-pg18-${randomUUID()}`;
const owner = randomUUID();
const label = "org.virki.oidc-disposable-owner";
const image = "postgres:18.6-alpine3.24";
const database = "rp_oidc_proof";
const role = "rp_oidc_owner";
const schema = "rp_oidc_private";
const adminPassword = randomBytes(32).toString("hex");
const rolePassword = randomBytes(32).toString("hex");
const tsx = process.env.VIRKI_OIDC_TSX_PATH || path.resolve(root, "node_modules", "tsx", "dist", "cli.mjs");
const dockerBinary = process.env.VIRKI_OIDC_DOCKER_BINARY || "docker";
let containerStarted = false;
let cleaned = false;

function docker(args, timeout = 30_000) {
  const run = spawnSync(dockerBinary, args, {
    encoding: "utf8", windowsHide: true, timeout, maxBuffer: 128 * 1024
  });
  if (run.error || run.status !== 0) {
    throw new Error(`Disposable Docker operation failed (${args[0]}).`);
  }
  return run.stdout.trim();
}

function cleanup() {
  if (cleaned || !containerStarted) return;
  cleaned = true;
  const inspected = spawnSync(dockerBinary, [
    "inspect", "--format", `{{index .Config.Labels "${label}"}}`, container
  ], { encoding: "utf8", windowsHide: true, timeout: 15_000 });
  if (inspected.status !== 0) return; // --rm may have already completed cleanup.
  if (inspected.stdout.trim() !== owner) {
    console.error("Disposable PostgreSQL ownership mismatch; no cleanup attempted.");
    process.exitCode = 1;
    return;
  }
  const removed = spawnSync(dockerBinary, ["rm", "--force", "--volumes", container], {
    encoding: "utf8", windowsHide: true, timeout: 30_000
  });
  if (removed.status !== 0) {
    console.error("Disposable PostgreSQL owned container cleanup failed.");
    process.exitCode = 1;
  } else {
    console.log("PG18 disposable container cleaned by exact owner label.");
  }
}

function psql(user, password, db, statement) {
  return docker([
    "exec", "--env", `PGPASSWORD=${password}`, container,
    "psql", "--host", "127.0.0.1", "--username", user, "--dbname", db,
    "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
    "--set", "ON_ERROR_STOP=1", "--command", statement
  ]);
}

process.once("SIGINT", () => { cleanup(); process.exit(130); });
process.once("SIGTERM", () => { cleanup(); process.exit(143); });

try {
  if (!existsSync(tsx)) throw new Error("tsx from Virki's installed local dependencies is unavailable.");
  docker(["image", "inspect", image]);
  // Unique name, ephemeral tmpfs, no mounted host files, and a Docker-allocated loopback port.
  // Even an uncertain docker-run exit is inspected for our exact owner label in finally.
  containerStarted = true;
  docker([
    "run", "--detach", "--rm", "--name", container, "--label", `${label}=${owner}`,
    "--publish", "127.0.0.1::5432",
    "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,size=512m",
    "--env", "POSTGRES_USER=postgres",
    "--env", `POSTGRES_PASSWORD=${adminPassword}`,
    "--env", "POSTGRES_DB=postgres", image
  ], 120_000);
  const bindings = docker(["port", container, "5432/tcp"]);
  if (!/^127\.0\.0\.1:[0-9]+$/u.test(bindings)) throw new Error("PG18 is not bound exclusively to loopback.");
  let ready = false;
  for (let attempt = 0; attempt < 90; attempt++) {
    const health = spawnSync(dockerBinary, ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"], {
      encoding: "utf8", windowsHide: true, timeout: 5_000
    });
    if (health.status === 0) { ready = true; break; }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  if (!ready) throw new Error("Disposable PG18 startup health check failed.");

  psql("postgres", adminPassword, "postgres", `CREATE ROLE ${role} LOGIN PASSWORD '${rolePassword}'`);
  psql("postgres", adminPassword, "postgres", `CREATE DATABASE ${database} OWNER ${role}`);
  psql("postgres", adminPassword, database, `SET ROLE ${role}; CREATE SCHEMA ${schema} AUTHORIZATION ${role}; CREATE TABLE ${schema}."VirkiOidcLoginFlow" ("stateHash" text PRIMARY KEY, "ciphertext" text NOT NULL, "expiresAt" timestamptz NOT NULL); RESET ROLE`);
  psql("postgres", adminPassword, database, `ALTER ROLE ${role} IN DATABASE ${database} SET search_path = ${schema}`);
  psql("postgres", adminPassword, database, `ALTER ROLE ${role} IN DATABASE ${database} SET TimeZone = 'America/Porto_Velho'`);
  const version = psql(role, rolePassword, database, "SHOW server_version").split(".")[0];
  if (version !== "18") throw new Error("Unexpected PostgreSQL major version.");
  console.log("PG18 ready: isolated RP-owned schema, loopback-only port, America/Porto_Velho.");

  const test = spawnSync(process.execPath, [
    tsx, "--test", path.join(root, "packages", "oidc-node", "src", "postgres-store.integration.test.ts")
  ], {
    cwd: root, stdio: "inherit", windowsHide: true, timeout: 210_000,
    env: {
      ...process.env,
      VIRKI_OIDC_PG_CONTAINER: container,
      VIRKI_OIDC_PG_ROLE: role,
      VIRKI_OIDC_PG_PASSWORD: rolePassword,
      VIRKI_OIDC_PG_DATABASE: database,
      VIRKI_OIDC_PG_SCHEMA: schema,
      VIRKI_OIDC_TSX_PATH: tsx,
      VIRKI_OIDC_DOCKER_BINARY: dockerBinary
    }
  });
  if (test.error || test.status !== 0) throw new Error("OIDC PostgreSQL integration test failed.");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Disposable PostgreSQL runner failed.");
  process.exitCode = 1;
} finally {
  cleanup();
}
