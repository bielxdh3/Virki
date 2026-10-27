// A unique, self-owned PostgreSQL container for #58 protocol/adversarial tests.
// Never reuses or stops the repository's shared integration container.
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, writeSync } from "node:fs";
import path from "node:path";
import { createAdmittedOidcDockerClient } from "./lib/disposable-docker-session.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const name = `virki-passkeys-${randomUUID().slice(0, 12)}`;
const secret = () => randomBytes(32).toString("hex");
const passwords = { bootstrap: secret(), runtime: secret(), migrator: secret(), audit: secret(), test: secret() };
const db = "virki_passkey_test";
const owner = randomUUID();
const ownerLabel = "org.virki.passkeys-disposable-owner";
let started = false;
let admittedDocker;
let acknowledgedContainerId;
let uncertainStart = false;
const evidenceDir = path.join(root, ".virki-mission-tmp", "passkeys-docker-recovery");
const receiptPath = path.join(evidenceDir, `${owner}.jsonl`);
const HEX_CID = /^[a-f0-9]{64}$/u;
let receiptFd = null;
let receiptIdentity;

function record(stage, containerId = null) {
  if (receiptFd === null) {
    const parent = path.dirname(evidenceDir);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    if (lstatSync(parent).isSymbolicLink() || !lstatSync(parent).isDirectory()) {
      throw new Error("Disposable evidence parent is not an ordinary directory.");
    }
    mkdirSync(evidenceDir, { mode: 0o700, recursive: true });
    if (lstatSync(evidenceDir).isSymbolicLink() || !lstatSync(evidenceDir).isDirectory()) {
      throw new Error("Disposable evidence directory is not trusted.");
    }
    receiptFd = openSync(receiptPath, "wx", 0o600);
    receiptIdentity = fstatSync(receiptFd, { bigint: true });
  }
  const link = lstatSync(receiptPath, { bigint: true });
  const pinned = fstatSync(receiptFd, { bigint: true });
  if (!link.isFile() || link.isSymbolicLink() || link.dev !== pinned.dev ||
      link.ino !== pinned.ino || pinned.dev !== receiptIdentity.dev ||
      pinned.ino !== receiptIdentity.ino) {
    throw new Error("Disposable Docker receipt path changed; reconciliation required.");
  }
  writeSync(receiptFd, JSON.stringify({ stage, name, owner, containerId }) + "\n");
  fsyncSync(receiptFd);
  // On POSIX also persist each directory entry before Docker mutations.
  if (process.platform !== "win32") {
    for (const directory of [evidenceDir, path.dirname(evidenceDir), root]) {
      const directoryFd = openSync(directory, "r");
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    }
  }
}

function docker(args, max = 60_000) {
  if (!admittedDocker) throw new Error("No admitted disposable Docker engine.");
  const result = admittedDocker.invoke(args, max);
  if (result?.error || result?.status !== 0) throw new Error(`Disposable docker ${args[0]} failed.`);
  return result.stdout.trim();
}

function cleanup() {
  if (!started) return;
  const inspectFormat = `{{.Id}}|{{.Name}}|{{index .Config.Labels "${ownerLabel}"}}`;
  const invokeInspect = (target) => admittedDocker.invoke([
    "inspect", "--format", inspectFormat, target
  ], 15_000);
  const missing = (result, target) => {
    if (result?.error || result?.status === 0 || typeof result?.stderr !== "string") return false;
    const lastLine = result.stderr.trim().split(/\r?\n/u).at(-1);
    return [
      `Error: No such object: ${target}`,
      `Error response from daemon: No such container: ${target}`,
      `Error response from daemon: No such object: ${target}`
    ].includes(lastLine);
  };
  const failCleanup = (stage) => {
    record("RECONCILIATION_REQUIRED:" + stage, acknowledgedContainerId ?? null);
    console.error(`Passkey disposable cleanup uncertain (${stage}); reconcile ${receiptPath}`);
    process.exitCode = 1;
  };
  const parseOwned = (result) => {
    if (result?.error || result?.status !== 0 || typeof result?.stdout !== "string") return null;
    const parts = result.stdout.trim().split("|");
    if (parts.length !== 3 || !HEX_CID.test(parts[0]) ||
        parts[1] !== `/${name}` || parts[2] !== owner) return null;
    return parts[0];
  };
  const target = acknowledgedContainerId ?? name;
  const inspected = invokeInspect(target);
  if (missing(inspected, target)) {
    if (uncertainStart) failCleanup("lost-run-ack-absent-not-proof");
    else record("AUTO_REMOVED_CONFIRMED", acknowledgedContainerId);
    return;
  }
  const foundId = parseOwned(inspected);
  if (!foundId || (acknowledgedContainerId && acknowledgedContainerId !== foundId)) {
    failCleanup("foreign-or-invalid-inspection");
    return;
  }
  // Do not remove by a mutable name. An ID cannot be reassigned to a new
  // container if an adversary swaps the name between inspect and rm.
  if (parseOwned(invokeInspect(foundId)) !== foundId) {
    failCleanup("identity-changed-before-removal");
    return;
  }
  record("REMOVE_PENDING", foundId);
  const removed = admittedDocker.invoke(["rm", "--force", "--volumes", foundId], 30_000);
  if (removed?.error || removed?.status !== 0 || !missing(invokeInspect(foundId), foundId)) {
    failCleanup("removal-unconfirmed");
    return;
  }
  record("CLEANUP_CONFIRMED", foundId);
}

try {
  admittedDocker = createAdmittedOidcDockerClient();
  // Durable owner/name intent MUST exist before an uncertain Docker run.
  record("RUN_PENDING");
  started = true;
  uncertainStart = true;
  const createdId = docker([
    "run", "--detach", "--rm", "--name", name, "--label", `${ownerLabel}=${owner}`,
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
  if (!HEX_CID.test(createdId)) throw new Error("Unverified disposable Docker run container ID.");
  acknowledgedContainerId = createdId;
  record("RUN_ACKNOWLEDGED", acknowledgedContainerId);
  uncertainStart = false;
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
    ...admittedDocker.subprocessEnv, NODE_ENV: "test", VIRKI_INTEGRATION_ENABLED: "true",
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
  cleanup();
}
