// Isolated, fail-closed integration proof for @virki/oidc-node on real PostgreSQL 18.
// Usage: node scripts/oidc-node-disposable-postgres.mjs
// No production connection strings, volume mounts or shared Docker resources are used.
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, writeSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAdmittedOidcDockerClient } from "./lib/disposable-docker-session.mjs";
import { assertPrivateEvidenceFile, ensurePrivateEvidenceDirectory,
  ownerEvidenceDirectory } from "./lib/disposable-docker-receipt-security.mjs";

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
let admittedDocker;
let containerStarted = false;
let cleaned = false;
let acknowledgedContainerId;
let uncertainStart = false;
const evidenceDir = ownerEvidenceDirectory(root, "oidc");
const receiptPath = path.join(evidenceDir, `${owner}.jsonl`);
const HEX_CID = /^[a-f0-9]{64}$/u;
let receiptFd = null;
let receiptIdentity;

function record(stage, containerId = null) {
  if (receiptFd === null) {
    ensurePrivateEvidenceDirectory(evidenceDir);
    const parent = path.dirname(evidenceDir);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    if (lstatSync(parent).isSymbolicLink() || !lstatSync(parent).isDirectory()) {
      throw new Error("Disposable evidence parent is not an ordinary directory.");
    }
    mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
    if (lstatSync(evidenceDir).isSymbolicLink() || !lstatSync(evidenceDir).isDirectory()) {
      throw new Error("Disposable evidence directory is not trusted.");
    }
    receiptFd = openSync(receiptPath, "wx", 0o600);
    receiptIdentity = fstatSync(receiptFd, { bigint: true });
    assertPrivateEvidenceFile(receiptPath);
  }
  ensurePrivateEvidenceDirectory(evidenceDir);
  assertPrivateEvidenceFile(receiptPath);
  const link = lstatSync(receiptPath, { bigint: true });
  const pinned = fstatSync(receiptFd, { bigint: true });
  if (!link.isFile() || link.isSymbolicLink() || link.dev !== pinned.dev ||
      link.ino !== pinned.ino || pinned.dev !== receiptIdentity.dev ||
      pinned.ino !== receiptIdentity.ino) {
    throw new Error("Disposable Docker receipt path changed; reconciliation required.");
  }
  const bytes = Buffer.from(JSON.stringify({ stage, name: container, owner, containerId }) + "\n");
  let written = 0;
  while (written < bytes.length) {
    const count = writeSync(receiptFd, bytes, written, bytes.length - written);
    if (!Number.isSafeInteger(count) || count <= 0 || count > bytes.length - written) {
      throw new Error("Disposable Docker receipt write could not be completed.");
    }
    written += count;
  }
  fsyncSync(receiptFd);
  assertPrivateEvidenceFile(receiptPath);
  if (process.platform !== "win32") {
    for (const directory of [evidenceDir, path.dirname(evidenceDir), root]) {
      const directoryFd = openSync(directory, "r");
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    }
  }
}

function docker(args, timeout = 30_000) {
  if (!admittedDocker) throw new Error("No admitted disposable Docker engine.");
  const run = admittedDocker.invoke(args, timeout);
  if (run.error || run.status !== 0) {
    throw new Error(`Disposable Docker operation failed (${args[0]}).`);
  }
  return run.stdout.trim();
}

function cleanup() {
  if (cleaned || !containerStarted) return;
  cleaned = true;
  const inspectFormat = `{{.Id}}|{{.Name}}|{{index .Config.Labels "${label}"}}`;
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
    console.error(`OIDC disposable cleanup uncertain (${stage}); reconcile ${receiptPath}`);
    process.exitCode = 1;
  };
  const parseOwned = (result) => {
    if (result?.error || result?.status !== 0 || typeof result?.stdout !== "string") return null;
    const parts = result.stdout.trim().split("|");
    if (parts.length !== 3 || !HEX_CID.test(parts[0]) ||
        parts[1] !== `/${container}` || parts[2] !== owner) return null;
    return parts[0];
  };
  const target = acknowledgedContainerId ?? container;
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
  console.log("PG18 disposable container cleaned by verified immutable owner ID.");
}

function psql(user, password, db, statement) {
  return docker([
    "exec", "--env", `PGPASSWORD=${password}`, acknowledgedContainerId,
    "psql", "--host", "127.0.0.1", "--username", user, "--dbname", db,
    "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
    "--set", "ON_ERROR_STOP=1", "--command", statement
  ]);
}

process.once("SIGINT", () => { cleanup(); process.exit(130); });
process.once("SIGTERM", () => { cleanup(); process.exit(143); });

try {
  if (!existsSync(tsx)) throw new Error("tsx from Virki's installed local dependencies is unavailable.");
  // Fail closed before touching any Docker resource. Ambient DOCKER_HOST,
  // DOCKER_CONTEXT and Docker CLI overrides must not select remote daemons.
  admittedDocker = createAdmittedOidcDockerClient();
  docker(["image", "inspect", image]);
  // Unique name, ephemeral tmpfs, no mounted host files, and a Docker-allocated loopback port.
  // Persist intent before Docker create: a lost ACK cannot silently orphan DB.
  record("RUN_PENDING");
  containerStarted = true;
  uncertainStart = true;
  const createdId = docker([
    "run", "--detach", "--rm", "--name", container, "--label", `${label}=${owner}`,
    "--publish", "127.0.0.1::5432",
    "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,size=512m",
    "--env", "POSTGRES_USER=postgres",
    "--env", `POSTGRES_PASSWORD=${adminPassword}`,
    "--env", "POSTGRES_DB=postgres", image
  ], 120_000);
  if (!HEX_CID.test(createdId)) throw new Error("Unverified disposable Docker run container ID.");
  acknowledgedContainerId = createdId;
  record("RUN_ACKNOWLEDGED", acknowledgedContainerId);
  uncertainStart = false;
  const bindings = docker(["port", acknowledgedContainerId, "5432/tcp"]);
  if (!/^127\.0\.0\.1:[0-9]+$/u.test(bindings)) throw new Error("PG18 is not bound exclusively to loopback.");
  let ready = false;
  for (let attempt = 0; attempt < 90; attempt++) {
    const health = admittedDocker.invoke(["exec", acknowledgedContainerId, "pg_isready",
      "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"], 5_000);
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
      ...admittedDocker.subprocessEnv,
      VIRKI_OIDC_PG_CONTAINER: acknowledgedContainerId,
      VIRKI_OIDC_PG_ROLE: role,
      VIRKI_OIDC_PG_PASSWORD: rolePassword,
      VIRKI_OIDC_PG_DATABASE: database,
      VIRKI_OIDC_PG_SCHEMA: schema,
      VIRKI_OIDC_TSX_PATH: tsx,
      VIRKI_OIDC_DOCKER_BINARY: admittedDocker.subprocessEnv.VIRKI_OIDC_DOCKER_BINARY
    }
  });
  if (test.error || test.status !== 0) throw new Error("OIDC PostgreSQL integration test failed.");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Disposable PostgreSQL runner failed.");
  process.exitCode = 1;
} finally {
  cleanup();
}
