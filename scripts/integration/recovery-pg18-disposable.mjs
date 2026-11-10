// Mandatory, isolated physical PostgreSQL 18 integration proof for recovery.
// Each suite gets a new owner-labelled Docker container, DB and scoped roles.
// This never selects the ambient Docker context or an existing test database.
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, writeSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAdmittedOidcDockerClient } from "../lib/disposable-docker-session.mjs";
import { assertPrivatePg18ReceiptFile, ensurePrivatePg18ReceiptDirectory,
  pg18ReceiptDirectory } from "./local-pg18-receipt.mjs";
import { RECOVERY_PG18_IMAGE, RECOVERY_PG18_SUITES, privateRecoveryDockerAdmissionEnvironment,
  privateRecoveryTestEnvironment, requireExactRecoveryPg18Tap, requireRecoveryPg18ContainerImage,
  requireRecoveryPg18ImagePlatform,
  verifiedRecoveryPg18LocalImage } from "./recovery-pg18-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const label = "org.virki.recovery-pg18-disposable-owner";
const hexCid = /^[a-f0-9]{64}$/u;
const secret = () => randomBytes(32).toString("hex");
const delay = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1_000);
let activeCleanup = null;
for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  process.once(signal, () => {
    try { activeCleanup?.(); } catch (error) {
      console.error(error instanceof Error ? error.message : "Private PG18 signal cleanup failed.");
    }
    process.exit(code);
  });
}

function runSuite(suite) {
  const owner = randomUUID();
  const name = `virki-recovery-pg18-${owner}`;
  const database = `${suite.databasePrefix}${randomUUID().replaceAll("-", "")}`;
  const passwords = { bootstrap: secret(), runtime: secret(), migrator: secret(), audit: secret(), test: secret() };
  const receiptDirectory = pg18ReceiptDirectory(root);
  const receiptPath = path.join(receiptDirectory, `${owner}.jsonl`);
  let dockerClient;
  let receiptFd = null;
  let receiptIdentity;
  let started = false;
  let uncertainStart = false;
  let containerId;
  const initRoles = path.join(root, "infra", "postgres-init", "10-virki-database-roles.sh");
  const initTestRole = path.join(root, "scripts", "e2e", "20-virki-e2e-runtime-test-role.sh");

  function record(stage, id = null) {
    if (receiptFd === null) {
      ensurePrivatePg18ReceiptDirectory(receiptDirectory);
      const parent = path.dirname(receiptDirectory);
      mkdirSync(parent, { recursive: true, mode: 0o700 });
      for (const folder of [parent, receiptDirectory]) {
        if (folder === receiptDirectory) mkdirSync(folder, { recursive: true, mode: 0o700 });
        const state = lstatSync(folder);
        if (!state.isDirectory() || state.isSymbolicLink()) throw new Error("Unsafe disposable receipt directory.");
        if (process.platform !== "win32" &&
            (state.uid !== process.getuid() || (state.mode & 0o077) !== 0)) {
          throw new Error("Disposable receipt directory must be private and owned by this process.");
        }
      }
      receiptFd = openSync(receiptPath, "wx", 0o600);
      receiptIdentity = fstatSync(receiptFd, { bigint: true });
      assertPrivatePg18ReceiptFile(receiptPath);
    }
    ensurePrivatePg18ReceiptDirectory(receiptDirectory);
    assertPrivatePg18ReceiptFile(receiptPath);
    const link = lstatSync(receiptPath, { bigint: true });
    const opened = fstatSync(receiptFd, { bigint: true });
    if (!link.isFile() || link.isSymbolicLink() || link.nlink !== 1n ||
        ["dev", "ino", "mode", "nlink"].some((field) =>
          link[field] !== receiptIdentity[field] || opened[field] !== receiptIdentity[field])) {
      throw new Error("Disposable owner receipt identity changed.");
    }
    const bytes = Buffer.from(JSON.stringify({ stage, owner, name, containerId: id }) + "\n");
    for (let offset = 0; offset < bytes.length;) {
      const n = writeSync(receiptFd, bytes, offset, bytes.length - offset);
      if (!Number.isSafeInteger(n) || n <= 0 || n > bytes.length - offset) throw new Error("Incomplete owner receipt write.");
      offset += n;
    }
    fsyncSync(receiptFd);
    assertPrivatePg18ReceiptFile(receiptPath);
    if (process.platform !== "win32") {
      for (const folder of [receiptDirectory, path.dirname(receiptDirectory), root]) {
        const fd = openSync(folder, "r");
        try { fsyncSync(fd); } finally { closeSync(fd); }
      }
    }
  }

  function docker(args, timeout = 30_000) {
    if (!dockerClient) throw new Error("No admitted local Docker engine.");
    const result = dockerClient.invoke(args, timeout);
    if (result?.error || result?.status !== 0 || typeof result.stdout !== "string") {
      throw new Error(`Private PG18 Docker ${args[0]} failed.`);
    }
    return result.stdout.trim();
  }

  function cleanup() {
    if (!started) return;
    const inspectFormat = `{{.Id}}|{{.Name}}|{{index .Config.Labels "${label}"}}`;
    const inspect = (target) => dockerClient.invoke(["inspect", "--format", inspectFormat, target], 15_000);
    const missing = (result, target) => {
      if (result?.error || result?.status === 0 || typeof result?.stderr !== "string") return false;
      return [
        `Error: No such object: ${target}`,
        `Error response from daemon: No such container: ${target}`,
        `Error response from daemon: No such object: ${target}`,
        // Docker Desktop 29.x uses this exact lowercase diagnostic after rm.
        `error: no such object: ${target}`
      ].includes(result.stderr.trim().split(/\r?\n/u).at(-1));
    };
    const fail = (stage) => {
      record(`RECONCILIATION_REQUIRED:${stage}`, containerId ?? null);
      throw new Error(`Private PG18 cleanup uncertain (${stage}); reconcile ${receiptPath}`);
    };
    const owned = (result) => {
      if (result?.error || result?.status !== 0 || typeof result?.stdout !== "string") return null;
      const parts = result.stdout.trim().split("|");
      return parts.length === 3 && hexCid.test(parts[0]) &&
        parts[1] === `/${name}` && parts[2] === owner ? parts[0] : null;
    };
    const target = containerId ?? name;
    const inspected = inspect(target);
    if (missing(inspected, target)) {
      if (uncertainStart) fail("lost-run-ack-absent-is-not-proof");
      record("AUTO_REMOVED_CONFIRMED", containerId);
      return;
    }
    const id = owned(inspected);
    if (!id || (containerId && id !== containerId)) fail("foreign-container-or-identity");
    if (owned(inspect(id)) !== id) fail("identity-changed-before-delete");
    record("REMOVE_PENDING", id);
    const removed = dockerClient.invoke(["rm", "--force", "--volumes", id], 30_000);
    if (removed?.error || removed?.status !== 0 || !missing(inspect(id), id)) {
      fail("removal-unconfirmed");
    }
    record("CLEANUP_CONFIRMED", id);
  }

  let result = 0;
  try {
    for (const file of [initRoles, initTestRole]) {
      const state = lstatSync(file);
      if (!state.isFile() || state.isSymbolicLink()) {
        throw new Error("Private PG18 initialization script is missing or aliased.");
      }
    }
    dockerClient = createAdmittedOidcDockerClient({ env: privateRecoveryDockerAdmissionEnvironment() });
    activeCleanup = cleanup;
    // Pin the OCI index digest, then independently check the locally resolved
    // image ID and RepoDigests. Never trust the mutable tag or `docker run`
    // success alone as proof of which image the daemon actually selected.
    record("IMAGE_PULL_PENDING");
    docker(["pull", "--quiet", RECOVERY_PG18_IMAGE], 180_000);
    const verifiedImageId = verifiedRecoveryPg18LocalImage(docker([
      "image", "inspect", "--format", "{{.Id}}|{{json .RepoDigests}}", RECOVERY_PG18_IMAGE
    ]));
    requireRecoveryPg18ImagePlatform(docker([
      "image", "inspect", "--format", "{{.Os}}|{{.Architecture}}", RECOVERY_PG18_IMAGE
    ]));
    record("IMAGE_DIGEST_VERIFIED");
    // A separate durable RUN_PENDING receipt precedes container creation.
    record("RUN_PENDING");
    started = true;
    uncertainStart = true;
    const created = docker([
      "run", "--detach", "--rm", "--name", name, "--label", `${label}=${owner}`,
      "--publish", "127.0.0.1::5432",
      "--tmpfs", "/var/lib/postgresql:rw,noexec,nosuid,nodev,size=512m",
      "--health-cmd", `pg_isready -h 127.0.0.1 -U virki_bootstrap -d ${database}`,
      "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "90",
      "--env", `POSTGRES_DB=${database}`, "--env", "POSTGRES_USER=virki_bootstrap",
      "--env", `POSTGRES_PASSWORD=${passwords.bootstrap}`,
      "--env", `VIRKI_RUNTIME_DB_PASSWORD=${passwords.runtime}`,
      "--env", `VIRKI_MIGRATOR_DB_PASSWORD=${passwords.migrator}`,
      "--env", `VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD=${passwords.audit}`,
      "--env", `VIRKI_E2E_DATABASE_PASSWORD=${passwords.test}`,
      "--mount", `type=bind,source=${initRoles},target=/docker-entrypoint-initdb.d/10-virki-database-roles.sh,readonly`,
      "--mount", `type=bind,source=${initTestRole},target=/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh,readonly`,
      RECOVERY_PG18_IMAGE
    ], 120_000);
    if (!hexCid.test(created)) throw new Error("Unverified private PG18 Docker container ID.");
    containerId = created;
    record("RUN_ACKNOWLEDGED", containerId);
    uncertainStart = false;
    requireRecoveryPg18ContainerImage(docker([
      "inspect", "--format", "{{.Image}}|{{.Config.Image}}", containerId
    ]), verifiedImageId);
    let healthy = false;
    for (let i = 0; i < 90; i++) {
      const status = docker(["inspect", "--format", "{{.State.Health.Status}}", containerId]);
      if (status === "healthy") { healthy = true; break; }
      if (status === "unhealthy") throw new Error("Private PG18 initialization was unhealthy.");
      delay();
    }
    if (!healthy) throw new Error("Private PG18 initialization timed out.");
    const mapped = docker(["port", containerId, "5432/tcp"]);
    if (!/^127\.0\.0\.1:([1-9][0-9]{0,4})$/u.test(mapped) || Number(mapped.split(":")[1]) > 65535) {
      throw new Error("Private PG18 must bind exclusively to loopback.");
    }
    const version = docker(["exec", containerId, "psql", "--username", "virki_bootstrap", "--dbname", database,
      "--no-psqlrc", "--tuples-only", "--no-align", "--command", "SHOW server_version_num"]);
    if (!/^18[0-9]{4}$/u.test(version)) throw new Error("Private recovery database is not PostgreSQL 18.");

    const port = mapped.slice("127.0.0.1:".length);
    const url = (role, password) => `postgresql://${role}:${password}@127.0.0.1:${port}/${database}?schema=public`;
    const testUrl = url("virki_runtime_test", passwords.test);
    const env = privateRecoveryTestEnvironment({
      databaseUrl: testUrl, migrationUrl: url("virki_migrator", passwords.migrator), secret
    });
    const migrate = spawnSync(process.execPath,
      [path.join(root, "packages", "database", "scripts", "prisma-migrate.mjs"), "deploy"],
      { cwd: root, env, encoding: "utf8", windowsHide: true, timeout: 180_000, maxBuffer: 2 * 1024 * 1024 });
    if (migrate.error || migrate.status !== 0) throw new Error(`Private PG18 migration failed for ${suite.kind}.`);
    // Reapply the fixture grants after migrations. Scripts are mounted only in
    // this owned container; never touch another DB or a system PostgreSQL.
    docker(["exec", "--env", `POSTGRES_DB=${database}`,
      "--env", "POSTGRES_USER=virki_bootstrap", "--env", `VIRKI_E2E_DATABASE_PASSWORD=${passwords.test}`,
      containerId, "sh", "/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh"]);
    const tested = spawnSync(process.execPath,
      [path.join(root, "scripts", "integration", "run.mjs"), suite.file],
      { cwd: root, env, encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 });
    if (tested.error || tested.status !== 0) throw new Error(`Private PG18 ${suite.kind} integration failed.`);
    // Insist on exact named TAP results, not just a zero exit status.
    requireExactRecoveryPg18Tap(tested.stdout, suite);
  } catch (error) {
    result = 1;
    console.error(error instanceof Error ? error.message : "Private PG18 recovery proof failed.");
  } finally {
    try { cleanup(); } catch (error) {
      result = 1;
      console.error(error instanceof Error ? error.message : "Private PG18 cleanup failed.");
    }
    activeCleanup = null;
    if (receiptFd !== null) closeSync(receiptFd);
  }
  if (result !== 0) throw new Error(`Private PG18 ${suite.kind} did not complete safely.`);
  console.log(`PG18 RECOVERY PASS: ${suite.kind} ${suite.names.length} named tests, zero SKIP/FAIL, owned container removed.`);
}

try {
  for (const suite of RECOVERY_PG18_SUITES) runSuite(suite);
  console.log("PG18 RECOVERY REQUIRED GATE: 9 real PASS, 0 FAIL, 0 SKIP, both disposable containers removed.");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Private PG18 recovery runner failed.");
  process.exitCode = 1;
}
