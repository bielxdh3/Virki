#!/usr/bin/env node
// Dev-only full PostgreSQL backup -> independent pg_restore -> REAL Prisma CLI
// migrate resolve/deploy/status -> schema+history health -> rollback clone.
// Both containers use Docker --network=none; only one owned disposable socket
// volume (NEVER PGDATA) connects them. Absolutely no host ports or SSH.
// No container is touched without matching random owner, pinned image and CID.
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  POSTGRES, NODE, OWNER_LABEL, planDisposablePrismaNative,
  assertPrismaNativeDockerMetadata,
} from "./lib/offline-prisma-native-container.mjs";
import { assertDisposablePgDockerEnvironment, requireSignedPgDockerCli } from "./lib/offline-pg-docker-transport.mjs";
import { runProtectedWindowsJournalOperation } from "../infra/offline/disposable-local-docker.mjs";
import {
  verifyCommittedStage2PrismaMigrations, verifyDisposablePrismaDatabaseHistory,
} from "./lib/offline-prisma-native-source.mjs";
import {
  isVerifiedPrismaInvocationResult, isVerifiedSuccessfulCleanup,
} from "./lib/offline-prisma-native-result.mjs";
import {
  INTERRUPT_TIMING, assertCommittedFirstDdl, deriveBlockedDdlProbe,
  deriveBlockedDdlBackendIdentityProbe, parseBlockedDdlBackendIdentity,
  deriveBlockedDdlBackendTermination, deriveBlockedDdlBackendAbsence,
} from "./lib/offline-prisma-native-ddl-observation.mjs";
import {
  classifyPrismaPostkillExit, assertPrismaPostkillDatabaseState,
} from "./lib/offline-prisma-postkill.mjs";

const ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine";
const INSPECT = "{{json .}}";
const HEX_ID = /^[a-f0-9]{64}$/u;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/u;
const URL_SOURCE = "postgresql://postgres@localhost:5432/virki_source?host=/var/run/postgresql";
const URL_CLONE = "postgresql://postgres@localhost:5432/virki_clone?host=/var/run/postgresql";
const URL_ROLLBACK = "postgresql://postgres@localhost:5432/virki_rollback?host=/var/run/postgresql";
// Deliberately nonexistent database on the SAME private Unix socket. The
// actual Prisma CLI must reject it with P1003 before valid migration deploy.
const URL_MISSING = "postgresql://postgres@localhost:5432/virki_nonexistent?host=/var/run/postgresql";
let diagnosticPhase = "preflight";
let diagnosticCode = "UNCLASSIFIED";
let diagnosticModule = "unknown";
function refuse() { throw new Error("Offline no-port Prisma fixture refused; private operator reconciliation may be required."); }
function ensure(ok) { if (!ok) refuse(); }

export function runDisposablePrismaNative({
  env = process.env, argv = process.argv.slice(2),
} = {}) {
  // Invocation arguments are never host, CID, image, socket, SQL, URL or path.
  ensure(process.platform === "win32" && env.VIRKI_PRISMA_NATIVE_DISPOSABLE === "1" &&
    argv.length === 1 && ["happy", "diverge", "probe", "interrupt"].includes(argv[0]));
  assertDisposablePgDockerEnvironment(env);
  const signedCli = requireSignedPgDockerCli();
  const config = mkdtempSync(path.join(tmpdir(), "virki-native-prisma-cli-"));
  const owner = randomBytes(16).toString("hex");
  const socketVolume = `virki-prisma-sock-${owner}`;
  const sourceRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const migrations = verifyCommittedStage2PrismaMigrations(path.join(sourceRoot,
    "packages/database/prisma/migrations"));
  assertCommittedFirstDdl(readFileSync(path.join(sourceRoot,
    "packages/database/prisma/migrations/20261001000000_security_polish/migration.sql"), "utf8"));
  const migrationDigest = createHash("sha256").update(JSON.stringify(migrations)).digest("hex");
  const journalIdentity = {
    directory: path.join(homedir(), ".virki", "offline-docker-reconciliation"),
    name: `virki-offline-fixture-${owner}`, owner,
  };
  const docker = (args, { timeout = 15000, maxBuffer = 8192 } = {}) => {
    // No shell, caller-inherited PATH/DOCKER/PG variables or Docker config.
    const result = spawnSync(signedCli, ["--host", ENDPOINT, "--config", config, ...args], {
      shell: false, windowsHide: true, timeout, maxBuffer, encoding: "utf8",
      env: { SystemRoot: "C:\\Windows", WINDIR: "C:\\Windows",
        PATH: "C:\\Windows\\System32;C:\\Windows" },
    });
    return result;
  };
  const call = (args, opts) => {
    const result = docker(args, opts);
    if (result.error || result.status !== 0) refuse();
    return String(result.stdout ?? "").trim();
  };
  const journal = (action, data) => runProtectedWindowsJournalOperation(action, {
    ...journalIdentity, ...(data === undefined ? {} : { line: JSON.stringify(data) }),
  });
  const observe = (id) => {
    const result = docker(["inspect", "--type", "container", "--format", INSPECT, id]);
    if (result.error || result.status !== 0) refuse();
    try { return JSON.parse(result.stdout); } catch { refuse(); }
  };
  const absent = (id) => {
    const observed = docker(["inspect", "--type", "container", "--format", "{{.Id}}", id]);
    return !observed.error && observed.status !== 0 &&
      /no such object|no such container/iu.test(observed.stderr ?? "");
  };
  let started = false;
  let finished = false;
  let volumeAttempted = false;
  let volumeAccepted = false;
  let postkillZeroExitAnomaly = false;
  const created = [];
  let imageIDs = {};
  const runOwned = (kind, spec) => {
    journal("append", { event: `${kind}_run_may_still_start`, name: spec.name, image: spec.image });
    const reply = docker(spec.args, { timeout: 25000 });
    const id = !reply.error && reply.status === 0 ? String(reply.stdout ?? "").trim() : "";
    // A missing/lost CID is an ambiguous launch even if a name lookup says
    // not-found: a late create could still appear. Journal is NEVER cleared.
    if (!HEX_ID.test(id)) refuse();
    const entry = { kind, id, name: spec.name, owner, image: spec.image };
    verifyEntry(entry);
    created.push(entry);
    journal("append", { event: `${kind}_accepted`, cid: id });
    return entry;
  };
  const verifyEntry = (entry) => assertPrismaNativeDockerMetadata(observe(entry.id), {
    ...entry, imageId: imageIDs[entry.kind], imageRef: entry.image,
    network: "none", socketVolume,
  });
  const exec = (entry, command, opts = {}) => {
    verifyEntry(entry);
    return call(["exec", entry.id, ...command], opts);
  };
  const pg = (args, opts) => exec(created[0], args, opts);
  const nodePrisma = (db, command, { expectFailure = false, expectedCode = null } = {}) => {
    ensure([URL_CLONE, URL_SOURCE, URL_ROLLBACK, URL_MISSING].includes(db));
    ensure(["deploy", "status", "resolve"].includes(command[0]));
    ensure(expectedCode === null || ["P1003", "P3009"].includes(expectedCode));
    ensure(db !== URL_MISSING || (command[0] === "status" && expectedCode === "P1003"));
    verifyEntry(created[1]);
    const cmd = ["exec", "--env", `DATABASE_URL=${db}`, created[1].id,
      "node", "/app/node_modules/prisma/build/index.js", "migrate", ...command,
      "--schema", "/tmp/virki-prisma/schema.prisma"];
    // Prisma can emit multi-line, formatted diagnostics. A 4 KiB child
    // buffer previously masked the actual negative-case result as UNKNOWN.
    const output = docker(cmd, { timeout: 90000, maxBuffer: 32768 });
    const observed = `${output.stdout ?? ""}\n${output.stderr ?? ""}`;
    if (!isVerifiedPrismaInvocationResult(output, { expectFailure, expectedCode })) {
      const pg = /\b(P[0-9]{4})\b/u.exec(observed);
      diagnosticCode = output.error?.code === "ENOBUFS" ? "PRISMA_OUTPUT_LIMIT" :
        output.error?.code === "ETIMEDOUT" ? "PRISMA_TIMEOUT" :
          output.error?.code === "EACCES" ? "PRISMA_ACCESS_DENIED" :
            expectedCode && output.status === 0 ? "WRONG_URL_UNEXPECTED_SUCCESS" :
              pg ? pg[1] :
        /schema.engine|schema-engine|query.engine|query-engine/iu.test(observed) ? "ENGINE" :
          /permission denied|EACCES/iu.test(observed) ? "PERMISSION" :
            /cannot find|not found|module/iu.test(observed) ? "DEPENDENCY" :
              /datasource|database|socket|connection/iu.test(observed) ? "CONNECTION" :
                /unsupported|invalid|unknown option/iu.test(observed) ? "ARGUMENT" :
                  expectedCode ? `WRONG_URL_UNCLASSIFIED_EXIT_${Number.isInteger(output.status) ? output.status : "ERROR"}` : "UNKNOWN";
      refuse();
    }
    return output;
  };
  const interruptRealSchemaEngine = () => {
    // Every async Docker exec has immutable-CID/owner verification and a
    // protected MAY-START journal event first. No shell or ambient endpoint.
    const background = (entry, args, event) => {
      verifyEntry(entry);
      journal("append", { event, cid: entry.id });
      const child = spawn(signedCli, ["--host", ENDPOINT, "--config", config, ...args], {
        shell: false, windowsHide: true, stdio: "ignore",
        env: { SystemRoot: "C:\\Windows", WINDIR: "C:\\Windows",
          PATH: "C:\\Windows\\System32;C:\\Windows" },
      });
      child.on("error", () => { diagnosticCode = "ASYNC_DOCKER_CLIENT_ERROR"; });
      ensure(Number.isInteger(child.pid) && child.pid > 0);
    };
    const sql = (statement) => pg(["psql", "-X", "-qAt", "-U", "postgres",
      "-h", "/var/run/postgresql", "-d", "virki_clone", "-c", statement], { timeout: 7000 });
    const lock = `SELECT COUNT(*) FROM pg_locks WHERE relation = 'public."ProjectConnection"'::regclass ` +
      `AND mode='ShareUpdateExclusiveLock' AND granted`;
    const waiting = deriveBlockedDdlProbe();
    const backendIdentityProbe = deriveBlockedDdlBackendIdentityProbe();
    const pollExactlyOne = (statement, limit) => {
      for (let i = 0; i < limit; i++) if (sql(statement) === "1") return;
      refuse();
    };
    diagnosticPhase = "engine-interrupt-lock-acquire";
    background(created[0], ["exec", created[0].id, "psql", "-X", "-qAt",
      "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
      "-c", `BEGIN; LOCK TABLE "ProjectConnection" IN SHARE UPDATE EXCLUSIVE MODE; SELECT pg_sleep(${INTERRUPT_TIMING.blockerSeconds});`],
    "prisma_test_exclusive_pg_lock_may_start");
    pollExactlyOne(lock, 48);
    journal("append", { event: "exclusive_pg_lock_granted" });
    diagnosticPhase = "engine-interrupt-await-real-ddl";
    background(created[1], ["exec", created[1].id, "node",
      "/workspace/scripts/fixtures/offline-prisma-native/interrupt.mjs", "run"],
    "real_prisma_migrate_deploy_engine_may_start");
    // Require both the actual waiting ALTER in PostgreSQL (joined to our
    // private holder via pg_blocking_pids) and the real schema-engine
    // executable with the right UID, PPID and Prisma CLI argv. Earlier
    // AccessExclusiveLock could have blocked preliminary SELECTs instead.
    const deadline = Date.now() + INTERRUPT_TIMING.observationTimeoutMs;
    let sawEngine = false;
    let matched = false;
    while (Date.now() < deadline) {
      ensure(sql(lock) === "1");
      const state = exec(created[1], ["node", "/workspace/scripts/fixtures/offline-prisma-native/interrupt.mjs", "probe"],
        { timeout: 12000 });
      if (state === "PRISMA_CLI_EXITED_BEFORE_OBSERVATION") {
        diagnosticCode = "PRISMA_CLI_EXITED_BEFORE_DDL";
        refuse();
      }
      ensure(state === "EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED" || state === "ENGINE_NOT_YET_OBSERVED");
      if (state === "EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED") sawEngine = true;
      if (state === "EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED" && sql(waiting) === "1") {
        matched = true;
        break;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
    }
    if (!matched) {
      diagnosticCode = sawEngine ? "ENGINE_ACTIVE_BUT_FIRST_DDL_NOT_BLOCKED" : "ENGINE_NEVER_VERIFIED";
      refuse();
    }
    // Recheck immediately before SIGKILL; launch alone never suffices.
    ensure(sql(lock) === "1" && sql(waiting) === "1" &&
      exec(created[1], ["node", "/workspace/scripts/fixtures/offline-prisma-native/interrupt.mjs", "probe"],
        { timeout: 12000 }) === "EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED");
    ensure(sql(`SELECT COUNT(*) FROM "_prisma_migrations" WHERE migration_name='20261001000000_security_polish' ` +
      `AND finished_at IS NULL AND rolled_back_at IS NULL`) === "1");
    ensure(sql(`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' ` +
      `AND table_name='ProjectConnection' AND column_name='launchUrl'`) === "0");
    // Pin only the backend running the exact immutable migration SQL and
    // blocked by OUR private holder. PID alone is insufficient; retain its
    // PostgreSQL backend_start with microsecond precision against reuse.
    const pendingDdlBackend = parseBlockedDdlBackendIdentity(sql(backendIdentityProbe));
    ensure(sql(waiting) === "1");
    journal("append", { event: "real_prisma_waiting_pg_backend_unique_identity_pinned",
      pid: pendingDdlBackend.pid, backendStartMicros: pendingDdlBackend.startedMicroseconds });
    journal("append", { event: "real_prisma_schema_engine_ddl_blocked_on_pg_lock" });
    diagnosticPhase = "engine-interrupt-exact-sigkill";
    ensure(exec(created[1], ["node", "/workspace/scripts/fixtures/offline-prisma-native/interrupt.mjs", "kill"],
      { timeout: 12000 }) === "EXACT_PRISMA_SCHEMA_ENGINE_SIGKILL_SENT");
    journal("append", { event: "exact_prisma_schema_engine_sigkill_sent" });
    // PostgreSQL can continue executing the enqueued ALTER even after the
    // Prisma schema-engine process is killed. Terminate ONLY its still-blocked
    // owner-pinned backend BEFORE releasing the private holder lock. This is
    // the actual session failure injection, not synthesized migration history.
    diagnosticPhase = "engine-interrupt-terminate-exact-waiting-pg-backend";
    ensure(sql(lock) === "1" && sql(waiting) === "1" &&
      sql(backendIdentityProbe) === `${pendingDdlBackend.pid}|${pendingDdlBackend.startedMicroseconds}`);
    journal("append", { event: "real_prisma_postkill_waiting_backend_termination_may_start",
      pid: pendingDdlBackend.pid, backendStartMicros: pendingDdlBackend.startedMicroseconds });
    ensure(sql(deriveBlockedDdlBackendTermination(pendingDdlBackend)) === "t");
    ensure(sql(deriveBlockedDdlBackendAbsence(pendingDdlBackend)) === "0" &&
      sql(waiting) === "0" && sql(lock) === "1");
    journal("append", { event: "real_prisma_postkill_waiting_backend_terminated",
      pid: pendingDdlBackend.pid, backendStartMicros: pendingDdlBackend.startedMicroseconds });
    journal("append", { event: "real_prisma_postkill_waiting_backend_absent" });
    let runnerExited = false;
    const exitDeadline = Date.now() + 75000;
    while (Date.now() < exitDeadline) {
      const marker = docker(["exec", created[1].id, "test", "-s", "/tmp/virki-prisma-engine-exit.json"],
        { timeout: 5000 });
      if (!marker.error && marker.status === 0) { runnerExited = true; break; }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
    }
    if (!runnerExited) {
      diagnosticCode = "PRISMA_EXIT_MARKER_TIMEOUT";
      refuse();
    }
    const exitEvidence = JSON.parse(exec(created[1], ["cat", "/tmp/virki-prisma-engine-exit.json"]));
    const exitClass = classifyPrismaPostkillExit(exitEvidence);
    // Only known safe lines from the pinned disposable fixture are journaled.
    // Neither the PostgreSQL URL nor arbitrary CLI stdout/stderr is persisted.
    for (const channel of ["stdout", "stderr"]) {
      const summary = exitEvidence[channel];
      ensure(summary && Number.isSafeInteger(summary.byteLength) &&
        summary.byteLength >= 0 && summary.byteLength <= 32768 &&
        /^[a-f0-9]{64}$/u.test(summary.sha256) &&
        Array.isArray(summary.safeLines) && summary.safeLines.length <= 6 &&
        summary.safeLines.every((line) => typeof line === "string" &&
          line.length <= 120 && /^(?:Prisma schema loaded from \/tmp\/virki-prisma\/schema\.prisma|Error: P[0-9]{4}|All migrations have been successfully applied\.|Applying migration `(?:0_init|[0-9]{14}_[a-z0-9_]+)`|[0-9]{1,3} migrations found in prisma\/migrations)$/u.test(line)));
    }
    journal("append", { event: "real_prisma_cli_exit_marker_observed",
      status: exitEvidence.status, signal: exitEvidence.signal, error: exitEvidence.error,
      stdout: exitEvidence.stdout, stderr: exitEvidence.stderr });
    if (exitClass.zeroExitAnomaly) {
      postkillZeroExitAnomaly = true;
      journal("append", { event: "postkill_cli_zero_exit_anomaly_latched_not_success" });
    } else {
      ensure(exec(created[1], ["node",
        "/workspace/scripts/fixtures/offline-prisma-native/interrupt.mjs", "result"],
      { timeout: 15000 }) === "REAL_PRISMA_CLI_NONZERO_AFTER_SIGKILL");
      journal("append", { event: "real_prisma_cli_failed_after_engine_sigkill" });
    }
    const postkillState = `SELECT ` +
      `(SELECT count(*) FROM "_prisma_migrations" WHERE migration_name='20261001000000_security_polish' AND finished_at IS NULL AND rolled_back_at IS NULL)::text || '|' || ` +
      `(SELECT count(*) FROM "_prisma_migrations" WHERE migration_name='20261001000000_security_polish' AND finished_at IS NOT NULL)::text || '|' || ` +
      `(SELECT count(*) FROM "_prisma_migrations" WHERE migration_name='20261001000000_security_polish' AND rolled_back_at IS NOT NULL)::text || '|' || ` +
      `(SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='ProjectConnection' AND column_name='launchUrl')::text`;
    diagnosticPhase = "engine-interrupt-postkill-database-before-release";
    assertPrismaPostkillDatabaseState(sql(postkillState));
    journal("append", { event: "real_postkill_migration_unfinished_column_absent_before_release" });
    // Terminate ONLY the private PostgreSQL test lock backend, selected by
    // its granted private holder lock and controlled pg_sleep query marker.
    diagnosticPhase = "engine-interrupt-release-private-lock";
    const lockPid = sql(`SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid ` +
      `WHERE a.datname='virki_clone' AND l.relation='public."ProjectConnection"'::regclass ` +
      `AND l.mode='ShareUpdateExclusiveLock' AND l.granted AND a.query LIKE '%pg_sleep(${INTERRUPT_TIMING.blockerSeconds})%'`);
    ensure(/^[1-9][0-9]{0,9}$/u.test(lockPid));
    ensure(sql(`SELECT pg_terminate_backend(${lockPid})`) === "t");
    ensure(sql(lock) === "0");
    // The actual engine died mid-migration. Prisma must now fail closed on
    // the incomplete row; explicit rolled-back resolution allows reapply.
    diagnosticPhase = "engine-interrupt-prisma-failed-history";
    assertPrismaPostkillDatabaseState(sql(postkillState));
    journal("append", { event: "real_postkill_migration_unfinished_column_absent_after_release" });
    // Even a zero-status first CLI cannot authorize recovery. The fresh Prisma
    // invocation must independently exit nonzero and return EXACT P3009.
    nodePrisma(URL_CLONE, ["deploy"], { expectedCode: "P3009" });
    journal("append", { event: "real_prisma_p3009_after_schema_engine_sigkill" });
    diagnosticPhase = "engine-interrupt-prisma-resolve-rollback";
    nodePrisma(URL_CLONE, ["resolve", "--rolled-back", "20261001000000_security_polish"]);
    nodePrisma(URL_CLONE, ["deploy"]);
    nodePrisma(URL_CLONE, ["status"]);
    journal("append", { event: "real_prisma_migrations_redeployed_after_sigkill" });
  };
  try {
    ensure(call(["info", "--format", "{{.OperatingSystem}}|{{.OSType}}"]) === "Docker Desktop|linux");
    for (const [kind, image] of [["pg", POSTGRES], ["node", NODE]]) {
      const id = call(["image", "inspect", image, "--format", "{{.Id}}"]);
      ensure(IMAGE_ID.test(id));
      imageIDs[kind] = id;
    }
    // Windows handle-/DACL-bound journal is created BEFORE either docker run.
    journal("create", { version: 1, fixture: "offline-native-prisma-engine",
      state: "run_may_still_start", engine: ENDPOINT, owner,
      pgImage: POSTGRES, runnerImage: NODE, socketVolume, migrationDigest });
    started = true;
    // Create a completely new private data-FREE local volume. Postgres's
    // official /var/run/postgresql image directory seeds postgres ownership;
    // node user 70 connects only through its verified Unix-domain socket.
    journal("append", { event: "socket_volume_may_still_start", socketVolume });
    volumeAttempted = true;
    ensure(call(["volume", "create", "--label", `${OWNER_LABEL}=${owner}`, socketVolume]) === socketVolume);
    const volumeInfo = JSON.parse(call(["volume", "inspect", socketVolume, "--format", "{{json .}}"]));
    ensure(volumeInfo.Name === socketVolume && volumeInfo.Driver === "local" &&
      volumeInfo.Scope === "local" && volumeInfo.Labels?.[OWNER_LABEL] === owner);
    volumeAccepted = true;
    journal("append", { event: "socket_volume_owned_and_verified" });
    diagnosticPhase = "postgres-launch";
    const plan = planDisposablePrismaNative({ owner, socketVolume });
    runOwned("pg", plan.pg);
    let ready = false;
    for (let i = 0; i < 50; i++) {
      const response = docker(["exec", created[0].id, "test", "-s", "/tmp/virki-proof/ready"], { timeout: 5000 });
      if (response.status === 0 && !response.error) { ready = true; break; }
      const stalled = spawnSync("C:\\Windows\\System32\\timeout.exe", ["/T", "1", "/NOBREAK"],
        { windowsHide: true, timeout: 2000, encoding: "utf8", maxBuffer: 1024 });
      void stalled;
    }
    ensure(ready);
    diagnosticPhase = "prisma-runner-launch";
    runOwned("node", plan.node);
    journal("append", { event: "preflight_containers_verified" });
    diagnosticPhase = "prisma-dependency-files";
    ensure(docker(["exec", created[1].id, "test", "-r", "/app/node_modules/prisma/build/index.js"]).status === 0);
    ensure(docker(["exec", created[1].id, "test", "-r", "/workspace/packages/database/prisma/schema.prisma"]).status === 0);
    ensure(docker(["exec", created[1].id, "test", "-x", "/opt/virki-prisma/schema-engine-linux-musl-openssl-3.0.x"]).status === 0);
    diagnosticPhase = "prisma-cli-version";
    const versionOutput = docker(["exec", created[1].id, "node", "/app/node_modules/prisma/build/index.js", "--version"],
      { timeout: 90000, maxBuffer: 8192 });
    if (versionOutput.error || versionOutput.status !== 0 ||
        !/\b6\.19\.3\b/u.test(`${versionOutput.stdout ?? ""}\n${versionOutput.stderr ?? ""}`)) {
      const moduleName = /Cannot find (?:module|package) ['"]([^'"]+)['"]/iu.exec(versionOutput.stderr ?? "")?.[1];
      const relative = moduleName?.startsWith("/deps/") ? moduleName.slice(6) : moduleName;
      if (relative && /^[a-zA-Z0-9@_./-]{1,120}$/u.test(relative)) diagnosticModule = relative;
      diagnosticCode = /Cannot find module/iu.test(versionOutput.stderr ?? "") ? "MODULE_NOT_FOUND" :
        /permission denied/iu.test(versionOutput.stderr ?? "") ? "PERMISSION" : "CLI_VERSION";
      if (versionOutput.error?.code === "ENOBUFS") diagnosticCode = "OUTPUT_BOUNDED";
      if (versionOutput.error?.code === "ETIMEDOUT") diagnosticCode = "CLI_TIMEOUT";
      if (versionOutput.error?.code === "EACCES") diagnosticCode = "CLI_ACCESS";
      if (diagnosticCode === "CLI_VERSION" && versionOutput.status !== 0)
        diagnosticCode = `CLI_EXIT_${Number.isInteger(versionOutput.status) ? versionOutput.status : "ERROR"}`;
      refuse();
    }
    diagnosticPhase = "sealed-prisma-snapshot";
    ensure(call(["exec", created[1].id, "node",
      "/workspace/scripts/fixtures/offline-prisma-native/snapshot.mjs"],
    { timeout: 30000, maxBuffer: 2048 }) === "SNAPSHOT_READY");
    journal("append", { event: "committed_stage2_prisma_snapshot_verified", migrationDigest });
    if (argv[0] === "probe") {
      journal("append", { event: "prisma_cli_version_only_verified_no_migration" });
      finished = true;
      return Object.freeze({ status: "PRISMA_CLI_ONLY_VERIFIED_NO_MIGRATION",
        prismaEngineExecuted: false, backupVerified: false,
        productionProof: false, deployAuthorized: false });
    }
    diagnosticPhase = "unix-health";
    ensure(pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "postgres",
      "-c", "SELECT inet_server_addr() IS NULL"]) === "t");
    // Assert TCP itself is OFF; Node Prisma uses private Unix socket, never
    // Docker networks or a host port.
    diagnosticPhase = "no-tcp-listener";
    ensure(pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "postgres",
      "-c", "SHOW listen_addresses"]) === "");
    // Real custom PostgreSQL snapshot; encrypted/artificial user data never
    // leaves private container tmpfs. Explicit digest verified before restore.
    diagnosticPhase = "pg-baseline-synthetic-data";
    pg(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_source",
      "-c", "INSERT INTO \"User\"(\"id\",\"email\",\"emailNormalized\",\"displayName\",\"passwordHash\",\"role\",\"accountStatus\",\"secondFactorMethod\",\"updatedAt\") VALUES('prisma-fixture-admin','fixture@fixture.invalid','fixture@fixture.invalid','Fixture ADMIN','synthetic-only','ADMIN','ACTIVE','EMAIL',now())"]);
    diagnosticPhase = "pg-backup";
    pg(["pg_dump", "-U", "postgres", "-h", "/var/run/postgresql", "-Fc", "-f", "/tmp/virki-proof/baseline.dump",
      "-d", "virki_source"], { timeout: 30000 });
    const baselineSha = pg(["sha256sum", "/tmp/virki-proof/baseline.dump"]).split(/\s/u)[0];
    ensure(/^[a-f0-9]{64}$/u.test(baselineSha));
    journal("append", { event: "backup_verified", sha256: baselineSha });
    diagnosticPhase = "pg-restore";
    pg(["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "-U", "postgres", "-h", "/var/run/postgresql",
      "-d", "virki_clone", "/tmp/virki-proof/baseline.dump"], { timeout: 30000 });
    ensure(pg(["sha256sum", "/tmp/virki-proof/baseline.dump"]).startsWith(baselineSha));
    journal("append", { event: "restore_verified" });
    // Real Prisma CLI first registers 0_init (already physically present in
    // backup) and then applies the remaining committed SQL migrations itself.
    diagnosticPhase = "prisma-resolve";
    nodePrisma(URL_CLONE, ["resolve", "--applied", "0_init"]);
    const interrupted = argv[0] === "interrupt";
    if (interrupted) {
      interruptRealSchemaEngine();
    } else {
      // Genuine Prisma negative: the wrong database on the same Unix socket
      // must return its exact P1003, never a generic Docker/Node error.
      diagnosticPhase = "prisma-wrong-url-negative";
      nodePrisma(URL_MISSING, ["status"], { expectedCode: "P1003" });
      journal("append", { event: "real_prisma_wrong_database_refused" });
      diagnosticPhase = "prisma-deploy";
      nodePrisma(URL_CLONE, ["deploy"]);
      diagnosticPhase = "prisma-status";
      nodePrisma(URL_CLONE, ["status"]);
      journal("append", { event: "real_prisma_migrate_deploy_complete" });
    }
    diagnosticPhase = "migration-history";
    const history = pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
      "-c", "SELECT COUNT(*) FROM \"_prisma_migrations\""]);
    ensure(Number(history) === migrations.length + (interrupted ? 1 : 0));
    const rows = pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
      "-c", "SELECT migration_name||'|'||checksum FROM \"_prisma_migrations\" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name"]);
    ensure(verifyDisposablePrismaDatabaseHistory(migrations, rows).migrationHistoryVerified === true);
    ensure(pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
      "-c", "SELECT COUNT(*) FROM \"_prisma_migrations\" WHERE finished_at IS NULL AND rolled_back_at IS NULL"]) === "0");
    const rolledBackRows = pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
      "-c", "SELECT migration_name||'|'||checksum FROM \"_prisma_migrations\" WHERE rolled_back_at IS NOT NULL AND finished_at IS NULL ORDER BY migration_name"]);
    const interruptedMigration = migrations.find((item) => item.name === "20261001000000_security_polish");
    ensure(interrupted ? rolledBackRows === `${interruptedMigration.name}|${interruptedMigration.checksum}` : rolledBackRows === "");
    ensure(pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
      "-c", "SELECT \"emailNormalized\" FROM \"User\" WHERE \"id\"='prisma-fixture-admin'"]) === "fixture@fixture.invalid");
    const passkeys = pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
      "-c", "SELECT to_regclass('public.\"PasskeyCredential\"') IS NOT NULL"]);
    ensure(passkeys === "t");
    journal("append", { event: "migration_history_and_schema_healthy" });
    if (argv[0] === "diverge") {
      pg(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_clone",
        "-c", "INSERT INTO \"_prisma_migrations\"(id,checksum,migration_name,started_at,finished_at,applied_steps_count) VALUES ('unknown-fixture','unknown-fixture','20990101000000_unapproved',now(),now(),1)"]);
      nodePrisma(URL_CLONE, ["status"], { expectFailure: true });
      journal("append", { event: "divergent_migration_history_refused" });
      throw new Error("EXPECTED_DIVERGENCE");
    }
    // Clean real database-restart proof, no database or schema state lost.
    diagnosticPhase = "postgres-restart";
    pg(["pg_ctl", "-D", "/var/lib/postgresql/data", "-m", "fast", "-w", "-o",
      "-c listen_addresses='' -c unix_socket_directories=/var/run/postgresql", "restart"], { timeout: 30000 });
    nodePrisma(URL_CLONE, ["status"]);
    journal("append", { event: "restart_prisma_history_verified" });
    // Reconstruct the exact predecessor in an independent rollback DB, never
    // mutate the now-migrated clone. This is disposable rollback feasibility.
    diagnosticPhase = "rollback-proof";
    pg(["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "-U", "postgres", "-h", "/var/run/postgresql",
      "-d", "virki_rollback", "/tmp/virki-proof/baseline.dump"], { timeout: 30000 });
    ensure(pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_rollback",
      "-c", "SELECT \"emailNormalized\" FROM \"User\" WHERE \"id\"='prisma-fixture-admin'"]) === "fixture@fixture.invalid");
    ensure(pg(["psql", "-X", "-qAt", "-U", "postgres", "-h", "/var/run/postgresql", "-d", "virki_rollback",
      "-c", "SELECT to_regclass('public.\"PasskeyCredential\"') IS NULL"]) === "t");
    journal("append", { event: "rollback_restored_and_proven" });
    finished = true;
    return Object.freeze({ status: interrupted ?
      postkillZeroExitAnomaly ? "REAL_PRISMA_P3009_RECOVERED_WITH_CLI_ZERO_EXIT_ANOMALY_DIAGNOSTIC_ONLY" :
        "REAL_PRISMA_SCHEMA_ENGINE_SIGKILL_RECOVERED_DISPOSABLE_ONLY" :
      "REAL_PRISMA_MIGRATE_DEPLOY_DISPOSABLE_ONLY",
      migrationCount: Number(history), backupSha256: baselineSha,
      wrongDatabaseRefusedByPrisma: !interrupted,
      prismaSchemaEngineSigkillRecovered: interrupted,
      postkillZeroExitAnomaly, prismaP3009IndependentlyVerified: interrupted,
      noHostPublishedPorts: true, networkIsolated: true,
      productionProof: false, transferAuthorized: false, deployAuthorized: false });
  } finally {
    // Cleanup is conservative. Even an observed current absence after a lost
    // launch does not preclude late creation: keep journal for reconciliation.
    let cleaned = true;
    for (const entry of created.toReversed()) {
      try {
        verifyEntry(entry);
        journal("append", { event: `${entry.kind}_cleanup_verified`, cid: entry.id });
        call(["rm", "--force", "--volumes", entry.id], { timeout: 15000 });
        if (!absent(entry.id)) cleaned = false;
      } catch { cleaned = false; }
    }
    if (volumeAccepted && cleaned && created.length === 2) {
      try {
        const v = JSON.parse(call(["volume", "inspect", socketVolume, "--format", "{{json .}}"]));
        ensure(v.Name === socketVolume && v.Driver === "local" &&
          v.Labels?.[OWNER_LABEL] === owner && v.Scope === "local");
        journal("append", { event: "socket_volume_cleanup_verified" });
        call(["volume", "rm", socketVolume]);
        const gone = docker(["volume", "inspect", socketVolume, "--format", "{{.Name}}"]);
        if (gone.error || gone.status === 0 ||
          !/no such volume/iu.test(gone.stderr ?? "")) cleaned = false;
      } catch { cleaned = false; }
    }
    if (started && finished && cleaned && created.length === 2 && volumeAttempted && volumeAccepted &&
        !postkillZeroExitAnomaly) {
      journal("remove");
    }
    // Private Docker CLI config contains no credentials and never reuses a
    // user profile; no deletion of operator ownership evidence on failures.
    rmSync(config, { recursive: true, force: true });
    if (!isVerifiedSuccessfulCleanup({
      finished, cleaned, createdCount: created.length,
      volumeAttempted, volumeAccepted,
    })) {
      diagnosticPhase = "owner-cleanup-unverified";
      refuse();
    }
  }
}

if (process.argv[1] && path.basename(process.argv[1]) === "offline-prisma-native-run.mjs") {
  try {
    const result = runDisposablePrismaNative();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write(`OFFLINE_PRISMA_NATIVE_NOT_READY phase=${diagnosticPhase} code=${diagnosticCode} module=${diagnosticModule}; protected owner journal retained on failure\n`);
    process.exitCode = 1;
  }
}
