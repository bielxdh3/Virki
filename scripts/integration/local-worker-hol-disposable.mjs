// One-shot, real PostgreSQL HOL/CAS proof on the signed, local Windows Docker
// Desktop Linux engine. Separate from the GitHub-only worker-hol-ci.sh gate.
// Never reuses a database, Docker context, SMTP provider or production secret.
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, writeSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAdmittedOidcDockerClient } from "../lib/disposable-docker-session.mjs";
import { ensurePrivateLocalHolReceiptDirectory, assertPrivateLocalHolReceiptFile,
  privateLocalHolReceiptDirectory } from "./local-worker-hol-receipt.mjs";
import {
  HOL_IMAGE, HOL_KIND, HOL_KIND_LABEL, HOL_OWNER_LABEL, assertLocalHolHost,
  localHolSystemEnvironment, localHolTestEnvironment, requireSignedDockerCli,
  requireHolImage, requireHolPlatform, requireHolContainerImage, requireHolPort,
  requireHolPostgresVersion, requireHolOwner, reconcileLocalHolContainer
} from "./local-worker-hol-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const windowsPowerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const dockerCli = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const idPattern = /^[a-f0-9]{64}$/u;
const secret = () => randomBytes(32).toString("hex");
const delay = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
let activeCleanup;

for (const [signal, exit] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  process.once(signal, () => {
    try { activeCleanup?.(); }
    catch (error) { console.error(error instanceof Error ? error.message : "Local HOL signal cleanup uncertain."); }
    process.exit(exit);
  });
}

function requireWindowsDockerSignature(hostEnv) {
  if (!existsSync(windowsPowerShell) || !existsSync(dockerCli)) {
    throw new Error("Local HOL requires the protected, installed Docker Desktop and Windows PowerShell.");
  }
  const script = [
    "$ErrorActionPreference='Stop'",
    `$sig=Get-AuthenticodeSignature -LiteralPath '${dockerCli}'`,
    "if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or",
    "    -not $sig.SignerCertificate.Subject.StartsWith('CN=Docker Inc,',",
    "      [System.StringComparison]::OrdinalIgnoreCase)) { exit 1 }",
    "[Console]::Out.Write('VALID_DOCKER_CLI')"
  ].join("\n");
  const observed = spawnSync(windowsPowerShell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8", windowsHide: true, timeout: 20_000,
    env: localHolSystemEnvironment(hostEnv)
  });
  requireSignedDockerCli(observed);
}

function runPhysicalHol() {
  assertLocalHolHost({ platform: process.platform, source: process.env });
  if (process.versions.node.split(".")[0] !== "22") {
    throw new Error("Local HOL requires the reviewed Node 22 runtime.");
  }
  const tsx = path.join(root, "node_modules", "tsx", "dist", "cli.mjs");
  if (!existsSync(tsx)) throw new Error("Local HOL requires npm ci in this isolated worktree.");
  const initRoles = path.join(root, "infra", "postgres-init", "10-virki-database-roles.sh");
  const initWorker = path.join(root, "scripts", "e2e", "20-virki-e2e-runtime-test-role.sh");
  for (const target of [root, initRoles, initWorker]) {
    const st = lstatSync(target);
    if (st.isSymbolicLink() || (target === root ? !st.isDirectory() : !st.isFile())) {
      throw new Error("Local HOL refuses aliased source or database role scripts.");
    }
  }
  requireWindowsDockerSignature(process.env);
  const dockerClient = createAdmittedOidcDockerClient({
    env: localHolSystemEnvironment(process.env)
  });
  const invoke = dockerClient.invoke;
  const owner = randomUUID();
  const name = `virki-email-hol-local-${owner}`;
  const database = `virki_email_worker_hol_${randomBytes(6).toString("hex")}`;
  requireHolOwner({ owner, name, database });
  const passwords = {
    bootstrap: secret(), runtime: secret(), migrator: secret(), audit: secret(), worker: secret()
  };
  if (new Set(Object.values(passwords)).size !== 5) throw new Error("Local HOL fixture password collision.");

  // A separate owner-ACL protected receipt directory. The shared recovery
  // helper is intentionally not weakened for local Windows capability ACEs.
  const receiptDirectory = privateLocalHolReceiptDirectory();
  const receiptPath = path.join(receiptDirectory, `email-hol-${owner}.jsonl`);
  let receiptFd = null;
  let receiptIdentity;
  let started = false;
  let uncertainStart = false;
  let containerId;
  let cleanupCompleted = false;

  function record(stage, id = null) {
    if (receiptFd === null) {
      ensurePrivateLocalHolReceiptDirectory();
      const parent = path.dirname(receiptDirectory);
      mkdirSync(parent, { recursive: true, mode: 0o700 });
      for (const directory of [parent, receiptDirectory]) {
        if (directory === receiptDirectory) mkdirSync(directory, { recursive: true, mode: 0o700 });
        const st = lstatSync(directory);
        if (!st.isDirectory() || st.isSymbolicLink() ||
            (process.platform !== "win32" && (st.uid !== process.getuid() || (st.mode & 0o077) !== 0))) {
          throw new Error("Local HOL receipt parent is not owner-private.");
        }
      }
      receiptFd = openSync(receiptPath, "wx", 0o600);
      receiptIdentity = fstatSync(receiptFd, { bigint: true });
      assertPrivateLocalHolReceiptFile(receiptPath);
    }
    ensurePrivateLocalHolReceiptDirectory();
    assertPrivateLocalHolReceiptFile(receiptPath);
    const link = lstatSync(receiptPath, { bigint: true });
    const opened = fstatSync(receiptFd, { bigint: true });
    if (!link.isFile() || link.isSymbolicLink() || link.nlink !== 1n ||
        ["dev", "ino", "mode", "nlink"].some((field) =>
          link[field] !== receiptIdentity[field] || opened[field] !== receiptIdentity[field])) {
      throw new Error("Local HOL owner receipt identity was replaced.");
    }
    const bytes = Buffer.from(JSON.stringify({ stage, owner, name, containerId: id }) + "\n");
    for (let offset = 0; offset < bytes.length;) {
      const n = writeSync(receiptFd, bytes, offset, bytes.length - offset);
      if (!Number.isSafeInteger(n) || n <= 0 || n > bytes.length - offset) {
        throw new Error("Local HOL receipt append was incomplete.");
      }
      offset += n;
    }
    fsyncSync(receiptFd);
    assertPrivateLocalHolReceiptFile(receiptPath);
  }

  function docker(args, timeout = 30_000) {
    const result = invoke(args, timeout);
    if (result?.error || result?.status !== 0 || typeof result.stdout !== "string") {
      throw new Error(`Local HOL Docker ${args[0]} failed.`);
    }
    return result.stdout.trim();
  }

  function cleanup() {
    if (!started || cleanupCompleted) return;
    try {
      reconcileLocalHolContainer({ invoke, owner, name, containerId, uncertainStart, record });
      cleanupCompleted = true;
    } catch (error) {
      try { record("RECONCILIATION_REQUIRED", containerId ?? null); }
      catch { /* never turn an uncertain cleanup into a successful exit */ }
      throw error;
    }
  }

  let safeEnvironment;
  try {
    activeCleanup = cleanup;
    record("IMAGE_PULL_PENDING");
    docker(["pull", "--quiet", HOL_IMAGE], 180_000);
    const pinnedImageId = requireHolImage(docker(["image", "inspect", "--format",
      "{{.Id}}|{{json .RepoDigests}}", HOL_IMAGE]));
    requireHolPlatform(docker(["image", "inspect", "--format", "{{.Os}}|{{.Architecture}}", HOL_IMAGE]));
    record("IMAGE_DIGEST_VERIFIED");
    // A durable RUN_PENDING record must exist BEFORE creating anything.
    record("RUN_PENDING");
    started = true;
    uncertainStart = true;
    const created = docker([
      "run", "--detach", "--rm", "--name", name,
      "--label", `${HOL_OWNER_LABEL}=${owner}`,
      "--label", `${HOL_KIND_LABEL}=${HOL_KIND}`,
      "--pids-limit", "256", "--memory", "512m",
      "--publish", "127.0.0.1::5432",
      "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m",
      "--health-cmd", `pg_isready -h 127.0.0.1 -U virki_bootstrap -d ${database}`,
      "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "90",
      "--env", `POSTGRES_DB=${database}`, "--env", "POSTGRES_USER=virki_bootstrap",
      "--env", `POSTGRES_PASSWORD=${passwords.bootstrap}`,
      "--env", `VIRKI_RUNTIME_DB_PASSWORD=${passwords.runtime}`,
      "--env", `VIRKI_MIGRATOR_DB_PASSWORD=${passwords.migrator}`,
      "--env", `VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD=${passwords.audit}`,
      "--env", `VIRKI_E2E_DATABASE_PASSWORD=${passwords.worker}`,
      "--mount", `type=bind,source=${initRoles},target=/docker-entrypoint-initdb.d/10-virki-database-roles.sh,readonly`,
      "--mount", `type=bind,source=${initWorker},target=/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh,readonly`,
      HOL_IMAGE
    ], 120_000);
    if (!idPattern.test(created)) throw new Error("Local HOL Docker returned an invalid container ID.");
    containerId = created;
    record("RUN_ACKNOWLEDGED", containerId);
    uncertainStart = false;
    requireHolContainerImage(docker(["inspect", "--format",
      "{{.Image}}|{{.Config.Image}}", containerId]), pinnedImageId);

    let ready = false;
    for (let attempt = 0; attempt < 90; attempt++) {
      const status = docker(["inspect", "--format", "{{.State.Health.Status}}", containerId], 15_000);
      if (status === "healthy") { ready = true; break; }
      if (status === "unhealthy") throw new Error("Local HOL disposable PostgreSQL is unhealthy.");
      delay(1000);
    }
    if (!ready) throw new Error("Local HOL disposable PostgreSQL health deadline exceeded.");
    const port = requireHolPort(docker(["port", containerId, "5432/tcp"]));
    const psql = (statement) => docker([
      "exec", containerId, "psql", "--username", "virki_bootstrap",
      "--dbname", database, "--no-psqlrc", "--tuples-only", "--no-align", "--quiet",
      "--set", "ON_ERROR_STOP=1", "--command", statement
    ], 20_000);
    requireHolPostgresVersion(psql("SHOW server_version_num"));
    const url = (role, password) =>
      `postgresql://${role}:${password}@127.0.0.1:${port}/${database}?schema=public`;
    safeEnvironment = localHolTestEnvironment({
      source: process.env,
      databaseUrl: url("virki_runtime_test", passwords.worker),
      migrationUrl: url("virki_migrator", passwords.migrator),
      secret
    });
    const redacted = (message) => Object.values(passwords)
      .concat([safeEnvironment.DATABASE_URL, safeEnvironment.MIGRATION_DATABASE_URL,
        safeEnvironment.VIRKI_OIDC_ADAPTER_KEY, safeEnvironment.VIRKI_TOTP_ENCRYPTION_KEY,
        safeEnvironment.VIRKI_EMAIL_OUTBOX_KEY])
      .reduce((text, value) => text.replaceAll(value, "[DISPOSABLE_SECRET]"), message ?? "");
    const child = (stage, argv, timeout) => {
      const result = spawnSync(process.execPath, argv, {
        cwd: root, env: safeEnvironment, encoding: "utf8",
        timeout, maxBuffer: 4 * 1024 * 1024, windowsHide: true
      });
      // Only output logs from test-only subprocesses after stripping ALL
      // generated credentials and URLs; stdout alone never constitutes PASS.
      if (result.stdout) process.stdout.write(redacted(result.stdout));
      if (result.stderr) process.stderr.write(redacted(result.stderr));
      if (result.error || result.status !== 0) throw new Error(`Local HOL ${stage} failed.`);
    };
    child("migrations", [
      path.join(root, "packages", "database", "scripts", "prisma-migrate.mjs"), "deploy"
    ], 180_000);
    // The independently observed virgin DB has no past mail or deliveries,
    // and worker role has neither superuser, role creation nor BYPASSRLS.
    docker(["exec", "--env", `POSTGRES_DB=${database}`,
      "--env", "POSTGRES_USER=virki_bootstrap",
      "--env", `VIRKI_E2E_DATABASE_PASSWORD=${passwords.worker}`,
      containerId, "sh", "/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh"], 30_000);
    if (psql("SELECT count(*) FROM pg_roles WHERE rolname='virki_runtime_test' AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolbypassrls") !== "1") {
      throw new Error("Local HOL independent observer rejects privileged worker role.");
    }
    if (psql('SELECT (SELECT count(*) FROM public."EmailOutboxMessage")::text || \'|\' || (SELECT count(*) FROM public."EmailDeliveryAttempt")::text') !== "0|0") {
      throw new Error("Local HOL independent observer refuses any non-virgin email queue.");
    }
    record("VIRGIN_DATABASE_OBSERVED", containerId);
    child("physical HOL/CAS TAP", [path.join(root, "scripts", "integration", "worker-hol.mjs")], 165_000);
    record("PHYSICAL_TWO_TESTS_PASS", containerId);
  } finally {
    try { cleanup(); }
    finally {
      activeCleanup = null;
      if (receiptFd !== null) closeSync(receiptFd);
    }
  }
  if (!cleanupCompleted) throw new Error("Local HOL proof and cleanup were not both complete.");
  console.log("LOCAL_EMAIL_WORKER_HOL_PHYSICAL_PASS: 2 real PASS, 0 FAIL, 0 SKIP; owner-ID cleanup verified.");
  console.log(`Local HOL private receipt: ${receiptPath}`);
}

try {
  if (process.argv.length !== 2) throw new Error("Local HOL runner accepts no target, env or database arguments.");
  runPhysicalHol();
} catch (error) {
  console.error(error instanceof Error ? error.message : "Local HOL proof did not complete safely.");
  process.exitCode = 1;
}
