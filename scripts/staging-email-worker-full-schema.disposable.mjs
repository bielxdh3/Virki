// Explicit, local-only proof: all committed Prisma migrations + actual scoped
// Prisma email worker. No external DB, VM, SMTP, registry pull or network egress.
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createEmailWorkerScramVerifier } from "./staging-email-worker-scram.mjs";
import { assertPrivateLocalHolReceiptFile, ensurePrivateLocalHolReceiptDirectory,
  privateLocalHolReceiptDirectory } from "./integration/local-worker-hol-receipt.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dockerCli = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const powerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const opensslCli = "C:\\Program Files\\Git\\usr\\bin\\openssl.exe";
const engine = "npipe:////./pipe/dockerDesktopLinuxEngine";
const image = "postgres:18.6-alpine3.24";
const runnerImage = "virki-pr118-stage-migrator:7076276";
const runnerImageId = "sha256:0ead09528cf7d3f3bed2007bd4dd1f623dfecf515053761f7c70cf37230b9193";
const runnerSourceRevision = "707627610c0baa3762f9da818cf1f801128ecbf9";
const imageId = "sha256:57b23a0326ee442e83b3d3fa027c5a148be0a392d7c91d1ca4e1e70131ee859a";
const ownerUuid = randomUUID();
const owner = ownerUuid.replaceAll("-", "");
const name = `virki-worker-full-${owner}`;
const runnerName = `virki-worker-node-${owner}`;
const networkName = `virki-worker-full-net-${owner}`;
const dbName = `virki_worker_full_${owner.slice(0, 12)}`;
const ownerLabel = "virki.worker-full.owner";
const password = () => randomBytes(32).toString("hex");
const secrets = {
  POSTGRES_PASSWORD: password(),
  VIRKI_RUNTIME_DB_PASSWORD: password(),
  VIRKI_MIGRATOR_DB_PASSWORD: password(),
  VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD: password(),
  VIRKI_EMAIL_WORKER_DB_PASSWORD: password()
};
secrets.VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER =
  createEmailWorkerScramVerifier(secrets.VIRKI_EMAIL_WORKER_DB_PASSWORD);
const systemKeys = ["PATH", "Path", "SystemRoot", "WINDIR", "HOME", "USERPROFILE",
  "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"];
const systemEnv = Object.fromEntries(systemKeys
  .filter((key) => typeof process.env[key] === "string")
  .map((key) => [key, process.env[key]]));
const dockerEnv = { ...systemEnv, ...secrets };
const hexId = /^[a-f0-9]{64}$/u;
let networkId;
let containerId;
let runnerId;
let networkCreateStarted = false;
let containerCreateStarted = false;
let runnerCreateStarted = false;
let networkCreateCommandIssued = false;
let containerCreateCommandIssued = false;
let runnerCreateCommandIssued = false;
let receiptFd = null;
let receiptIdentity;
let cleanupComplete = false;
let cleanupActive = false;
let interrupted = false;
let smtpCertificateDirectory = null;
const receiptPath = path.join(privateLocalHolReceiptDirectory(), `email-hol-${ownerUuid}.jsonl`);

function record(stage, id = null) {
  if (receiptFd === null) {
    ensurePrivateLocalHolReceiptDirectory();
    receiptFd = openSync(receiptPath, "wx", 0o600);
    receiptIdentity = fstatSync(receiptFd, { bigint: true });
  }
  ensurePrivateLocalHolReceiptDirectory();
  assertPrivateLocalHolReceiptFile(receiptPath);
  const disk = lstatSync(receiptPath, { bigint: true });
  const open = fstatSync(receiptFd, { bigint: true });
  if (!disk.isFile() || disk.isSymbolicLink() || disk.nlink !== 1n ||
      ["dev", "ino", "mode", "nlink"].some((key) =>
        disk[key] !== receiptIdentity[key] || open[key] !== receiptIdentity[key])) {
    throw new Error("Owner-private evidence journal identity changed.");
  }
  const bytes = Buffer.from(JSON.stringify({ stage, owner, networkName, name, runnerName, id }) + "\n");
  for (let written = 0; written < bytes.length;) {
    const n = writeSync(receiptFd, bytes, written, bytes.length - written);
    if (!Number.isSafeInteger(n) || n <= 0) throw new Error("Incomplete owner evidence append.");
    written += n;
  }
  fsyncSync(receiptFd);
  assertPrivateLocalHolReceiptFile(receiptPath);
}

function requireLocalOnly() {
  if (process.platform !== "win32" ||
      process.env.VIRKI_STAGING_WORKER_FULL_SCHEMA_PROOF !== "local-disposable-only" ||
      process.env.NODE_ENV === "production" || process.env.CI === "true") {
    throw new Error("Explicit local-only Windows staging worker proof is required.");
  }
  const injection = process.env.VIRKI_STAGING_WORKER_FULL_SCHEMA_FAIL_AT;
  if (injection !== undefined && ![
    "before-runner-create", "simulate-runner-ack-loss", "after-smtp-certificate-create"
  ].includes(injection)) {
    throw new Error("Unknown local-only failure-injection mode.");
  }
  for (const [key, value] of Object.entries(process.env)) {
    if (key === "VIRKI_STAGING_WORKER_FULL_SCHEMA_PROOF" ||
        key === "VIRKI_STAGING_WORKER_FULL_SCHEMA_FAIL_AT") continue;
    if (value && (/^(VIRKI_|DOCKER_|DATABASE_URL$|MIGRATION_DATABASE_URL$|PG(?:HOST|PORT|USER|PASSWORD|SERVICE|DATABASE|OPTIONS)|GH_TOKEN$)/iu).test(key)) {
      throw new Error(`Inherited sensitive or connection setting ${key} is forbidden.`);
    }
  }
  assert.ok(existsSync(dockerCli) && existsSync(powerShell), "Pinned Windows tools required");
  const signature = spawnSync(powerShell, ["-NoProfile", "-NonInteractive", "-Command",
    `$s=Get-AuthenticodeSignature -LiteralPath '${dockerCli}'; if($s.Status -ne 'Valid' -or -not $s.SignerCertificate -or -not $s.SignerCertificate.Subject.StartsWith('CN=Docker Inc,',[StringComparison]::OrdinalIgnoreCase)) { exit 1 }; 'SIGNED'`],
  { encoding: "utf8", windowsHide: true, timeout: 15_000, env: systemEnv });
  assert.equal(signature.status, 0, "Docker CLI signature must be valid");
  assert.equal(signature.stdout.trim(), "SIGNED");
}

function sanitize(value) {
  return Object.values(secrets).reduce((output, secret) =>
    output.replaceAll(secret, "[synthetic-redacted]"), String(value ?? ""));
}
function invoke(args, { allowFailure = false, timeout = 30_000, env = dockerEnv } = {}) {
  const result = spawnSync(dockerCli, ["--host", engine, ...args], {
    env, encoding: "utf8", windowsHide: true, timeout, maxBuffer: 2 * 1024 * 1024
  });
  if (result.error || (!allowFailure && result.status !== 0)) {
    throw new Error(`Local Docker ${args[0]} failed (status=${result.status}, error=${result.error?.code ?? "none"}): stdout=${sanitize(result.stdout).slice(-400)} stderr=${sanitize(result.stderr).slice(-500)}`);
  }
  return { status: result.status, stdout: sanitize(result.stdout).trim(),
    stderr: sanitize(result.stderr).trim() };
}
function checkNetwork() {
  assert.ok(networkId && hexId.test(networkId));
  assert.equal(invoke(["network", "inspect", networkId, "--format",
    `{{.Id}}|{{.Name}}|{{.Internal}}|{{index .Labels "${ownerLabel}"}}`]).stdout,
  `${networkId}|${networkName}|true|${owner}`, "Only the owned internal network is allowed");
}
function checkContainer() {
  assert.ok(containerId && hexId.test(containerId));
  assert.equal(invoke(["inspect", containerId, "--format",
    `{{.Id}}|{{.Name}}|{{index .Config.Labels "${ownerLabel}"}}|{{.HostConfig.NetworkMode}}|{{.Image}}`]).stdout,
  `${containerId}|/${name}|${owner}|${networkName}|${imageId}`,
  "Only the exact owned pinned container is allowed");
}
function checkRunner() {
  assert.ok(runnerId && hexId.test(runnerId));
  assert.equal(invoke(["inspect", runnerId, "--format",
    `{{.Id}}|{{.Name}}|{{index .Config.Labels "${ownerLabel}"}}|{{.HostConfig.NetworkMode}}|{{.Image}}`]).stdout,
  `${runnerId}|/${runnerName}|${owner}|${networkName}|${runnerImageId}`,
  "Only the exact owned pinned offline Node 22 runner is allowed");
}
function psql(statement) {
  checkContainer();
  const sql = invoke(["exec", containerId, "psql", "-U", "virki_bootstrap",
    "-d", dbName, "--no-psqlrc", "--no-align", "--tuples-only",
    "--quiet", "--set", "ON_ERROR_STOP=1", "--command", statement]);
  return sql.stdout;
}
function runInRunner(label, args, env, timeout = 180_000, user = null) {
  checkRunner();
  const extra = user ? ["--user", user] : [];
  let result;
  try {
    result = invoke(["exec", "--workdir", "/app", ...extra,
      ...Object.keys(env).flatMap((key) => ["--env", key]), runnerId, ...args],
    { env: { ...dockerEnv, ...env }, timeout, allowFailure: true });
  } catch (error) {
    throw new Error(`${label}: ${error instanceof Error ? error.message : "isolated stage failed"}`, { cause: error });
  }
  if (result.status !== 0) {
    const reasons = `${result.stdout}\n${result.stderr}`.split(/\r?\n/u)
      .filter((line) => /not ok|error:|failureType:|code:|expected:|actual:|assertion:|PrismaClient/iu.test(line))
      .slice(0, 20).join("\n");
    throw new Error(`${label} failed: ${reasons || "no diagnostic TAP lines"}`);
  }
  // No subprocess credentials or verifier can be printed as raw values.
  if (label === "Prisma scoped worker") {
    assert.match(result.stdout, /# tests 5(?:\r?\n|$)/u);
    assert.match(result.stdout, /# pass 5(?:\r?\n|$)/u);
    assert.match(result.stdout, /# fail 0(?:\r?\n|$)/u);
    assert.match(result.stdout, /# skipped 0(?:\r?\n|$)/u);
    for (const required of [
      "true SCRAM login and actual Prisma scoped worker process one mail safely",
      "PUBLIC and MAINTAIN drift stop the scoped worker before another dispatch",
      "real scoped Prisma worker persists a failed delivery without privileged writes",
      "actual scoped worker process sends over verified loopback STARTTLS AUTH only",
      "two real scoped workers reconcile exhausted heads and send one OTP over STARTTLS"
    ]) {
      assert.equal(result.stdout.split(/\r?\n/u).filter((line) =>
        /^ok [0-9]+ - /u.test(line) && line.endsWith(required)).length, 1,
      "Every required physical test must actually pass exactly once");
    }
  }
}
function copyToRunner(source, destination) {
  checkRunner();
  assert.ok(existsSync(source), "Reviewed source absent");
  invoke(["cp", source, `${runnerId}:${destination}`]);
}
function requireCopiedSource(source, destination) {
  const expected = createHash("sha256").update(readFileSync(source)).digest("hex");
  checkRunner();
  const observed = invoke(["exec", runnerId, "sha256sum", destination]).stdout;
  assert.equal(observed.split(" ")[0], expected, "Copied source differs from exact local review bytes");
}
function prepareOfflineSmtpCertificates() {
  assert.ok(existsSync(opensslCli), "Local approved Git OpenSSL binary unavailable; no certificate download.");
  const parent = privateLocalHolReceiptDirectory();
  if (!/^[A-Za-z]:\\/u.test(parent) || parent.startsWith("\\\\") || parent.startsWith("//")) {
    throw new Error("Synthetic SMTP certificates require an owner-private local Windows drive, never UNC.");
  }
  ensurePrivateLocalHolReceiptDirectory();
  const directory = mkdtempSync(path.join(parent, `virki-scoped-smtp-${owner}-`));
  const state = lstatSync(directory);
  if (!state.isDirectory() || state.isSymbolicLink()) {
    throw new Error("Offline SMTP certificate directory changed into an unsafe filesystem object.");
  }
  smtpCertificateDirectory = directory;
  const extensionFile = path.join(directory, "server.ext");
  const ca = path.join(directory, "ca.pem");
  const caKey = path.join(directory, "ca.key");
  const certificate = path.join(directory, "server.pem");
  const key = path.join(directory, "server.key");
  const request = path.join(directory, "server.csr");
  writeFileSync(extensionFile,
    "basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\n" +
    "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n");
  const openssl = (args) => {
    const result = spawnSync(opensslCli, args, {
      cwd: directory, env: systemEnv, encoding: "utf8", windowsHide: true, timeout: 15_000
    });
    if (result.status !== 0 || result.error) {
      throw new Error("Offline synthetic SMTP certificate generation failed.");
    }
  };
  openssl(["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-keyout", caKey, "-out", ca, "-subj", "/CN=virki-scoped-smtp-CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key, "-out", request, "-subj", "/CN=127.0.0.1"]);
  openssl(["x509", "-req", "-sha256", "-days", "1", "-in", request,
    "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-out", certificate,
    "-extfile", extensionFile]);
  for (const [source, name] of [[ca, "ca.pem"], [certificate, "server.pem"], [key, "server.key"]]) {
    checkRunner();
    copyToRunner(source, `/app/.virki-scoped-smtp/${name}`);
    requireCopiedSource(source, `/app/.virki-scoped-smtp/${name}`);
  }
  const runnerUid = invoke(["exec", runnerId, "id", "-u"]).stdout;
  const runnerGid = invoke(["exec", runnerId, "id", "-g"]).stdout;
  if (!/^[0-9]{1,6}$/u.test(runnerUid) || !/^[0-9]{1,6}$/u.test(runnerGid) ||
      runnerUid === "0" || runnerGid === "0") {
    throw new Error("Offline scoped SMTP worker requires a nonroot process UID/GID.");
  }
  invoke(["exec", "--user", "root", runnerId, "chown",
    `${runnerUid}:${runnerGid}`, "/app/.virki-scoped-smtp/server.key"]);
  invoke(["exec", "--user", "root", runnerId, "chmod", "600",
    "/app/.virki-scoped-smtp/server.key"]);
}
function cleanupOfflineSmtpCertificates() {
  if (smtpCertificateDirectory === null) return;
  const parent = privateLocalHolReceiptDirectory();
  ensurePrivateLocalHolReceiptDirectory();
  const approvedPrefix = path.join(parent, `virki-scoped-smtp-${owner}-`);
  if (!/^[A-Za-z]:\\/u.test(parent) || parent.startsWith("\\\\") ||
      !smtpCertificateDirectory.startsWith(approvedPrefix) ||
      !lstatSync(smtpCertificateDirectory).isDirectory() ||
      lstatSync(smtpCertificateDirectory).isSymbolicLink()) {
    throw new Error("Refusing to delete an unexpected synthetic certificate directory.");
  }
  rmSync(smtpCertificateDirectory, { recursive: true, force: false, maxRetries: 2 });
  smtpCertificateDirectory = null;
}
// A failed inspect is NOT evidence of absence. Accept only Docker's known,
// object-ID-specific missing diagnostics; daemon errors require reconciliation.
function assertOwnedResourceAbsent(result, kind, id) {
  const allowedName = kind === "network" ? networkName : kind === "runner" ? runnerName : name;
  assert.ok(hexId.test(id) || id === allowedName, "Missing-resource proof requires a pinned ID or owned name");
  if (result.status === 0) throw new Error(`${kind} still exists after owned removal.`);
  const lines = `${result.stdout}\n${result.stderr}`.trim().split(/\r?\n/u)
    .map((line) => line.trim()).filter(Boolean);
  if (lines[0] === "[]") lines.shift();
  const missing = kind === "network"
    ? [`Error response from daemon: network ${id} not found`,
      `Error response from daemon: No such network: ${id}`,
      `Error: No such network: ${id}`]
    : [`Error: No such object: ${id}`,
      `Error response from daemon: No such object: ${id}`,
      `Error response from daemon: No such container: ${id}`,
      `error: no such object: ${id}`];
  if (lines.length !== 1 || !missing.includes(lines[0])) {
    throw new Error(`${kind} removal verification was inconclusive; owner reconciliation required.`);
  }
}
function cleanup() {
  if (cleanupComplete) return;
  if (cleanupActive) throw new Error("Concurrent cleanup attempt; owner reconciliation required.");
  cleanupActive = true;
  const errors = [];
  const attempt = (operation) => {
    try { operation(); }
    catch (error) { errors.push(error); }
  };
  try {
  if (runnerCreateStarted) {
    attempt(() => {
      if (!runnerId) {
      const found = invoke(["inspect", runnerName, "--format",
        `{{.Id}}|{{index .Config.Labels "${ownerLabel}"}}`], { allowFailure: true });
      if (found.status === 0) {
        const [id, identity] = found.stdout.split("|");
        if (!hexId.test(id) || identity !== owner) throw new Error("Runner ownership uncertain; no unsafe deletion.");
        runnerId = id;
      } else {
        assertOwnedResourceAbsent(found, "runner", runnerName);
        if (runnerCreateCommandIssued) {
          throw new Error("Runner create command was issued without an ACK; delayed creation remains possible, reconciliation required.");
        }
        record("RUNNER_NOT_CREATED_CONFIRMED");
      }
      }
      if (runnerId) {
      checkRunner();
      record("RUNNER_REMOVE_PENDING", runnerId);
      invoke(["rm", "--force", "--volumes", runnerId]);
      assertOwnedResourceAbsent(invoke(["inspect", runnerId], { allowFailure: true }), "runner", runnerId);
      record("RUNNER_REMOVE_CONFIRMED", runnerId);
      }
    });
  }
  if (containerCreateStarted) {
    attempt(() => {
      if (!containerId) {
      const found = invoke(["inspect", name, "--format",
        `{{.Id}}|{{index .Config.Labels "${ownerLabel}"}}`], { allowFailure: true });
      if (found.status === 0) {
        const [id, identity] = found.stdout.split("|");
        if (!hexId.test(id) || identity !== owner) throw new Error("Container ownership uncertain; no unsafe deletion.");
        containerId = id;
      } else {
        assertOwnedResourceAbsent(found, "database", name);
        if (containerCreateCommandIssued) {
          throw new Error("PostgreSQL create command was issued without an ACK; delayed creation remains possible, reconciliation required.");
        }
        record("DATABASE_NOT_CREATED_CONFIRMED");
      }
      }
      if (containerId) {
      checkContainer();
      record("DATABASE_REMOVE_PENDING", containerId);
      invoke(["rm", "--force", "--volumes", containerId]);
      assertOwnedResourceAbsent(invoke(["inspect", containerId], { allowFailure: true }), "database", containerId);
      record("DATABASE_REMOVE_CONFIRMED", containerId);
      }
    });
  }
  if (networkCreateStarted) {
    attempt(() => {
      if (!networkId) {
      const found = invoke(["network", "inspect", networkName, "--format",
        `{{.Id}}|{{index .Labels "${ownerLabel}"}}`], { allowFailure: true });
      if (found.status === 0) {
        const [id, identity] = found.stdout.split("|");
        if (!hexId.test(id) || identity !== owner) throw new Error("Network ownership uncertain; no unsafe deletion.");
        networkId = id;
      } else {
        assertOwnedResourceAbsent(found, "network", networkName);
        if (networkCreateCommandIssued) {
          throw new Error("Docker network create command was issued without an ACK; delayed creation remains possible, reconciliation required.");
        }
        record("NETWORK_NOT_CREATED_CONFIRMED");
      }
      }
      if (networkId) {
      checkNetwork();
      record("NETWORK_REMOVE_PENDING", networkId);
      invoke(["network", "rm", networkId]);
      assertOwnedResourceAbsent(invoke(["network", "inspect", networkId], { allowFailure: true }), "network", networkId);
      record("NETWORK_REMOVE_CONFIRMED", networkId);
      }
    });
  }
    // Host-side ephemeral CA/server private keys are part of the same owned
    // fixture cleanup, including SIGINT/SIGTERM. No cleanup PASS before both
    // Docker identities and local synthetic keys are gone.
    attempt(() => cleanupOfflineSmtpCertificates());
    if (errors.length > 0) {
      throw new AggregateError(errors, "Owned Docker cleanup incomplete; reconciliation required.");
    }
    record("CLEANUP_CONFIRMED");
    cleanupComplete = true;
    process.stdout.write("LOCAL_FULL_SCHEMA_WORKER_CLEANUP=PASS\n");
  } catch (error) {
    try { record("RECONCILIATION_REQUIRED"); } catch { /* preserve original failure */ }
    throw error;
  } finally {
    cleanupActive = false;
  }
}

for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  process.once(signal, () => {
    interrupted = true;
    try { cleanup(); }
    catch (error) { console.error(error instanceof Error ? error.message : "Cleanup inconclusive."); }
    finally {
      if (receiptFd !== null) { closeSync(receiptFd); receiptFd = null; }
      process.exit(code);
    }
  });
}

async function main() {
  requireLocalOnly();
  assert.equal(invoke(["image", "inspect", image, "--format", "{{.Id}}"]).stdout,
    imageId, "Only cached pinned PG18 image accepted (never pull)");
  assert.equal(invoke(["image", "inspect", runnerImage, "--format", "{{.Id}}"]).stdout,
    runnerImageId, "Only cached pinned Node 22 image accepted (never pull)");
  assert.equal(invoke(["image", "inspect", runnerImage, "--format",
    '{{index .Config.Labels "org.opencontainers.image.revision"}}']).stdout,
  runnerSourceRevision, "Node runner must have the reviewed base revision");
  assert.equal(invoke(["version", "--format", "{{.Server.Os}}|{{.Server.Arch}}"]).stdout,
    "linux|amd64", "Only local Linux Docker engine accepted");
  let primaryError;
  let cleanupError;
  try {
    record("LOCAL_ADMISSION_CONFIRMED");
    record("NETWORK_CREATE_PENDING");
    networkCreateStarted = true;
    networkCreateCommandIssued = true;
    networkId = invoke(["network", "create", "--internal", "--driver", "bridge",
      "--label", `${ownerLabel}=${owner}`, networkName]).stdout;
    checkNetwork();
    record("NETWORK_CREATE_ACK", networkId);
    record("DATABASE_CREATE_PENDING");
    containerCreateStarted = true;
    containerCreateCommandIssued = true;
    containerId = invoke(["create", "--name", name, "--network", networkName,
      "--network-alias", "postgres", "--label", `${ownerLabel}=${owner}`,
      "--security-opt", "no-new-privileges:true",
      "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m",
      "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m",
      "--env", "PGDATA=/var/lib/postgresql/data/pgdata",
      "--env", `POSTGRES_DB=${dbName}`, "--env", "POSTGRES_USER=virki_bootstrap",
      ...Object.keys(secrets).filter((key) => key !== "VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER")
        .flatMap((key) => ["--env", key]),
      "--mount", `type=bind,source=${path.join(root, "infra", "postgres-init", "10-virki-database-roles.sh")},target=/docker-entrypoint-initdb.d/10-virki-database-roles.sh,readonly`,
      image]).stdout;
    checkContainer();
    record("DATABASE_CREATE_ACK", containerId);
    invoke(["start", containerId]);
    let ready = false;
    for (let i = 0; i < 90; i += 1) {
      const state = invoke(["exec", containerId, "pg_isready", "-h", "/var/run/postgresql",
        "-U", "virki_bootstrap", "-d", dbName], { allowFailure: true }).status;
      if (state === 0) { ready = true; break; }
      await delay(400);
    }
    assert.ok(ready, "Local disposable PostgreSQL failed to start");
    checkContainer();
    record("RUNNER_CREATE_PENDING");
    runnerCreateStarted = true;
    if (process.env.VIRKI_STAGING_WORKER_FULL_SCHEMA_FAIL_AT === "before-runner-create") {
      throw new Error("Synthetic runner create failure before Docker command.");
    }
    if (process.env.VIRKI_STAGING_WORKER_FULL_SCHEMA_FAIL_AT === "simulate-runner-ack-loss") {
      runnerCreateCommandIssued = true;
      throw new Error("Synthetic unacknowledged runner creation; no real runner-create command sent.");
    }
    runnerCreateCommandIssued = true;
    runnerId = invoke(["create", "--name", runnerName, "--network", networkName,
      "--label", `${ownerLabel}=${owner}`, "--entrypoint", "/bin/sh",
      runnerImage, "-c", "sleep infinity"]).stdout;
    checkRunner();
    record("RUNNER_CREATE_ACK", runnerId);
    invoke(["start", runnerId]);
    assert.match(invoke(["exec", runnerId, "node", "--version"]).stdout,
      /^v22\./u, "The application must run on pinned Node 22");
    // Copy exact CURRENT source into the offline runner; use only its cached
    // Node dependencies, never its older application code or an external npm.
    for (const segment of [
      ["packages", "auth", "src"],
      ["packages", "database", "src"],
      ["packages", "database", "prisma"],
      ["packages", "database", "scripts"]
    ]) {
      copyToRunner(path.join(root, ...segment), `/app/${segment.slice(0, -1).join("/")}/`);
    }
    copyToRunner(path.join(root, "scripts", "staging-email-worker-full-schema.proof.ts"),
      "/app/scripts/staging-email-worker-full-schema.proof.ts");
    invoke(["exec", runnerId, "mkdir", "-p", "/app/scripts/integration"]);
    copyToRunner(path.join(root, "scripts", "integration", "loopback-smtp-sink.mjs"),
      "/app/scripts/integration/loopback-smtp-sink.mjs");
    requireCopiedSource(path.join(root, "packages", "auth", "src", "email.ts"),
      "/app/packages/auth/src/email.ts");
    requireCopiedSource(path.join(root, "packages", "auth", "src", "email-worker-role.ts"),
      "/app/packages/auth/src/email-worker-role.ts");
    requireCopiedSource(path.join(root, "scripts", "staging-email-worker-full-schema.proof.ts"),
      "/app/scripts/staging-email-worker-full-schema.proof.ts");
    requireCopiedSource(path.join(root, "scripts", "integration", "loopback-smtp-sink.mjs"),
      "/app/scripts/integration/loopback-smtp-sink.mjs");
    const runnerUid = invoke(["exec", runnerId, "id", "-u"]).stdout;
    const runnerGid = invoke(["exec", runnerId, "id", "-g"]).stdout;
    if (!/^[0-9]{1,6}$/u.test(runnerUid) || !/^[0-9]{1,6}$/u.test(runnerGid) ||
        runnerUid === "0" || runnerGid === "0") {
      throw new Error("Offline scoped SMTP runner must be nonroot.");
    }
    invoke(["exec", "--user", "root", runnerId, "mkdir", "-p", "/app/.virki-scoped-smtp"]);
    invoke(["exec", "--user", "root", runnerId, "chown",
      `${runnerUid}:${runnerGid}`, "/app/.virki-scoped-smtp"]);
    invoke(["exec", "--user", "root", runnerId, "chmod", "700", "/app/.virki-scoped-smtp"]);
    prepareOfflineSmtpCertificates();
    if (process.env.VIRKI_STAGING_WORKER_FULL_SCHEMA_FAIL_AT === "after-smtp-certificate-create") {
      throw new Error("Synthetic failure after owner-private SMTP certificate creation.");
    }
    const url = (role, key) => `postgresql://${role}:${key}@postgres:5432/${dbName}?schema=public`;
    const baseEnv = {
      NODE_ENV: "test", DATABASE_URL: url("virki_runtime", secrets.VIRKI_RUNTIME_DB_PASSWORD),
      MIGRATION_DATABASE_URL: url("virki_migrator", secrets.VIRKI_MIGRATOR_DB_PASSWORD),
      AUDIT_LOG_RETENTION_DAYS: "180"
    };
    runInRunner("Prisma generate", ["npm", "run", "prisma:generate", "--workspace", "@virki/database"],
      baseEnv, 120_000, "root");
    runInRunner("Prisma migrations", ["node", "packages/database/scripts/prisma-migrate.mjs", "deploy"], baseEnv);
    assert.equal(psql('SELECT count(*) FROM public."_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL;'), "19",
      "Exactly 19 committed migrations must be applied");
    psql(`REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE ${dbName} FROM PUBLIC;`);
    checkContainer();
    const workerRoleScript = path.join(root, "infra", "postgres-init", "11-virki-email-worker-role.sh");
    invoke(["cp", workerRoleScript, `${containerId}:/11-virki-email-worker-role.sh`]);
    assert.equal(invoke(["exec", containerId, "sha256sum", "/11-virki-email-worker-role.sh"])
      .stdout.split(" ")[0], createHash("sha256").update(readFileSync(workerRoleScript)).digest("hex"),
    "Copied role provisioning script must match the exact local review bytes");
    invoke(["exec", "--env", "VIRKI_EMAIL_WORKER_DB_PASSWORD",
      "--env", "VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER", containerId, "sh",
      "/11-virki-email-worker-role.sh"]);
    checkContainer();
    // Force true TCP SCRAM as the first matching HBA rule; a default TRUST
    // fixture would make a wrong-password test falsely pass.
    invoke(["exec", "--user", "postgres", containerId, "sed", "-i",
      "1i host all all 0.0.0.0/0 scram-sha-256",
      "/var/lib/postgresql/data/pgdata/pg_hba.conf"]);
    assert.equal(psql("SELECT pg_reload_conf();"), "t");
    assert.equal(psql("SELECT auth_method FROM pg_hba_file_rules WHERE type='host' ORDER BY line_number LIMIT 1;"),
      "scram-sha-256");
    runInRunner("Prisma scoped worker", [
      "node", "node_modules/tsx/dist/cli.mjs",
      "--test", "--test-reporter=tap",
      "scripts/staging-email-worker-full-schema.proof.ts"
    ], {
      ...baseEnv,
      DATABASE_URL: url("virki_email_worker", secrets.VIRKI_EMAIL_WORKER_DB_PASSWORD),
      VIRKI_PROOF_RUNTIME_URL: baseEnv.DATABASE_URL,
      VIRKI_PROOF_WRONG_URL: url("virki_email_worker", password()),
      VIRKI_EMAIL_WORKER_SCOPED_ROLE: "required",
      VIRKI_EMAIL_OUTBOX_KEY: password(),
      VIRKI_STAGING_WORKER_FULL_SCHEMA_PROOF: "owned-internal-network",
      VIRKI_SCOPED_SMTP_CERT_DIR: "/app/.virki-scoped-smtp"
    });
  } catch (error) {
    primaryError = error;
  } finally {
    try { cleanup(); } catch (error) { cleanupError = error; }
    try {
      if (receiptFd !== null) closeSync(receiptFd);
    } catch (error) {
      cleanupError = cleanupError
        ? new AggregateError([cleanupError, error], "Cleanup and receipt close both failed.")
        : error;
    } finally { receiptFd = null; }
  }
  if (primaryError && cleanupError) {
    throw new AggregateError([primaryError, cleanupError],
      `Local proof failed (${sanitize(primaryError instanceof Error ? primaryError.message : "unknown")}); Docker cleanup also requires reconciliation.`,
      { cause: primaryError });
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  if (interrupted) throw new Error("Interrupted run cannot claim PASS.");
  process.stdout.write("LOCAL_FULL_SCHEMA_WORKER_PRISMA=PASS (19 migrations, 5 real Prisma tests, two scoped SMTP STARTTLS workers and ACL)\n");
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Full-schema proof failed");
  process.exitCode = 1;
});
