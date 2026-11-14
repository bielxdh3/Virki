import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  HOL_IMAGE, HOL_IMAGE_DIGEST, HOL_OWNER_LABEL, HOL_KIND_LABEL, HOL_KIND,
  assertLocalHolHost, localHolSystemEnvironment, localHolTestEnvironment,
  requireSignedDockerCli, requireHolImage, requireHolPlatform, requireHolContainerImage,
  requireHolPort, requireHolPostgresVersion, requireHolOwner,
  requireHolContainerIdentity, reconcileLocalHolContainer
} from "./local-worker-hol-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const owner = "10203040-5060-4070-8090-a0b0c0d0e0f0";
const name = `virki-email-hol-local-${owner}`;
const database = "virki_email_worker_hol_a1b2c3d4e5f6";
const cid = "d".repeat(64);
const id = `sha256:${cid}`;
const observed = `${cid}|/${name}|${owner}|${HOL_KIND}`;
const missing = (target) => ({
  status: 1, stdout: "", stderr: `error: no such object: ${target}\n`
});
const versionEnv = { PATH: "C:\\test", SystemRoot: "C:\\Windows", HOME: "home", NODE_ENV: "development" };

test("fixed PG17 image and immutable Docker identities never accept mutable or foreign targets", () => {
  assert.equal(HOL_OWNER_LABEL, "org.virki.email-hol-disposable-owner");
  assert.equal(HOL_KIND_LABEL, "org.virki.email-hol-disposable-kind");
  assert.equal(HOL_IMAGE, `postgres:17-alpine@${HOL_IMAGE_DIGEST}`);
  assert.match(HOL_IMAGE_DIGEST, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(requireHolImage(`${id}|["postgres@${HOL_IMAGE_DIGEST}"]`), id);
  assert.equal(requireHolImage(`${id}|["docker.io/library/postgres@${HOL_IMAGE_DIGEST}"]`), id);
  for (const image of [
    `${id}|[]`, `${id}|["postgres:17-alpine"]`, `${id}|["postgres@sha256:${"a".repeat(64)}"]`,
    `sha256:wrong|["postgres@${HOL_IMAGE_DIGEST}"]`, `${id}|not-json`, "",
    `${id}|["malicious/postgres@${HOL_IMAGE_DIGEST}"]`
  ]) assert.throws(() => requireHolImage(image), /digest/u);
  requireHolPlatform("linux|amd64");
  for (const platform of ["linux|arm64", "windows|amd64", ""]) {
    assert.throws(() => requireHolPlatform(platform), /linux\/amd64/u);
  }
  requireHolContainerImage(`${id}|${HOL_IMAGE}`, id);
  for (const image of [`${id}|postgres:latest`, `${id}|postgres:17-alpine`,
    `sha256:${"a".repeat(64)}|${HOL_IMAGE}`]) {
    assert.throws(() => requireHolContainerImage(image, id), /pinned PG17/u);
  }
  assert.equal(requireHolPort("127.0.0.1:54321"), "54321");
  for (const port of ["0.0.0.0:54321", "[::1]:54321", "127.0.0.1:0",
    "127.0.0.1:65536", "127.0.0.1:54321\n127.0.0.1:54322"]) {
    assert.throws(() => requireHolPort(port), /loopback/u);
  }
  requireHolPostgresVersion("170006");
  for (const version of ["180006", "160009", "17.0", ""]) {
    assert.throws(() => requireHolPostgresVersion(version), /major 17/u);
  }
});

test("local runner refuses GitHub imitation, remote Docker contexts and inherited secrets", () => {
  assert.doesNotThrow(() => assertLocalHolHost({ platform: "win32", source: versionEnv }));
  assert.throws(() => assertLocalHolHost({
    platform: "win32", source: { ...versionEnv, NODE_ENV: "production" }
  }), /production and CI/u);
  assert.throws(() => assertLocalHolHost({
    platform: "win32", source: { ...versionEnv, CI: "true" }
  }), /production and CI/u);
  for (const platform of ["linux", "darwin", "freebsd"]) {
    assert.throws(() => assertLocalHolHost({ platform, source: versionEnv }), /Windows Docker Desktop/u);
  }
  const bad = {
    DOCKER_HOST: "tcp://production.invalid:2376", DOCKER_CONTEXT: "production",
    DOCKER_CONFIG: "C:\\prod", DATABASE_URL: "postgresql://production.invalid/prod",
    MIGRATION_DATABASE_URL: "postgresql://production.invalid/prod",
    VIRKI_INTEGRATION_DATABASE_URL: "postgresql://production.invalid/prod",
    VIRKI_EMAIL_SMTP_PASSWORD: "real-smtp-password", VIRKI_EMAIL_TRANSPORT: "smtp",
    VIRKI_EMAIL_OUTBOX_KEY: "secret", NODE_OPTIONS: "--require=prod-hook",
    NODE_PATH: "somewhere", GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted",
    GITHUB_TOKEN: "secret", ACTIONS_RUNTIME_TOKEN: "secret", CLOUDFLARE_TUNNEL_TOKEN: "secret",
    VIRKI_RATE_LIMIT_HASH_SECRET: "secret", GH_TOKEN: "secret"
  };
  for (const [key, value] of Object.entries(bad)) {
    assert.throws(() => assertLocalHolHost({ platform: "win32", source: { ...versionEnv, [key]: value } }), /refuses inherited/u, key);
  }
  assert.deepEqual(localHolSystemEnvironment({ ...versionEnv, ...bad }), {
    PATH: versionEnv.PATH, SystemRoot: versionEnv.SystemRoot, HOME: versionEnv.HOME
  });
  requireSignedDockerCli({ status: 0, stdout: "VALID_DOCKER_CLI" });
  for (const signature of [{ status: 0, stdout: "Valid" }, { status: 0, stdout: "" },
    { status: 1, stdout: "VALID_DOCKER_CLI" }, { error: new Error("unavailable") }]) {
    assert.throws(() => requireSignedDockerCli(signature), /Authenticode/u);
  }
});

test("worker and migrator roles, independent secrets, virgin queue and explicit local-only envelope", () => {
  const url = (role, password) => `postgresql://${role}:${password}@127.0.0.1:54444/${database}?schema=public`;
  const runtime = url("virki_runtime_test", "a".repeat(64));
  const migration = url("virki_migrator", "b".repeat(64));
  let cursor = 0;
  const secret = () => (++cursor).toString(16).padStart(64, "0");
  const env = localHolTestEnvironment({
    source: { ...versionEnv, NODE_OPTIONS: "--require=prod", GITHUB_TOKEN: "private", VIRKI_EMAIL_TRANSPORT: "smtp" },
    databaseUrl: runtime, migrationUrl: migration, secret
  });
  assert.deepEqual(Object.keys(env).sort(), [
    "PATH", "SystemRoot", "HOME", "NODE_ENV", "VIRKI_INTEGRATION_ENABLED",
    "VIRKI_CORE_TEST_DATABASE_CONFIRM", "VIRKI_EMAIL_WORKER_DEDICATED_DB",
    "DATABASE_URL", "VIRKI_INTEGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL",
    "AUDIT_LOG_RETENTION_DAYS", "VIRKI_PORTAL_URL", "VIRKI_HUB_URL",
    "VIRKI_OIDC_ADAPTER_KEY", "VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY"
  ].sort());
  assert.equal(env.NODE_ENV, "test");
  assert.equal(env.VIRKI_EMAIL_WORKER_DEDICATED_DB, "confirmed");
  assert.equal(env.VIRKI_EMAIL_OUTBOX_KEY, "3".padStart(64, "0"));
  for (const invalid of [
    { databaseUrl: runtime.replace("127.0.0.1", "prod.invalid") },
    { databaseUrl: runtime.replace(database, "production") },
    { databaseUrl: runtime.replace("virki_runtime_test", "virki_migrator") },
    { migrationUrl: migration.replace(database, "another_db") },
    { migrationUrl: migration.replace(":54444", ":44444") },
    { migrationUrl: migration.replace("virki_migrator", "virki_runtime_test") },
    { databaseUrl: runtime.replace("?schema=public", "") }
  ]) assert.throws(() => localHolTestEnvironment({
    source: versionEnv, databaseUrl: runtime, migrationUrl: migration, secret,
    ...invalid
  }), /role isolation/u);
  assert.throws(() => localHolTestEnvironment({
    source: versionEnv, databaseUrl: runtime, migrationUrl: migration, secret: () => "a".repeat(64)
  }), /independent/u);
});

function fakeDocker({ initial = observed, second = observed, rmStatus = 0, afterRemoval = true } = {}) {
  const calls = [];
  let checks = 0;
  let removed = false;
  const invoke = (args) => {
    calls.push(args);
    if (args[0] === "inspect") {
      checks++;
      if (removed && afterRemoval) return missing(args.at(-1));
      const found = checks === 1 ? initial : second;
      return found === null ? missing(args.at(-1)) : { status: 0, stdout: found };
    }
    if (args[0] === "rm") {
      removed = rmStatus === 0;
      return { status: rmStatus, stdout: "" };
    }
    throw new Error("Mock should only see inspect or verified rm");
  };
  return { invoke, calls };
}

test("ownership is immutable: no foreign label, name, ID, or forged ACK may cause deletion", () => {
  requireHolOwner({ owner, name, database });
  assert.equal(requireHolContainerIdentity(observed, { owner, name, expectedId: cid }), cid);
  for (const wrong of [
    observed.replace(owner, "not-owner"),
    observed.replace("/" + name, "/another-name"),
    observed.replace(HOL_KIND, "shared"),
    observed.replace(cid, "f".repeat(64))
  ]) {
    assert.throws(() => requireHolContainerIdentity(wrong, { owner, name, expectedId: cid }), /immutable owner/u);
  }
  const recorded = [];
  const foreign = fakeDocker({ initial: observed.replace(owner, "foreign") });
  assert.throws(() => reconcileLocalHolContainer({
    invoke: foreign.invoke, owner, name, containerId: cid, uncertainStart: false,
    record: (...entry) => recorded.push(entry)
  }), /immutable owner/u);
  assert.equal(foreign.calls.some((call) => call[0] === "rm"), false);
  assert.equal(recorded.length, 0);

  const changed = fakeDocker({ second: observed.replace(HOL_KIND, "other") });
  assert.throws(() => reconcileLocalHolContainer({
    invoke: changed.invoke, owner, name, containerId: cid, uncertainStart: false, record: () => {}
  }), /immutable owner/u);
  assert.equal(changed.calls.some((call) => call[0] === "rm"), false);
});

test("lost RUN acknowledgement cannot false-green when container is absent", () => {
  const unacknowledged = fakeDocker({ initial: null });
  const recorded = [];
  assert.throws(() => reconcileLocalHolContainer({
    invoke: unacknowledged.invoke, owner, name, uncertainStart: true,
    record: (...entry) => recorded.push(entry)
  }), /absent container is not proof/u);
  assert.equal(recorded.length, 0);
  assert.equal(unacknowledged.calls.some((call) => call[0] === "rm"), false);
  const alreadyGone = fakeDocker({ initial: null });
  reconcileLocalHolContainer({
    invoke: alreadyGone.invoke, owner, name, containerId: cid, uncertainStart: false,
    record: (...entry) => recorded.push(entry)
  });
  assert.deepEqual(recorded, [["AUTO_REMOVED_CONFIRMED", cid]]);
  const neverGone = fakeDocker({ initial: null });
  assert.throws(() => reconcileLocalHolContainer({
    invoke: (args, timeout) => {
      const response = neverGone.invoke(args, timeout);
      return response?.status !== 0 ? { ...response, stderr: "permission denied" } : response;
    }, owner, name, containerId: cid, uncertainStart: false, record: () => {}
  }), /inconclusive/u, "unknown Docker errors are NEVER accepted as confirmed removal");
});

test("cleanup removes ONLY the verified immutable owned ID and requires proof it vanished", () => {
  const good = fakeDocker();
  const recorded = [];
  reconcileLocalHolContainer({
    invoke: good.invoke, owner, name, containerId: cid, uncertainStart: false,
    record: (...entry) => recorded.push(entry)
  });
  assert.deepEqual(recorded, [["REMOVE_PENDING", cid], ["CLEANUP_CONFIRMED", cid]]);
  assert.deepEqual(good.calls.filter((call) => call[0] === "rm"), [["rm", "--force", "--volumes", cid]]);
  const failed = fakeDocker({ rmStatus: 1 });
  const failureRecord = [];
  assert.throws(() => reconcileLocalHolContainer({
    invoke: failed.invoke, owner, name, containerId: cid, uncertainStart: false,
    record: (...entry) => failureRecord.push(entry)
  }), /removal/u);
  assert.deepEqual(failureRecord, [["REMOVE_PENDING", cid]]);
  const stillThere = fakeDocker({ afterRemoval: false });
  assert.throws(() => reconcileLocalHolContainer({
    invoke: stillThere.invoke, owner, name, containerId: cid, uncertainStart: false,
    record: () => {}
  }), /removal/u);
});

test("static physical launcher is a separate local gate, never enables CI identity or SMTP", () => {
  const script = readFileSync(path.join(root, "scripts", "integration", "local-worker-hol-disposable.mjs"), "utf8");
  const ciScript = readFileSync(path.join(root, "scripts", "integration", "worker-hol-ci.sh"), "utf8");
  const receipt = readFileSync(path.join(root, "scripts", "integration", "local-worker-hol-receipt.mjs"), "utf8");
  assert.match(script, /Get-AuthenticodeSignature/u);
  assert.match(script, /createAdmittedOidcDockerClient/u);
  assert.match(script, /VIRGIN_DATABASE_OBSERVED/u);
  assert.match(script, /scripts", "integration", "worker-hol\.mjs"/u);
  assert.match(script, /PHYSICAL_TWO_TESTS_PASS/u);
  assert.match(script, /reconcileLocalHolContainer/u);
  assert.match(receipt, /Foreign writer can alter HOL receipt parent/u);
  assert.match(receipt, /Foreign access to local HOL private receipt/u);
  assert.match(receipt, /GetOwner/u);
  assert.match(receipt, /inheritance:r/u);
  assert.doesNotMatch(script, /(?:GITHUB_ACTIONS|RUNNER_ENVIRONMENT)\s*[=:]/u);
  assert.doesNotMatch(script, /(?:smtp|SMTP)[.-]?(?:send|connect|createTransport)\s*\(/u);
  assert.match(ciScript, /VIRKI_HOL_RUNNER_ENVIRONMENT/u, "CI gate must remain GitHub-exclusive");
});
