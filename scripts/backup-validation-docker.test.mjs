import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  assertLocalBackupEnvironment, createBackupOwnerEvidence, finalizeBackupOwnerEvidence,
  readBackupOwnerEvidence, DOCKER_BINARY, DOCKER_HOST, inspectLinuxRunnerSocket,
  LINUX_CI_DOCKER_BINARY, LINUX_CI_DOCKER_HOST, LocalBackupDocker, POSTGRES_IMAGE,
} from "./lib/backup-validation-docker.mjs";

const id = "a".repeat(64);
const alternateId = "c".repeat(64);
const nonce = "b".repeat(48);
const env = { VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER: "1" };
const ciEnv = {
  VIRKI_BACKUP_VALIDATION_LINUX_CI: "1", GITHUB_ACTIONS: "true", CI: "true",
  RUNNER_OS: "Linux", RUNNER_ENVIRONMENT: "github-hosted", GITHUB_REPOSITORY: "bielxdh3/Virki",
  GITHUB_RUN_ID: "1234567", GITHUB_RUN_ATTEMPT: "1",
};

function fixture(overrides = {}) {
  const calls = [];
  const state = { infoId: "desktop-engine-id", owner: nonce, containerId: id, returnedId: id, ...overrides };
  const identity = { socketDevice: 7, socketInode: 1234, hostname: "gha-runner-01" };
  const inspect = () => ({
    Id: state.containerId,
    Image: state.imageId ?? `sha256:${"d".repeat(64)}`,
    Name: `/virki-backup-validation-${nonce}`,
    Config: {
      Image: POSTGRES_IMAGE,
      Labels: {
        "virki.backup-validation.owner": state.owner,
        "virki.backup-validation.fixture": "prisma-backup-restore",
      },
    },
    HostConfig: { Privileged: false, Binds: null, Tmpfs: { "/var/lib/postgresql/data": "rw,noexec,nosuid,nodev,size=512m" }, PortBindings: { "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "" }] } },
    Mounts: [],
    NetworkSettings: { Ports: { "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "56432" }] } },
    State: { Running: true, Health: { Status: "healthy" } },
  });
  const spawn = (binary, args, options) => {
    calls.push({ binary, args, options });
    const subcommand = args[4];
    if (subcommand === "info") return { status: 0, stdout: JSON.stringify({ OSType: "linux", OperatingSystem: state.os ?? (state.linux ? "Ubuntu 24.04" : "Docker Desktop"), ID: state.infoId, Name: state.daemonName ?? identity.hostname }) };
    if (subcommand === "pull") return { status: state.pullStatus ?? 0, stdout: "Digest: verified" };
    if (subcommand === "image") return { status: state.imageStatus ?? 0, stdout: `sha256:${"d".repeat(64)}` };
    if (subcommand === "run") return { status: state.runStatus ?? 0, stdout: state.returnedId, stderr: "password=secret" };
    if (subcommand === "inspect") return { status: state.inspectStatus ?? 0, stdout: JSON.stringify({ ...inspect(), ...state.inspectOverrides }) };
    if (subcommand === "rm") return { status: state.removeStatus ?? 0, stdout: state.containerId };
    if (subcommand === "ps") return { status: state.listStatus ?? 0, stdout: state.listOutput ?? "" };
    if (subcommand === "exec") return { status: state.execStatus ?? 0, stdout: options.encoding === null ? Buffer.from("fixture") : "fixture", stderr: "secret=leak" };
    throw new Error(`Unexpected Docker invocation: ${subcommand}`);
  };
  const docker = new LocalBackupDocker({ configDirectory: state.linux ? "/tmp/backup-docker-config" : "C:\\private\\test-docker-config",
    env: state.linux ? ciEnv : env, platform: state.linux ? "linux" : "win32", spawn,
    linuxProbe: () => ({ ...identity, ...state.linuxProbeOverrides }), nonce });
  return { docker, calls, state, identity };
}

test("refuses all ambient remote/context, database and Node overrides before invoking Docker", () => {
  for (const key of ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "COMPOSE_PROJECT_NAME", "DATABASE_URL", "MIGRATION_DATABASE_URL", "PGHOST", "PGPORT", "PGSERVICEFILE", "PGPASSWORD", "NODE_OPTIONS"]) {
    assert.throws(() => assertLocalBackupEnvironment({ ...env, [key]: "remote-or-secret" }, "win32"), /refuses ambient/u, key);
  }
  assert.throws(() => assertLocalBackupEnvironment({}, "win32"), /opt-in/u);
  assert.throws(() => assertLocalBackupEnvironment(env, "linux"), /opt-in/u);
});

test("Linux CI rejects missing or mismatched environment hints, which are not attestation", () => {
  for (const overrides of [
    { RUNNER_ENVIRONMENT: "self-hosted" }, { GITHUB_ACTIONS: "false" }, { RUNNER_OS: "Windows" },
    { CI: "false" }, { GITHUB_REPOSITORY: "attacker/fork" }, { GITHUB_RUN_ID: "0" },
    { GITHUB_RUN_ATTEMPT: "${bad}" }, { VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER: "1" },
  ]) {
    assert.throws(() => assertLocalBackupEnvironment({ ...ciEnv, ...overrides }, "linux"), /opt-in/u);
  }
  assert.equal(assertLocalBackupEnvironment(ciEnv, "linux"), "linux-ci");
  for (const key of ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "COMPOSE_FILE", "PGHOST", "PGPASSWORD", "MIGRATION_DATABASE_URL", "NODE_OPTIONS"]) {
    assert.throws(() => assertLocalBackupEnvironment({ ...ciEnv, [key]: "evil" }, "linux"), /ambient/u);
  }
});

test("workflow opts in only when hosted Linux runner contexts and repository match", () => {
  const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const step = workflow.match(/ {6}- name: Validate database backup and restore\r?\n([\s\S]*?)(?=\r?\n {6}- name:|$)/u)?.[1];
  assert.ok(step, "CI must retain the real Prisma backup/restore step.");
  assert.match(step, /VIRKI_BACKUP_VALIDATION_LINUX_CI: \$\{\{ runner\.environment == 'github-hosted' && runner\.os == 'Linux' && github\.repository == 'bielxdh3\/Virki' && '1' \|\| '0' \}\}/u);
  assert.match(step, /run: npm run test:backup:restore/u);
  assert.doesNotMatch(step, /if:\s*\$\{\{/u, "Untrusted runner context must fail the test, not silently skip it.");
});

test("Linux CI checks root-owned canonical local socket and CLI metadata", () => {
  const stat = (target) => target.endsWith(".sock")
    ? { isSocket: () => true, uid: 0, mode: 0o140660, dev: 4, ino: 55 }
    : { isFile: () => true, uid: 0, mode: 0o100755 };
  const realpath = (target) => target.endsWith(".sock") ? "/run/docker.sock" : LINUX_CI_DOCKER_BINARY;
  const valid = { stat, realpath, hostname: () => "gha-linux-runner" };
  assert.deepEqual(inspectLinuxRunnerSocket(valid), { socketDevice: 4, socketInode: 55, hostname: "gha-linux-runner" });
  for (const probe of [
    { realpath: (target) => target.endsWith(".sock") ? "/tmp/ssh-forwarded.sock" : LINUX_CI_DOCKER_BINARY },
    { stat: (target) => ({ ...stat(target), uid: 1000 }) },
    { stat: (target) => ({ ...stat(target), mode: 0o140666 }) },
    { stat: () => ({ isSocket: () => false, isFile: () => false, uid: 0, mode: 0o100755, dev: 4, ino: 55 }) },
    { hostname: () => "host\nspoofed" },
  ]) {
    assert.throws(() => inspectLinuxRunnerSocket({ ...valid, ...probe }), /safety checks/u);
  }
  assert.throws(() => inspectLinuxRunnerSocket({ ...valid, stat: () => { throw new Error("ENOENT"); } }), /could not be checked/u);
});

test("Linux refuses a missing local socket before any Docker CLI call", () => {
  let executed = false;
  assert.throws(() => new LocalBackupDocker({
    configDirectory: "/tmp/backup-docker-config", env: ciEnv, platform: "linux", nonce,
    linuxProbe: () => inspectLinuxRunnerSocket({ stat: () => { throw new Error("ENOENT"); } }),
    spawn: () => { executed = true; throw new Error("unexpected exec"); },
  }), /could not be checked/u);
  assert.equal(executed, false);
});

test("matching spoofable CI variables and daemon metadata cannot prove local origin", () => {
  // Models a local root-owned forwarding proxy reporting the expected metadata.
  // It intentionally passes consistency checks. This is a TRUST ASSUMPTION,
  // not evidence of a cryptographically verified GitHub runner/daemon.
  assert.equal(assertLocalBackupEnvironment({ ...ciEnv }, "linux"), "linux-ci");
  const simulatedProxy = fixture({ linux: true, daemonName: "gha-runner-01", infoId: "forged-id" });
  assert.doesNotThrow(() => simulatedProxy.docker.start({ database: "d", user: "u", password: "p" }));
  assert.equal(simulatedProxy.docker.daemonId, "forged-id");
  simulatedProxy.docker.cleanup();
});

test("Linux CI pins argv and socket metadata on an assumed trusted runner, and pulls one digest", () => {
  const { docker, calls, state } = fixture({ linux: true });
  docker.start({ database: "d", user: "u", password: "p" });
  assert.deepEqual(calls.filter((call) => call.args[4] === "pull").map((call) => call.args.slice(4)), [["pull", POSTGRES_IMAGE]]);
  assert.ok(calls.every((call) => call.binary === LINUX_CI_DOCKER_BINARY && call.args[1] === LINUX_CI_DOCKER_HOST));
  assert.ok(calls.every((call) => Object.keys(call.options.env).sort().join() === "DOCKER_CONFIG,HOME,LANG"));
  docker.cleanup();
  state.linuxProbeOverrides = { socketInode: 9999 };
  assert.throws(() => docker.engine(), /socket metadata or hostname changed/u);
});

test("Linux CI refuses mismatching reported daemon hostname and changed socket metadata", () => {
  const mismatched = fixture({ linux: true, daemonName: "another-remote-host" });
  assert.throws(() => mismatched.docker.start({ database: "d", user: "u", password: "p" }), /engine metadata did not match/u);
  assert.ok(!mismatched.calls.some((call) => ["run", "pull"].includes(call.args[4])));
  const tampered = fixture({ linux: true });
  tampered.docker.start({ database: "d", user: "u", password: "p" });
  tampered.state.linuxProbeOverrides = { socketDevice: 900 };
  assert.throws(() => tampered.docker.cleanup(), /socket metadata or hostname changed/u);
  assert.ok(!tampered.calls.some((call) => call.args[4] === "rm"));
});

test("pins executable, npipe, local engine, owner and exact ID for real disposable fixture", () => {
  const { docker, calls } = fixture();
  docker.start({ database: "source_test", user: "test_role", password: "fixture-password" });
  assert.equal(docker.id, id);
  assert.equal(docker.state(), "healthy");
  assert.equal(docker.port(), "56432");
  assert.equal(docker.exec(["pg_dump", "-Fc"], { binary: true }).toString(), "fixture");
  docker.cleanup();
  assert.equal(docker.id, null);
  assert.ok(calls.every((call) => call.binary === DOCKER_BINARY));
  assert.ok(calls.every((call) => call.args[0] === "--host" && call.args[1] === DOCKER_HOST));
  assert.ok(calls.every((call) => call.args[2] === "--config" && call.args[3] === "C:\\private\\test-docker-config"));
  assert.ok(calls.every((call) => !Object.hasOwn(call.options.env, "DATABASE_URL") && !Object.hasOwn(call.options.env, "DOCKER_HOST")));
  const run = calls.find((call) => call.args[4] === "run").args;
  assert.ok(run.includes(POSTGRES_IMAGE));
  assert.ok(run.includes("--pull=never"));
  assert.ok(run.includes(`virki.backup-validation.owner=${nonce}`));
  assert.ok(run.includes("/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m"));
  assert.ok(run.includes("127.0.0.1::5432"));
  assert.ok(!run.includes("--volume") && !run.includes("--mount") && !run.includes("--privileged"));
  const exec = calls.find((call) => call.args[4] === "exec").args;
  assert.ok(exec.includes(id));
  assert.ok(!exec.includes(docker.name));
  const remove = calls.find((call) => call.args[4] === "rm").args;
  assert.deepEqual(remove.slice(4), ["rm", "--force", "--volumes", id]);
});

test("refuses non-Desktop Linux identities and never starts a container", () => {
  for (const os of ["Ubuntu 24.04", "Docker Engine - Community"]) {
    const { docker, calls } = fixture({ os });
    assert.throws(() => docker.start({ database: "d", user: "u", password: "p" }), /engine metadata did not match/u);
    assert.ok(!calls.some((call) => call.args[4] === "run"));
  }
});

test("refuses engine ID change before cleanup; never contacts another engine with rm", () => {
  const { docker, calls, state } = fixture();
  docker.start({ database: "d", user: "u", password: "p" });
  state.infoId = "different-engine";
  assert.throws(() => docker.cleanup(), /engine changed/u);
  assert.ok(!calls.some((call) => call.args[4] === "rm"));
});

test("missing pinned image stops before run and never pulls", () => {
  const { docker, calls } = fixture({ imageStatus: 1 });
  assert.throws(() => docker.start({ database: "d", user: "u", password: "p" }), /image failed/u);
  assert.ok(!calls.some((call) => call.args[4] === "run"));
});

test("refuses label/ID/port/mount substitutions before exec or cleanup", () => {
  for (const tamper of [
    (state) => { state.owner = "attacker"; },
    (state) => { state.containerId = alternateId; },
    (state) => { state.imageId = `sha256:${"e".repeat(64)}`; },
    (state) => { state.inspectOverrides = { Mounts: [{ Type: "bind", Source: "/var/run/docker.sock" }] }; },
    (state) => { state.inspectOverrides = { NetworkSettings: { Ports: { "5432/tcp": [{ HostIp: "0.0.0.0", HostPort: "56432" }] } } }; },
  ]) {
    const { docker, calls, state } = fixture();
    docker.start({ database: "d", user: "u", password: "p" });
    tamper(state);
    assert.throws(() => docker.exec(["psql"]), /identity|ownership\/isolation|immutable ID/u);
    assert.throws(() => docker.cleanup(), /identity|ownership\/isolation|immutable ID/u);
    assert.ok(!calls.some((call) => ["exec", "rm"].includes(call.args[4])));
  }
});

test("stopped owned container remains cleanable with immutable ID after port is released", () => {
  const { docker, calls, state } = fixture();
  docker.start({ database: "d", user: "u", password: "p" });
  state.inspectOverrides = { State: { Running: false, Health: { Status: "unhealthy" } }, NetworkSettings: { Ports: {} } };
  assert.throws(() => docker.port(), /published port/u);
  docker.cleanup();
  assert.equal(calls.filter((call) => call.args[4] === "rm").length, 1);
});

test("adopts orphan created despite lost run response only with matching owner metadata", () => {
  const owned = fixture({ returnedId: "corrupted", runStatus: 1 });
  assert.throws(() => owned.docker.start({ database: "d", user: "u", password: "p" }), /invalid container ID/u);
  assert.equal(owned.docker.id, id);
  owned.docker.cleanup();
  assert.equal(owned.calls.filter((call) => call.args[4] === "rm").length, 1);

  const foreign = fixture({ returnedId: "corrupted", runStatus: 1, owner: "foreign" });
  assert.throws(() => foreign.docker.start({ database: "d", user: "u", password: "p" }), /invalid container ID/u);
  assert.equal(foreign.docker.id, null);
  foreign.docker.cleanup();
  assert.equal(foreign.calls.filter((call) => call.args[4] === "rm").length, 0);
});

test("ambiguous detached Docker run retains owner evidence even when inspect initially cannot find it", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "backup-evidence-unit-"));
  try {
    const { docker, state } = fixture({ returnedId: "", runStatus: 1, inspectStatus: 1 });
    docker.engine();
    const evidenceDirectory = await createBackupOwnerEvidence(docker, parent);
    assert.throws(() => docker.start({ database: "d", user: "u", password: "p" }), /invalid container ID/u);
    assert.equal(docker.id, null);
    assert.equal(docker.runAttempted, true);
    const retained = await finalizeBackupOwnerEvidence(docker, evidenceDirectory);
    assert.equal(retained.retained, true);
    const recorded = await readBackupOwnerEvidence(evidenceDirectory);
    assert.equal(recorded.ownerLabel, `virki.backup-validation.owner=${nonce}`);
    assert.equal(recorded.name, docker.name);
    assert.equal(recorded.daemonId, docker.daemonId);
    assert.ok(!JSON.stringify(recorded).includes("fixture-password"));
    // The daemon may finish creating the same container after the CLI failed.
    // Manual reconciliation can locate it by the retained owner name and label.
    state.inspectStatus = 0;
    assert.equal(docker.inspect(recorded.name).Id, id);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("owner evidence is deleted only before Docker run or after a Docker query confirms removal", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "backup-evidence-unit-"));
  try {
    const untouched = fixture();
    const noRun = await createBackupOwnerEvidence(untouched.docker, parent);
    assert.deepEqual(await finalizeBackupOwnerEvidence(untouched.docker, noRun), { retained: false });

    const incomplete = fixture({ listOutput: id });
    const evidenceDir = await createBackupOwnerEvidence(incomplete.docker, parent);
    incomplete.docker.start({ database: "d", user: "u", password: "p" });
    assert.throws(() => incomplete.docker.cleanup(), /not confirmed by Docker status/u);
    assert.deepEqual(await finalizeBackupOwnerEvidence(incomplete.docker, evidenceDir), { retained: true, directory: evidenceDir });
    assert.equal((await readBackupOwnerEvidence(evidenceDir)).name, incomplete.docker.name);

    incomplete.state.listOutput = "";
    incomplete.docker.cleanup();
    assert.equal(incomplete.docker.cleaned, true);
    assert.deepEqual(await finalizeBackupOwnerEvidence(incomplete.docker, evidenceDir), { retained: false });
    await assert.rejects(() => readBackupOwnerEvidence(evidenceDir), /ENOENT/u);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("Docker failures redact stdout, stderr, connection strings and credentials", () => {
  const { docker, state } = fixture();
  docker.start({ database: "d", user: "u", password: "p" });
  state.execStatus = 1;
  assert.throws(() => docker.exec(["psql"]), (error) => !/secret=leak|password=|postgresql:\/\//u.test(error.message));
});
