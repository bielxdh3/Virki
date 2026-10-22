import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertLocalBackupEnvironment, DOCKER_BINARY, DOCKER_HOST, inspectLinuxRunnerSocket,
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
    if (subcommand === "inspect") return { status: 0, stdout: JSON.stringify({ ...inspect(), ...state.inspectOverrides }) };
    if (subcommand === "rm") return { status: state.removeStatus ?? 0, stdout: state.containerId };
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

test("Linux CI rejects self-hosted, spoofed and incomplete workflow admission even with opt-in", () => {
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

test("Linux CI validates root-owned canonical local Unix socket and root-owned CLI", () => {
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
    assert.throws(() => inspectLinuxRunnerSocket({ ...valid, ...probe }), /trustworthy/u);
  }
  assert.throws(() => inspectLinuxRunnerSocket({ ...valid, stat: () => { throw new Error("ENOENT"); } }), /could not be verified/u);
});

test("Linux CI pins argv, own socket and engine, pulls only cached digest before run", () => {
  const { docker, calls, state } = fixture({ linux: true });
  docker.start({ database: "d", user: "u", password: "p" });
  assert.deepEqual(calls.filter((call) => call.args[4] === "pull").map((call) => call.args.slice(4)), [["pull", POSTGRES_IMAGE]]);
  assert.ok(calls.every((call) => call.binary === LINUX_CI_DOCKER_BINARY && call.args[1] === LINUX_CI_DOCKER_HOST));
  assert.ok(calls.every((call) => Object.keys(call.options.env).sort().join() === "DOCKER_CONFIG,HOME,LANG"));
  docker.cleanup();
  state.linuxProbeOverrides = { socketInode: 9999 };
  assert.throws(() => docker.engine(), /socket or runner identity changed/u);
});

test("Linux CI refuses cross-host daemon and changed socket before run/cleanup", () => {
  const mismatched = fixture({ linux: true, daemonName: "another-remote-host" });
  assert.throws(() => mismatched.docker.start({ database: "d", user: "u", password: "p" }), /Docker Desktop Linux engine/u);
  assert.ok(!mismatched.calls.some((call) => ["run", "pull"].includes(call.args[4])));
  const tampered = fixture({ linux: true });
  tampered.docker.start({ database: "d", user: "u", password: "p" });
  tampered.state.linuxProbeOverrides = { socketDevice: 900 };
  assert.throws(() => tampered.docker.cleanup(), /socket or runner identity changed/u);
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
    assert.throws(() => docker.start({ database: "d", user: "u", password: "p" }), /Docker Desktop/u);
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

test("adopts orphan created despite lost run response only with independently verified owner", () => {
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

test("Docker failures redact stdout, stderr, connection strings and credentials", () => {
  const { docker, state } = fixture();
  docker.start({ database: "d", user: "u", password: "p" });
  state.execStatus = 1;
  assert.throws(() => docker.exec(["psql"]), (error) => !/secret=leak|password=|postgresql:\/\//u.test(error.message));
});
