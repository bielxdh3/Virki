import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { OwnedRoleDocker, requireRoleFixtureLocalEnvironment, verifyOfficialBuildx, inspectRoleLinuxSocket,
  LINUX_CI_DOCKER, LINUX_CI_ENGINE, runProtectedLinuxRoleJournal } from "./role-fixture-docker.mjs";

const runId = "a".repeat(24);
const fixture = "virki-role-fresh-0123456789ab";
const name = fixture;
const network = `${fixture}-net`;
const cid = "e".repeat(64);
const netId = "b".repeat(64);
const postgres = "postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3";
const labels = { "virki.role-test.run": runId, "virki.role-test.fixture": fixture, "virki.role-test.kind": "postgres" };
const linuxCI = {
  VIRKI_ROLE_FIXTURE_LINUX_CI: "1", GITHUB_ACTIONS: "true", CI: "true",
  RUNNER_OS: "Linux", RUNNER_ENVIRONMENT: "github-hosted",
  GITHUB_REPOSITORY: "bielxdh3/Virki", GITHUB_RUN_ID: "123456",
  GITHUB_RUN_ATTEMPT: "1",
};

function mockGuard({ late = false, foreign = false, renamed = false, linux = false } = {}) {
  const calls = [];
  const evidence = [];
  const invoke = (cli, argv, options) => {
    assert.equal(cli, linux ? LINUX_CI_DOCKER : "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe");
    assert.deepEqual(argv.slice(0, 2), ["--host", linux ? LINUX_CI_ENGINE : "npipe:////./pipe/dockerDesktopLinuxEngine"]);
    assert.equal(options.env.PATH, linux ? "/usr/bin:/bin" : "C:\\Windows\\System32;C:\\Windows");
    assert.equal(Object.hasOwn(options.env, "DOCKER_HOST"), false);
    const args = argv.slice(2);
    calls.push(args);
    if (args[0] === "info") return { status: 0, stdout: JSON.stringify({
      OSType: "linux", OperatingSystem: linux ? "Ubuntu" : "Docker Desktop",
      Name: linux ? "ci-host" : "desktop", ID: "LOCALENGINE1234",
    }) };
    if (args[0] === "network" && args[1] === "create") return { status: 0, stdout: netId };
    if (args[0] === "network" && args[1] === "inspect" && args.includes("{{json .}}")) {
      return { status: 0, stdout: JSON.stringify({ Id: netId, Name: network,
        Driver: "bridge", Internal: true,
        Labels: { "virki.role-test.run": foreign ? "foreign" : runId, "virki.role-test.fixture": fixture } }) };
    }
    if (args[0] === "create") return late
      ? { status: 1, error: { code: "ETIMEDOUT" }, stderr: "timeout" }
      : { status: 0, stdout: cid };
    if (args[0] === "run") return { status: 0, stdout: "prisma migration output" };
    if (args[0] === "inspect" && args.includes("{{json .}}")) {
      const target = args.at(-1);
      const isRunner = target.includes("-migrate-");
      return late ? { status: 1, stderr: "No such object" }
        : { status: 0, stdout: JSON.stringify({
          Id: cid, Name: renamed ? "/foreign" : `/${isRunner ? target : name}`,
          Image: isRunner ? `sha256:${"c".repeat(64)}` : undefined,
          Config: { Image: postgres, Labels: isRunner
            ? { ...labels, "virki.role-test.kind": "migration-runner" } : labels },
          HostConfig: { Privileged: false, NetworkMode: network, Binds: [], PortBindings: {} },
          Mounts: [],
        }) };
    }
    if (args[0] === "rm" || args[0] === "start" || args[0] === "cp") return { status: 0, stdout: cid };
    if (args[0] === "exec") return { status: 1, stderr: "permission denied" };
    throw new Error(`Unexpected fake Docker call: ${args[0]}`);
  };
  const guard = new OwnedRoleDocker({
    runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: linux ? "linux" : "win32",
    env: linux ? linuxCI : {},
    linuxProbe: () => ({ dev: 1, ino: 2, hostname: "ci-host" }),
    invoke, journal: (operation, request) => evidence.push({ operation, request }),
  });
  return { guard, calls, evidence };
}

function networkCreate() {
  return ["network", "create", "--internal",
    "--label", `virki.role-test.run=${runId}`,
    "--label", `virki.role-test.fixture=${fixture}`, network];
}

function postgresCreate() {
  return ["create", "--name", name, "--network", network,
    "--network-alias", "postgres",
    "--label", `virki.role-test.run=${runId}`,
    "--label", `virki.role-test.fixture=${fixture}`,
    "--label", "virki.role-test.kind=postgres",
    "--health-cmd", "pg_isready -h 127.0.0.1 -U virki_bootstrap -d virki_roles_test",
    "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "60",
    "--env", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
    "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
    "--env", "POSTGRES_DB=virki_roles_test",
    "--env", "POSTGRES_USER=virki_bootstrap",
    "--env=POSTGRES_PASSWORD",
    "--env=VIRKI_RUNTIME_DB_PASSWORD",
    "--env=VIRKI_MIGRATOR_DB_PASSWORD",
    "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
    "--env=AUDIT_LOG_RETENTION_DAYS",
    "--env=VIRKI_E2E_DATABASE_PASSWORD",
    "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m", postgres];
}

test("RED→GREEN: refuses ambient remote daemon and Docker CLI PATH shadow without any contact", () => {
  assert.throws(() => requireRoleFixtureLocalEnvironment({ DOCKER_HOST: "tcp://remote:2375" }, "win32"), /no Docker/u);
  assert.throws(() => requireRoleFixtureLocalEnvironment({}, "linux"), /hosted Linux CI/u);
  const mock = mockGuard();
  mock.guard.call(networkCreate());
  assert.equal(mock.calls.every((args) => !args.includes("--privileged")), true);
  assert.ok(mock.evidence.find((event) => event.request.line?.includes("network_create_intent")));
});

test("RED→GREEN: every extra foreign Docker target or option is refused before ANY daemon call", () => {
  const fake = mockGuard();
  fake.guard.call(networkCreate());
  fake.guard.call(postgresCreate());
  const dataVolume = "virki-role-interrupted-0123456789ab-data";
  const wrong = [
    ["rm", "--force", "FOREIGN", cid],
    ["rm", "--force", cid, "FOREIGN"],
    ["rm", "FOREIGN", cid],
    ["start", "FOREIGN", name],
    ["stop", name, "FOREIGN"],
    ["exec", name, "sh", "-c", "cat /etc/shadow"],
    ["exec", "--env=PGPASSWORD", name, "psql", "--help", "--privileged"],
    ["cp", "E:\\safe\\roles.sh", `${name}:/test/roles.sh`, "FOREIGN"],
    ["inspect", "--format={{.Name}}", "FOREIGN", name],
    ["logs", "--tail", "40", "FOREIGN", name],
    ["network", "rm", "FOREIGN", network],
    ["network", "rm", network, "FOREIGN"],
    ["volume", "rm", dataVolume, "FOREIGN"],
    ["volume", "rm", "FOREIGN", dataVolume],
    ["image", "rm", "FOREIGN", "sha256:" + "c".repeat(64)],
    ["ps", "--all", "--quiet", "--filter", `name=^/${name}$`, "--filter", "name=FOREIGN"],
    ["volume", "ls", "--quiet", "--filter", `name=^${dataVolume}$`, "--all"],
    ["network", "inspect", "--format={{json .}}", network, "FOREIGN"],
    ["buildx", "build", "--load", "--platform", "linux/amd64", "--progress", "plain", "--file",
      "infra/Dockerfile.prod", "--target", "migrator", "--build-arg", `VIRKI_BUILD_REVISION=${"f".repeat(40)}`,
      "--label", `virki.role-test.run=${runId}`, "--tag", `virki-role-test-migrator:${runId}`, ".", "--push"],
  ];
  for (const argv of wrong) {
    const before = fake.calls.length;
    assert.throws(() => fake.guard.call(argv), /unreviewed Docker arguments/u, JSON.stringify(argv));
    assert.equal(fake.calls.length, before, "Rejected argv must not even call Docker info");
  }
});

test("RED→GREEN: hosted Linux CI is explicit, fixed and denies all ambient daemon overrides", () => {
  assert.equal(requireRoleFixtureLocalEnvironment(linuxCI, "linux"), "linux-ci");
  for (const broken of [
    { ...linuxCI, RUNNER_ENVIRONMENT: "self-hosted" },
    { ...linuxCI, GITHUB_REPOSITORY: "attacker/fork" },
    { ...linuxCI, GITHUB_RUN_ID: "0" },
    { ...linuxCI, GITHUB_ACTIONS: "false" },
    { ...linuxCI, DOCKER_CONTEXT: "remote" },
    { ...linuxCI, NODE_OPTIONS: "--require=evil" },
    { ...linuxCI, PGHOST: "external" },
  ]) assert.throws(() => requireRoleFixtureLocalEnvironment(broken, "linux"));
  const fake = mockGuard({ linux: true });
  fake.guard.call(networkCreate());
  assert.equal(fake.calls[0][0], "info");
  const workflow = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  const step = workflow.match(/ {6}- name: Test isolated PostgreSQL role separation\r?\n([\s\S]*?)(?=\r?\n {6}- name:|$)/u)?.[1];
  assert.ok(step);
  assert.match(step, /VIRKI_ROLE_FIXTURE_LINUX_CI: \$\{\{ runner\.environment == 'github-hosted' && runner\.os == 'Linux' && github\.repository == 'bielxdh3\/Virki' && '1' \|\| '0' \}\}/u);
  assert.match(step, /run: npm run test:database:roles/u);
  assert.doesNotMatch(step, /if:\s*\$\{\{/u);
});

test("Linux socket probe refuses non-root socket, unsafe executable and redirected endpoints", () => {
  const info = { isSocket: () => true, isFile: () => false, uid: 0, mode: 0o140660, dev: 1, ino: 2 };
  const binary = { isSocket: () => false, isFile: () => true, uid: 0, mode: 0o100755 };
  const good = { stat: (target) => target.endsWith(".sock") ? info : binary,
    canonicalize: (target) => target.endsWith(".sock") ? "/run/docker.sock" : LINUX_CI_DOCKER,
    hostname: () => "ci-host" };
  assert.deepEqual(inspectRoleLinuxSocket(good), { dev: 1, ino: 2, hostname: "ci-host" });
  assert.throws(() => inspectRoleLinuxSocket({ ...good, stat: (target) =>
    target.endsWith(".sock") ? { ...info, uid: 1000 } : binary }), /untrusted/u);
  assert.throws(() => inspectRoleLinuxSocket({ ...good, canonicalize: () => "/tmp/foreign.sock" }), /untrusted/u);
});

test("controlled runtime DDL denial uses exactly the reviewed psql invocation", () => {
  const fake = mockGuard();
  fake.guard.call(networkCreate());
  fake.guard.call(postgresCreate());
  const probe = ["exec", "--env=PGPASSWORD", name, "psql", "--no-psqlrc",
    "--host", "127.0.0.1", "--username", "virki_runtime", "--dbname",
    "virki_roles_test", "--set", "ON_ERROR_STOP=1", "--command",
    "CREATE TABLE public.__virki_forbidden_probe (id integer);"];
  assert.equal(fake.guard.call(probe).status, 1);
  const before = fake.calls.length;
  assert.throws(() => fake.guard.call([...probe, "FOREIGN"]), /unreviewed Docker arguments/u);
  assert.throws(() => fake.guard.call(["exec", "--interactive", ...probe.slice(1)]), /unreviewed Docker arguments/u);
  assert.equal(fake.calls.length, before);
});

test("native Linux journal uses exclusive 0600 durable writes in its private 0700 owner directory", {
  // Never mutate a developer's WSL instance; exercise native journaling only
  // on the explicitly admitted disposable hosted Linux CI runner.
  skip: process.platform !== "linux" || process.env.VIRKI_ROLE_FIXTURE_LINUX_CI !== "1",
}, () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-role-owner-"));
  const owner = "b".repeat(32);
  const name = `virki-offline-fixture-${owner}`;
  const request = { directory, name, owner, line: '{"event":"reserved"}' };
  try {
    runProtectedLinuxRoleJournal("create", request);
    assert.equal(statSync(directory).mode & 0o077, 0);
    const filename = path.join(directory, `${name}.jsonl`);
    assert.equal(statSync(filename).mode & 0o077, 0);
    assert.throws(() => runProtectedLinuxRoleJournal("create", request), /EEXIST/u);
    runProtectedLinuxRoleJournal("append", { ...request, line: '{"event":"observed"}' });
    assert.equal(readFileSync(filename, "utf8"), '{"event":"reserved"}\n{"event":"observed"}\n');
    runProtectedLinuxRoleJournal("remove", request);
    assert.equal(existsSync(directory), false);
  } finally { if (existsSync(directory)) rmSync(directory, { recursive: true, force: true }); }
});

test("native Linux journal preserves its evidence when an unexpected sibling prevents removal", {
  skip: process.platform !== "linux" || process.env.VIRKI_ROLE_FIXTURE_LINUX_CI !== "1",
}, () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-role-owner-"));
  const owner = "c".repeat(32);
  const name = `virki-offline-fixture-${owner}`;
  const request = { directory, name, owner, line: '{"event":"reserved"}' };
  const filename = path.join(directory, `${name}.jsonl`);
  const unexpected = path.join(directory, "unexpected-evidence");
  try {
    runProtectedLinuxRoleJournal("create", request);
    writeFileSync(unexpected, "must survive", { mode: 0o600 });
    assert.throws(() => runProtectedLinuxRoleJournal("remove", request), /unexpected entries/u);
    assert.equal(readFileSync(filename, "utf8"), '{"event":"reserved"}\n');
    assert.equal(readFileSync(unexpected, "utf8"), "must survive");
    assert.equal(existsSync(directory), true);
  } finally { if (existsSync(directory)) rmSync(directory, { recursive: true, force: true }); }
});

test("CI endpoint inode/host changes fail before Docker info and raw launch remains inaccessible", () => {
  const contacts = [];
  let drift = false;
  const guarded = new OwnedRoleDocker({
    runId, cwd: "/tmp/virki-fixture", platform: "linux", env: linuxCI,
    journal: () => {},
    linuxProbe: () => ({ dev: 1, ino: drift ? 3 : 2, hostname: "ci-host" }),
    invoke: (_cli, args) => {
      contacts.push(args);
      return { status: 0, stdout: JSON.stringify({
        OSType: "linux", OperatingSystem: "Ubuntu", ID: "LOCALENGINE1234", Name: "ci-host",
      }) };
    },
  });
  assert.equal(typeof guarded.raw, "undefined");
  assert.equal(typeof guarded.checked, "undefined");
  const before = contacts.length;
  drift = true;
  assert.throws(() => guarded.call(networkCreate()), /socket identity changed/u);
  assert.equal(contacts.length, before);
});

test("RED→GREEN: matching label is insufficient to remove foreign resource", () => {
  const fake = mockGuard({ foreign: true });
  assert.throws(() => fake.guard.call(networkCreate()), /start\/identity uncertain/u);
  assert.equal(fake.calls.some((args) => args[0] === "network" && args[1] === "rm"), false);
  assert.ok(fake.evidence.at(-1).request.line.includes("network_create_intent"));
});

test("RED→GREEN: uncertain Docker create preserves journal and never cleans by guessed name", () => {
  const fake = mockGuard({ late: true });
  fake.guard.call(networkCreate());
  assert.throws(() => fake.guard.call(postgresCreate()), /Reconcile owner evidence/u);
  assert.equal(fake.guard.uncertain, true);
  assert.ok(fake.evidence.some((e) => e.request.line?.includes("container_create_intent")));
  assert.equal(fake.calls.some((args) => ["rm", "start", "stop"].includes(args[0])), false);
  assert.throws(() => fake.guard.finish(true), /evidence retained/u);
  assert.equal(fake.evidence.some((e) => e.operation === "remove"), false);
});

test("refuses all resource creation when private journal cannot durably reserve the run", () => {
  const calls = [];
  assert.throws(() => new OwnedRoleDocker({
    runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: "win32", env: {},
    invoke: (_exe, argv) => {
      calls.push(argv.slice(2));
      return { status: 0, stdout: JSON.stringify({
        OSType: "linux", OperatingSystem: "Docker Desktop", ID: "LOCALENGINE1234",
      }) };
    },
    journal: () => { throw Error("disk flush denied"); },
  }), /disk flush denied/u);
  assert.deepEqual(calls.map((call) => call[0]), ["info"]);
});

test("RED→GREEN: exact inspected immutable ID is mandatory for mutation and copy", () => {
  const fake = mockGuard();
  fake.guard.call(networkCreate());
  fake.guard.call(postgresCreate());
  assert.throws(() => fake.guard.call(["rm", "--force", "d".repeat(64)]), /unrecorded or foreign/u);
  const result = fake.guard.call(["start", name]);
  assert.equal(result.stdout, name);
  const start = fake.calls.filter((args) => args[0] === "start").at(-1);
  assert.deepEqual(start, ["start", cid]);
  fake.guard.call(["cp", path.join(fake.guard.cwd, "infra", "postgres-init", "10-virki-database-roles.sh"),
    `${name}:/test/10-virki-database-roles.sh`]);
  const cp = fake.calls.filter((args) => args[0] === "cp").at(-1);
  assert.equal(cp[2], `${cid}:/test/10-virki-database-roles.sh`);
  assert.equal(fake.calls.some((args) => args[0] === "rm"), false);
});

test("RED→GREEN: container name swap refuses execution or cleanup", () => {
  const fake = mockGuard({ renamed: true });
  fake.guard.call(networkCreate());
  assert.throws(() => fake.guard.call(postgresCreate()), /start\/identity uncertain/u);
  assert.equal(fake.guard.records.size, 0);
  assert.equal(fake.calls.some((args) => args[0] === "rm"), false);
});

test("rejects privileged container options even with matching labels and ID", () => {
  const fake = mockGuard();
  fake.guard.call(networkCreate());
  assert.throws(() => fake.guard.call([...postgresCreate().slice(0, -1),
    "--privileged", postgres]), /unreviewed Docker arguments/u);
  assert.throws(() => fake.guard.call([...postgresCreate().slice(0, -1),
    "--network=host", postgres]), /unreviewed Docker arguments/u);
  assert.throws(() => fake.guard.call([...postgresCreate().slice(0, -1),
    "--mount", "type=bind,source=C:\\Windows,target=/host", postgres]), /unreviewed Docker arguments/u);
  assert.equal(fake.calls.some((args) => args[0] === "create"), false);
});

test("rejects unpinned migration build, unsafe privileges, and missing Buildx publisher", () => {
  const fake = mockGuard();
  assert.throws(() => fake.guard.call(["build", "--file", "infra/Dockerfile.prod", "."]), /unreviewed Docker arguments/u);
  assert.throws(() => fake.guard.call(["buildx", "build", "--privileged", "."]), /unreviewed Docker arguments/u);
  assert.equal(fake.calls.some((args) => ["buildx", "build"].includes(args[0])), false);
  const expected = "C:\\Program Files\\Docker\\cli-plugins\\docker-buildx.exe";
  const good = { stat: () => ({ isFile: () => true, isSymbolicLink: () => false }),
    canonicalize: () => expected,
    authenticate: () => ({ status: 0, stdout: "BUILDX_SIGNED" }) };
  assert.doesNotThrow(() => verifyOfficialBuildx(good));
  assert.throws(() => verifyOfficialBuildx({ ...good, canonicalize: () => "C:\\untrusted\\docker-buildx.exe" }), /signed Docker Desktop Buildx/u);
  assert.throws(() => verifyOfficialBuildx({ ...good, authenticate: () => ({ status: 1, stdout: "" }) }), /signed Docker Desktop Buildx/u);
});

const roleImageBuild = ["buildx", "build", "--load", "--platform", "linux/amd64",
  "--progress", "plain", "--file", "infra/Dockerfile.prod", "--target", "migrator",
  "--build-arg", `VIRKI_BUILD_REVISION=${"f".repeat(40)}`,
  "--label", `virki.role-test.run=${runId}`, "--tag", `virki-role-test-migrator:${runId}`, "."];

test("RED→GREEN: Windows Buildx executes only signed ProgramFiles binary with fresh private config and pinned default builder", () => {
  const hostile = mkdtempSync(path.join(os.tmpdir(), "virki-hostile-buildx-"));
  const userDocker = path.join(hostile, ".docker");
  const userPlugin = path.join(userDocker, "cli-plugins", "docker-buildx.exe");
  const pluginExtra = path.join(hostile, "cliPluginsExtraDirs");
  const calls = [];
  try {
    mkdirSync(path.dirname(userPlugin), { recursive: true });
    mkdirSync(pluginExtra);
    writeFileSync(userPlugin, "malicious unsigned plugin");
    writeFileSync(path.join(userDocker, "config.json"), JSON.stringify({ cliPluginsExtraDirs: [pluginExtra] }));
    const guard = new OwnedRoleDocker({
      runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: "win32",
      env: { HOME: hostile, USERPROFILE: hostile, APPDATA: hostile },
      journal: () => {},
      invoke: (exe, argv, options) => {
        calls.push({ exe, argv, env: options.env });
        if (exe === "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe" && argv[2] === "info") {
          return { status: 0, stdout: JSON.stringify({
            OSType: "linux", OperatingSystem: "Docker Desktop", ID: "LOCALENGINE1234",
          }) };
        }
        if (exe === "C:\\Program Files\\Docker\\cli-plugins\\docker-buildx.exe" && argv[2] === "inspect") {
          return { status: 0, stdout: "Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: default\nStatus: running\n" };
        }
        if (exe === "C:\\Program Files\\Docker\\cli-plugins\\docker-buildx.exe" && argv[2] === "build") {
          return { status: 0, stdout: "verified local build" };
        }
        throw Error(`Attempt to execute unreviewed command: ${exe} ${argv.join(" ")}`);
      },
    });
    assert.equal(guard.call(roleImageBuild).status, 0);
    const pluginCalls = calls.filter(({ exe }) => exe.endsWith("docker-buildx.exe"));
    assert.deepEqual(pluginCalls.map(({ argv }) => argv.slice(0, 4)), [
      ["--builder", "default", "inspect", "default"],
      ["--builder", "default", "build", "--load"],
    ]);
    assert.ok(pluginCalls.every(({ exe, env }) =>
      exe === "C:\\Program Files\\Docker\\cli-plugins\\docker-buildx.exe" &&
      env.DOCKER_HOST === "npipe:////./pipe/dockerDesktopLinuxEngine" &&
      env.DOCKER_CONFIG && env.BUILDX_CONFIG.startsWith(env.DOCKER_CONFIG) &&
      env.DOCKER_CONFIG !== userDocker && env.DOCKER_CONFIG !== hostile &&
      !Object.hasOwn(env, "DOCKER_CONTEXT") && !Object.hasOwn(env, "BUILDX_BUILDER")));
    assert.equal(calls.some(({ exe, argv }) => exe === userPlugin || argv.includes("buildx")), false);
    assert.ok(pluginCalls.every(({ env }) => !existsSync(env.DOCKER_CONFIG)));
  } finally { rmSync(hostile, { recursive: true, force: true }); }
});

test("RED→GREEN: remote/shadow Buildx builder preflight prevents image build", () => {
  for (const inspect of [
    "Name: default\nDriver: docker-container\nNodes:\nEndpoint: remote\nStatus: running\n",
    "Name: attacker\nDriver: docker\nNodes:\nEndpoint: default\nStatus: running\n",
    "Name: default\nDriver: docker\nNodes:\nEndpoint: tcp://attacker:2375\nStatus: running\n",
  ]) {
    const contacted = [];
    const guard = new OwnedRoleDocker({
      runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: "win32", env: {}, journal: () => {},
      invoke: (exe, argv) => {
        contacted.push({ exe, argv });
        if (argv[2] === "info") return { status: 0, stdout: JSON.stringify({
          OSType: "linux", OperatingSystem: "Docker Desktop", ID: "LOCALENGINE1234",
        }) };
        if (argv[2] === "inspect") return { status: 0, stdout: inspect };
        throw Error("Build must never execute after unsafe Buildx inspect");
      },
    });
    assert.throws(() => guard.call(roleImageBuild), /Buildx.*builder|builder.*Buildx/u);
    assert.equal(contacted.some(({ argv }) => argv[2] === "build"), false);
  }
});

test("RED→GREEN: config injection between Buildx preflight and build fails closed", () => {
  const contacted = [];
  const guard = new OwnedRoleDocker({
    runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: "win32", env: {}, journal: () => {},
    invoke: (exe, argv, options) => {
      contacted.push(argv);
      if (argv[2] === "info") return { status: 0, stdout: JSON.stringify({
        OSType: "linux", OperatingSystem: "Docker Desktop", ID: "LOCALENGINE1234",
      }) };
      if (argv[2] === "inspect") {
        writeFileSync(path.join(options.env.DOCKER_CONFIG, "config.json"),
          JSON.stringify({ cliPluginsExtraDirs: ["C:\\untrusted\\plugins"] }));
        return { status: 0, stdout: "Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: default\nStatus: running\n" };
      }
      throw Error("Unsafe build attempt");
    },
  });
  assert.throws(() => guard.call(roleImageBuild), /private configuration identity\/contents changed/u);
  assert.equal(contacted.some((argv) => argv[2] === "build"), false);
  assert.equal(guard.uncertain, true);
});

test("RED→GREEN: real signed Buildx default inspect tolerates device names and empty internal state", () => {
  const calls = [];
  const guard = new OwnedRoleDocker({
    runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: "win32", env: {}, journal: () => {},
    invoke: (exe, argv, options) => {
      calls.push(argv);
      if (argv[2] === "info") return { status: 0, stdout: JSON.stringify({
        OSType: "linux", OperatingSystem: "Docker Desktop", ID: "LOCALENGINE1234",
      }) };
      if (argv[2] === "inspect") {
        mkdirSync(options.env.BUILDX_CONFIG);
        for (const directory of ["activity", "defaults", "instances"]) {
          mkdirSync(path.join(options.env.BUILDX_CONFIG, directory));
        }
        writeFileSync(path.join(options.env.BUILDX_CONFIG, ".lock"), "");
        return { status: 0, stdout: [
          "Name:   default", "Driver: docker", "", "Nodes:",
          "Name:             default", "Endpoint:         default", "Status:           running",
          "BuildKit version: v0.31.2", "Platforms:        linux/amd64, linux/arm64",
          "Devices:", " Name:                  docker.com/gpu=webgpu",
          " Automatically allowed: false", "GC Policy rule#0:",
        ].join("\n") };
      }
      if (argv[2] === "build") return { status: 0, stdout: "safe local build" };
      throw Error("Unexpected Docker/Buildx operation");
    },
  });
  assert.equal(guard.call(roleImageBuild).status, 0);
  assert.equal(calls.filter((argv) => argv[2] === "build").length, 1);
});

test("RED→GREEN: even inside Buildx internal state, injected remote builder blocks image build", () => {
  const calls = [];
  const guard = new OwnedRoleDocker({
    runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: "win32", env: {}, journal: () => {},
    invoke: (exe, argv, options) => {
      calls.push(argv);
      if (argv[2] === "info") return { status: 0, stdout: JSON.stringify({
        OSType: "linux", OperatingSystem: "Docker Desktop", ID: "LOCALENGINE1234",
      }) };
      if (argv[2] === "inspect") {
        mkdirSync(options.env.BUILDX_CONFIG);
        for (const directory of ["activity", "defaults", "instances"]) {
          mkdirSync(path.join(options.env.BUILDX_CONFIG, directory));
        }
        writeFileSync(path.join(options.env.BUILDX_CONFIG, ".lock"), "");
        writeFileSync(path.join(options.env.BUILDX_CONFIG, "instances", "remote"), "malicious builder");
        return { status: 0, stdout: "Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: default\nStatus: running\n" };
      }
      throw Error("Build executed with injected remote builder state");
    },
  });
  assert.throws(() => guard.call(roleImageBuild), /private configuration identity\/contents changed/u);
  assert.equal(calls.some((argv) => argv[2] === "build"), false);
});

test("RED→GREEN: hosted Linux Buildx uses a writable isolated configuration and pinned local builder", () => {
  const commands = [];
  const guard = new OwnedRoleDocker({
    runId, cwd: "/tmp/virki-roles-safe-test", platform: "linux", env: linuxCI,
    linuxProbe: () => ({ dev: 1, ino: 2, hostname: "ci-host" }), journal: () => {},
    invoke: (exe, argv, options) => {
      commands.push({ exe, argv, env: options.env });
      assert.equal(exe, LINUX_CI_DOCKER);
      assert.deepEqual(argv.slice(0, 2), ["--host", LINUX_CI_ENGINE]);
      if (argv[2] === "info") return { status: 0, stdout: JSON.stringify({
        OSType: "linux", OperatingSystem: "Ubuntu", Name: "ci-host", ID: "LOCALENGINE1234",
      }) };
      assert.equal(argv[2], "buildx");
      assert.equal(options.env.HOME, "/nonexistent");
      assert.ok(options.env.DOCKER_CONFIG?.startsWith(os.tmpdir()));
      assert.equal(options.env.BUILDX_CONFIG, path.join(options.env.DOCKER_CONFIG, "buildx"));
      assert.equal(options.env.DOCKER_HOST, LINUX_CI_ENGINE);
      if (process.platform === "linux") assert.equal(statSync(options.env.DOCKER_CONFIG).mode & 0o077, 0);
      assert.deepEqual(argv.slice(3, 5), ["--builder", "default"]);
      if (argv[5] === "inspect") return { status: 0, stdout:
        "Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: default\nStatus: running\n" };
      if (argv[5] === "build") return { status: 0, stdout: "safe local image" };
      throw Error("Unexpected Linux Buildx invocation");
    },
  });
  assert.equal(guard.call(roleImageBuild).status, 0);
  assert.equal(commands.filter(({ argv }) => argv[5] === "build").length, 1);
  assert.ok(commands.filter(({ argv }) => argv[2] === "buildx")
    .every(({ env }) => !existsSync(env.DOCKER_CONFIG)));
});

test("RED→GREEN: hostile Linux Buildx state or remote driver blocks image creation", () => {
  for (const variant of ["saved-remote", "remote-driver"]) {
    const commands = [];
    const guard = new OwnedRoleDocker({
      runId, cwd: "/tmp/virki-roles-safe-test", platform: "linux", env: linuxCI,
      linuxProbe: () => ({ dev: 1, ino: 2, hostname: "ci-host" }), journal: () => {},
      invoke: (exe, argv, options) => {
        commands.push(argv);
        if (argv[2] === "info") return { status: 0, stdout: JSON.stringify({
          OSType: "linux", OperatingSystem: "Ubuntu", Name: "ci-host", ID: "LOCALENGINE1234",
        }) };
        if (argv[5] === "inspect") {
          if (variant === "saved-remote") {
            mkdirSync(options.env.BUILDX_CONFIG);
            for (const directory of ["activity", "defaults", "instances"]) {
              mkdirSync(path.join(options.env.BUILDX_CONFIG, directory));
            }
            writeFileSync(path.join(options.env.BUILDX_CONFIG, ".lock"), "");
            writeFileSync(path.join(options.env.BUILDX_CONFIG, "instances", "remote"), "remote builder");
          }
          return { status: 0, stdout: variant === "remote-driver"
            ? "Name: default\nDriver: docker-container\nNodes:\nName: default\nEndpoint: tcp://foreign:2375\nStatus: running\n"
            : "Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: default\nStatus: running\n" };
        }
        throw Error("Unreviewed Linux Buildx call");
      },
    });
    assert.throws(() => guard.call(roleImageBuild), /Buildx.*(?:config|builder)|builder.*Buildx/u);
    assert.equal(commands.some((argv) => argv[5] === "build"), false);
  }
});

test("pins allowed migrator command to the verified image digest rather than mutable tag", () => {
  const fake = mockGuard();
  fake.guard.call(networkCreate());
  const tag = `virki-role-test-migrator:${runId}`;
  const digest = `sha256:${"c".repeat(64)}`;
  fake.guard.image = { id: digest };
  fake.guard.imageTag = tag;
  const runName = `${fixture}-migrate-${"1".repeat(12)}`;
  const args = [
    "run", "--name", runName, "--network", network,
    "--label", `virki.role-test.run=${runId}`,
    "--label", `virki.role-test.fixture=${fixture}`,
    "--label", "virki.role-test.kind=migration-runner",
    "--env", "MIGRATION_DATABASE_URL", "--entrypoint", "node",
    tag, "/app/packages/database/scripts/prisma-migrate.mjs", "deploy",
  ];
  assert.equal(fake.guard.call(args, { env: { MIGRATION_DATABASE_URL: "opaque" } }).status, 0);
  const sent = fake.calls.find((entry) => entry[0] === "run");
  assert.ok(sent.includes(digest));
  assert.equal(sent.includes(tag), false);
  assert.equal(fake.guard.ownedContainersForFixture(fixture).length, 1);
  assert.throws(() => fake.guard.call([...args, "--privileged"]), /unreviewed Docker arguments/u);
});
