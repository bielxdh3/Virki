import assert from "node:assert/strict";
import test from "node:test";
import { OwnedRoleDocker, requireRoleFixtureLocalEnvironment, verifyOfficialBuildx } from "./role-fixture-docker.mjs";

const runId = "a".repeat(24);
const fixture = "virki-role-fresh-0123456789ab";
const name = fixture;
const network = `${fixture}-net`;
const cid = "e".repeat(64);
const netId = "b".repeat(64);
const postgres = "postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3";
const labels = { "virki.role-test.run": runId, "virki.role-test.fixture": fixture, "virki.role-test.kind": "postgres" };

function mockGuard({ late = false, foreign = false, renamed = false } = {}) {
  const calls = [];
  const evidence = [];
  const invoke = (cli, argv, options) => {
    assert.equal(cli, "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe");
    assert.deepEqual(argv.slice(0, 2), ["--host", "npipe:////./pipe/dockerDesktopLinuxEngine"]);
    assert.equal(options.env.PATH, "C:\\Windows\\System32;C:\\Windows");
    assert.equal(Object.hasOwn(options.env, "DOCKER_HOST"), false);
    const args = argv.slice(2);
    calls.push(args);
    if (args[0] === "info") return { status: 0, stdout: JSON.stringify({ OSType: "linux", OperatingSystem: "Docker Desktop", ID: "LOCALENGINE1234" }) };
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
    throw new Error(`Unexpected fake Docker call: ${args[0]}`);
  };
  const guard = new OwnedRoleDocker({
    runId, cwd: "E:\\Virki\\.worktrees\\safe-test", platform: "win32", env: {},
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
  assert.throws(() => requireRoleFixtureLocalEnvironment({}, "linux"), /local Windows/u);
  const mock = mockGuard();
  mock.guard.call(networkCreate());
  assert.equal(mock.calls.every((args) => !args.includes("--privileged")), true);
  assert.ok(mock.evidence.find((event) => event.request.line?.includes("network_create_intent")));
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
  fake.guard.call(["cp", "E:\\safe\\roles.sh", `${name}:/test/roles.sh`]);
  const cp = fake.calls.filter((args) => args[0] === "cp").at(-1);
  assert.equal(cp[2], `${cid}:/test/roles.sh`);
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
    "--privileged", postgres]), /unapproved container creation/u);
  assert.throws(() => fake.guard.call([...postgresCreate().slice(0, -1),
    "--network=host", postgres]), /unapproved container creation/u);
  assert.throws(() => fake.guard.call([...postgresCreate().slice(0, -1),
    "--mount", "type=bind,source=C:\\Windows,target=/host", postgres]), /unreviewed PostgreSQL creation profile/u);
  assert.equal(fake.calls.some((args) => args[0] === "create"), false);
});

test("rejects unpinned migration build, unsafe privileges, and missing Buildx publisher", () => {
  const fake = mockGuard();
  assert.throws(() => fake.guard.call(["build", "--file", "infra/Dockerfile.prod", "."]), /unreviewed Docker operation/u);
  assert.throws(() => fake.guard.call(["buildx", "build", "--privileged", "."]), /unexpected migration image build/u);
  assert.equal(fake.calls.some((args) => ["buildx", "build"].includes(args[0])), false);
  const expected = "C:\\Program Files\\Docker\\cli-plugins\\docker-buildx.exe";
  const good = { stat: () => ({ isFile: () => true, isSymbolicLink: () => false }),
    canonicalize: () => expected,
    authenticate: () => ({ status: 0, stdout: "BUILDX_SIGNED" }) };
  assert.doesNotThrow(() => verifyOfficialBuildx(good));
  assert.throws(() => verifyOfficialBuildx({ ...good, canonicalize: () => "C:\\untrusted\\docker-buildx.exe" }), /signed Docker Desktop Buildx/u);
  assert.throws(() => verifyOfficialBuildx({ ...good, authenticate: () => ({ status: 1, stdout: "" }) }), /signed Docker Desktop Buildx/u);
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
  assert.throws(() => fake.guard.call([...args, "--privileged"]), /unapproved container creation/u);
});
