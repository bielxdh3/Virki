import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  LocalBackupDocker, assertLocalMigrationEnvironment, createBackupOwnerEvidence,
  assertSafeOwnerReceiptParent,
  finalizeBackupValidationArtifacts, readBackupOwnerEvidence, POSTGRES_IMAGE,
  DOCKER_BINARY, DOCKER_HOST, LINUX_CI_DOCKER_BINARY, LINUX_CI_DOCKER_HOST,
} from "./lib/backup-validation-docker.mjs";

const id = "a".repeat(64);
const nonce = "b".repeat(48);
const windows = { VIRKI_MIGRATION_VALIDATION_LOCAL_DOCKER: "1" };
const linux = {
  VIRKI_MIGRATION_VALIDATION_LINUX_CI: "1", GITHUB_ACTIONS: "true", CI: "true",
  RUNNER_OS: "Linux", RUNNER_ENVIRONMENT: "github-hosted", GITHUB_REPOSITORY: "bielxdh3/Virki",
  GITHUB_RUN_ID: "1234567", GITHUB_RUN_ATTEMPT: "1",
};

function fixture({ ci = false, ...initial } = {}) {
  const calls = [];
  const state = { runId: id, inspectId: id, imageId: `sha256:${"c".repeat(64)}`, ...initial };
  const name = `virki-migration-validation-${nonce}`;
  const inspect = () => ({
    Id: state.inspectId, Name: `/${name}`, Image: state.imageId,
    Config: { Image: POSTGRES_IMAGE, Labels: {
      "virki.migration-validation.owner": state.owner ?? nonce,
      "virki.migration-validation.fixture": "prisma-migration",
    } },
    HostConfig: { Privileged: false, Binds: null,
      Tmpfs: { "/var/lib/postgresql/data": "rw,noexec,nosuid,nodev,size=512m" },
      PortBindings: { "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "" }] } },
    Mounts: [], NetworkSettings: { Ports: { "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "56543" }] } },
    State: { Running: true, Health: { Status: "healthy" } },
  });
  const spawn = (binary, args, options) => {
    calls.push({ binary, args, options });
    switch (args[4]) {
      case "info": return { status: 0, stdout: JSON.stringify({ OSType: "linux", OperatingSystem: ci ? "Ubuntu 24.04" : "Docker Desktop", ID: state.daemon ?? "stable-engine", Name: "runner-01" }) };
      case "pull": return { status: 0, stdout: "" };
      case "image": return { status: state.imageStatus ?? 0, stdout: state.imageId };
      case "run": return { status: state.runStatus ?? 0, stdout: state.runId, stderr: "SECRET" };
      case "inspect": return { status: state.inspectStatus ?? 0, stdout: JSON.stringify({ ...inspect(), ...state.inspectOverride }) };
      case "exec": return { status: state.execStatus ?? 0, stdout: state.sqlOutput ?? "1", stderr: "SECRET" };
      case "rm": return { status: state.rmStatus ?? 0, stdout: id };
      case "ps": return { status: 0, stdout: state.psOutput ?? "" };
      default: throw new Error(`Unexpected command: ${args[4]}`);
    }
  };
  const docker = new LocalBackupDocker({ fixture: "prisma-migration", env: ci ? linux : windows,
    platform: ci ? "linux" : "win32", configDirectory: ci ? "/tmp/private" : "C:\\private", nonce, spawn,
    linuxProbe: () => ({ socketDevice: 7, socketInode: state.socketInode ?? 55, hostname: "runner-01" }) });
  return { docker, calls, state, name };
}

test("migration preflight rejects unsafe implicit Docker contexts and missing explicit opt-in", () => {
  assert.throws(() => assertLocalMigrationEnvironment({}, "win32"), /opt-in/u);
  assert.throws(() => assertLocalMigrationEnvironment(windows, "linux"), /opt-in/u);
  assert.throws(() => assertLocalMigrationEnvironment({ ...windows, VIRKI_BACKUP_VALIDATION_LOCAL_DOCKER: "1" }, "win32"), /mixed backup/u);
  for (const variable of ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "COMPOSE_FILE", "PGHOST", "PGPASSWORD", "DATABASE_URL", "MIGRATION_DATABASE_URL", "NODE_OPTIONS"]) {
    assert.throws(() => assertLocalMigrationEnvironment({ ...windows, [variable]: "unsafe" }, "win32"), /ambient/u, variable);
    assert.throws(() => assertLocalMigrationEnvironment({ ...linux, [variable]: "unsafe" }, "linux"), /ambient/u, variable);
  }
  for (const changed of [{ RUNNER_ENVIRONMENT: "self-hosted" }, { GITHUB_REPOSITORY: "other/repo" }, { RUNNER_OS: "Windows" }, { CI: "false" }]) {
    assert.throws(() => assertLocalMigrationEnvironment({ ...linux, ...changed }, "linux"), /opt-in/u);
  }
});

test("owner evidence refuses redirected, symlinked and non-directory temp parents", () => {
  const parent = path.resolve(os.tmpdir());
  const valid = { lstat: () => ({ isDirectory: () => true, isSymbolicLink: () => false }), realpath: () => parent };
  assert.doesNotThrow(() => assertSafeOwnerReceiptParent(parent, valid));
  assert.throws(() => assertSafeOwnerReceiptParent(parent, { ...valid, lstat: () => ({ isDirectory: () => true, isSymbolicLink: () => true }) }), /symlinked/u);
  assert.throws(() => assertSafeOwnerReceiptParent(parent, { ...valid, lstat: () => ({ isDirectory: () => false, isSymbolicLink: () => false }) }), /non-directory/u);
  assert.throws(() => assertSafeOwnerReceiptParent(parent, { ...valid, realpath: () => `${parent}-redirected` }), /redirected/u);
  assert.throws(() => assertSafeOwnerReceiptParent("relative/path", valid), /absolute/u);
});

test("migration runner contains no ambient Docker CLI, PID-name cleanup, or fixed database password", () => {
  const source = readFileSync(new URL("./migration-validation.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /spawnSync\(\s*["']docker["']/u);
  assert.doesNotMatch(source, /containerName\s*=.*process\.pid/u);
  assert.doesNotMatch(source, /migration-validation-only/u);
  assert.doesNotMatch(source, /["']docker["'],\s*\[\s*["']rm["']/u);
  assert.match(source, /createBackupOwnerEvidence\(docker\)/u);
  assert.match(source, /finalizeBackupValidationArtifacts/u);
  assert.match(source, /fixture: "prisma-migration"/u);
});

test("migration uses pinned executable, named pipe, digest, random owner and immutable ID", () => {
  const { docker, calls, name } = fixture();
  docker.start({ database: "d", user: "u", password: "never-log-me" });
  assert.equal(docker.name, name);
  assert.equal(docker.id, id);
  assert.equal(docker.port(), "56543");
  assert.equal(docker.state(), "healthy");
  assert.equal(docker.execResult(["psql"], { input: "SELECT 1;" }).stdout, "1");
  docker.cleanup();
  assert.equal(docker.cleaned, true);
  assert.ok(calls.every(({ binary, args }) => binary === DOCKER_BINARY && args[0] === "--host" && args[1] === DOCKER_HOST));
  assert.ok(calls.every(({ options }) => !Object.hasOwn(options.env, "DOCKER_HOST") && !Object.hasOwn(options.env, "DATABASE_URL")));
  const run = calls.find(({ args }) => args[4] === "run").args;
  for (const expected of ["--pull=never", POSTGRES_IMAGE, "127.0.0.1::5432", `virki.migration-validation.owner=${nonce}`, "virki.migration-validation.fixture=prisma-migration"]) {
    assert.ok(run.includes(expected), expected);
  }
  assert.ok(!run.includes("--volume") && !run.includes("--mount") && !run.includes("--privileged"));
  assert.deepEqual(calls.find(({ args }) => args[4] === "rm").args.slice(4), ["rm", "--force", "--volumes", id]);
  assert.ok(calls.find(({ args }) => args[4] === "exec").args.includes(id));
});

test("migration refuses poisoned owner, mutable CID, image or port before running SQL or cleanup", () => {
  for (const tamper of [
    (s) => { s.owner = "foreign"; },
    (s) => { s.inspectId = "e".repeat(64); },
    (s) => { s.imageId = `sha256:${"f".repeat(64)}`; },
    (s) => { s.inspectOverride = { NetworkSettings: { Ports: { "5432/tcp": [{ HostIp: "0.0.0.0", HostPort: "56543" }] } } }; },
    (s) => { s.inspectOverride = { Mounts: [{ Type: "bind", Source: "/var/run/docker.sock" }] }; },
  ]) {
    const { docker, calls, state } = fixture();
    docker.start({ database: "d", user: "u", password: "p" });
    tamper(state);
    assert.throws(() => docker.execResult(["psql"]), /ownership|immutable ID/u);
    assert.throws(() => docker.cleanup(), /ownership|immutable ID/u);
    assert.ok(!calls.some(({ args }) => ["exec", "rm"].includes(args[4])));
  }
});

test("ambiguous run + delayed container retains isolated owner evidence while scratch directory is deleted", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "virki-migration-mock-"));
  try {
    const { docker, calls, state } = fixture({ runId: "bad", runStatus: 1, inspectStatus: 1 });
    docker.engine();
    const scratch = path.join(parent, "scratch");
    await mkdir(scratch);
    const evidence = await createBackupOwnerEvidence(docker, parent);
    const owner = await readBackupOwnerEvidence(evidence);
    assert.equal(owner.fixture, "prisma-migration");
    assert.equal(owner.ownerLabel, `virki.migration-validation.owner=${nonce}`);
    assert.throws(() => docker.start({ database: "d", user: "u", password: "p" }), /invalid container ID/u);
    assert.equal(docker.id, null);
    const errors = await finalizeBackupValidationArtifacts({ docker, temporaryDirectory: scratch, ownerEvidenceDirectory: evidence });
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /preserved for manual reconciliation/u);
    await assert.rejects(stat(scratch), /ENOENT/u);
    assert.equal((await readBackupOwnerEvidence(evidence)).name, owner.name);
    assert.ok(!calls.some(({ args }) => args[4] === "rm"));
    state.inspectStatus = 0;
    assert.equal(docker.inspect(docker.name).Id, id);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("uncertain rm preserves receipt; confirmed owned-ID removal clears it", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "virki-migration-mock-"));
  try {
    const { docker, state } = fixture();
    docker.engine();
    const evidence = await createBackupOwnerEvidence(docker, parent);
    docker.start({ database: "d", user: "u", password: "p" });
    state.psOutput = id;
    const fail = await finalizeBackupValidationArtifacts({ docker, ownerEvidenceDirectory: evidence });
    assert.equal(fail.length, 2);
    assert.equal((await readBackupOwnerEvidence(evidence)).name, docker.name);
    state.psOutput = "";
    assert.deepEqual(await finalizeBackupValidationArtifacts({ docker, ownerEvidenceDirectory: evidence }), []);
    await assert.rejects(readBackupOwnerEvidence(evidence), /ENOENT/u);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("CI migration workflow has hosted-only opt-in but never uses uncontrolled Docker context", () => {
  const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const step = workflow.match(/ {6}- name: Validate clean migration baseline or transition plan\r?\n([\s\S]*?)(?=\r?\n {6}- name:|$)/u)?.[1];
  assert.ok(step);
  assert.match(step, /VIRKI_MIGRATION_VALIDATION_LINUX_CI: \$\{\{ runner\.environment == 'github-hosted' && runner\.os == 'Linux' && github\.repository == 'bielxdh3\/Virki' && '1' \|\| '0' \}\}/u);
  assert.match(step, /run: npm run test:migration/u);
  const { docker, calls } = fixture({ ci: true });
  docker.start({ database: "d", user: "u", password: "p" });
  docker.cleanup();
  assert.ok(calls.every(({ binary, args }) => binary === LINUX_CI_DOCKER_BINARY && args[1] === LINUX_CI_DOCKER_HOST));
  assert.deepEqual(calls.filter(({ args }) => args[4] === "pull").map(({ args }) => args[5]), [POSTGRES_IMAGE]);
});

test("migration errors do not echo PostgreSQL password or Docker stderr, and never clean a foreign engine", () => {
  const invalid = fixture({ runStatus: 1, runId: "invalid", inspectStatus: 1 });
  assert.throws(() => invalid.docker.start({ database: "d", user: "u", password: "password-is-private" }), (error) =>
    /invalid container ID/u.test(error.message) && !/password-is-private|SECRET/u.test(error.message));
  assert.ok(!invalid.calls.some(({ args }) => args[4] === "rm"));

  const { docker, state, calls } = fixture();
  docker.start({ database: "d", user: "u", password: "p" });
  state.daemon = "a-different-daemon";
  assert.throws(() => docker.cleanup(), /engine changed/u);
  assert.ok(!calls.some(({ args }) => args[4] === "rm"));
});
