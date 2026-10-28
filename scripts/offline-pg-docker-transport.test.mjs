import assert from "node:assert/strict";
import test from "node:test";
import {
  assertDisposablePgDockerEnvironment, buildDisposablePgDockerInvocation,
} from "./lib/offline-pg-docker-transport.mjs";

const cli = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const socket = "npipe:////./pipe/dockerDesktopLinuxEngine";
const config = "C:\\Temp\\virki-private-docker-config";

test("PATH-spoofed docker executable cannot replace independently pinned signed Docker Desktop CLI", () => {
  const poisoned = {
    PATH: "C:\\attacker\\fake-docker;C:\\Windows\\System32",
    DOCKER_HOST: "tcp://production.invalid:2375",
    DOCKER_CONTEXT: "production",
    DOCKER_TLS_VERIFY: "1",
    SystemRoot: "C:\\Windows",
    WINDIR: "C:\\Windows",
  };
  assert.throws(() => assertDisposablePgDockerEnvironment(poisoned), /refus/iu);
  const invocation = buildDisposablePgDockerInvocation(["info", "--format", "{{.OperatingSystem}}|{{.OSType}}"], config);
  assert.equal(invocation.binary, cli);
  const fixedFormat = "{{.OperatingSystem}}|{{.OSType}}";
  assert.deepEqual(invocation.args, ["--host", socket, "--config", config,
    "info", "--format", fixedFormat]);
  assert.equal(invocation.options.shell, false);
  assert.equal(invocation.options.env.PATH, "C:\\Windows\\System32;C:\\Windows");
  for (const key of ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY"])
    assert.equal(Object.hasOwn(invocation.options.env, key), false, key);
});

test("foreign hosts, arbitrary subcommands and caller contexts cannot be injected", () => {
  const unknownId = "f".repeat(64);
  const owner = "a".repeat(32);
  const ownedName = `virki-disposable-pg-${owner}`;
  const format = '{{.Id}}|{{.Name}}|{{index .Config.Labels "dev.virki.disposable.pg-owner"}}';
  for (const args of [
    ["--host", "tcp://production.invalid", "info"],
    ["--context", "prod", "info"],
    ["--config", "C:\\attacker", "info"],
    ["pull", "postgres:latest"],
    ["rm", "demanage-production"],
    ["rm", "--force", "--volumes", unknownId],
    ["inspect", "--format", format, unknownId],
  ]) assert.throws(() => buildDisposablePgDockerInvocation(args, config), /refus/iu);
  assert.deepEqual(buildDisposablePgDockerInvocation(["rm", "--force", "--volumes", unknownId], config,
    { id: unknownId, name: ownedName, owner }).args.slice(-4), ["rm", "--force", "--volumes", unknownId]);
  assert.throws(() => buildDisposablePgDockerInvocation(["info"], "C:\\Temp\\../foreign"), /refus/iu);
});

test("fixture refuses ambient PostgreSQL credentials and unsafe node execution overrides", () => {
  for (const key of ["DATABASE_URL", "MIGRATION_DATABASE_URL", "PGHOST", "PGPASSWORD", "NODE_OPTIONS", "COMPOSE_FILE"])
    assert.throws(() => assertDisposablePgDockerEnvironment({ [key]: "injected" }), /refus/iu);
});
