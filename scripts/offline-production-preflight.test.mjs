import assert from "node:assert/strict";
import test from "node:test";
import { runProductionPreflight } from "./production-preflight.mjs";

const config = {
  sshAlias: "test-production", host: "production.example.invalid",
  port: "2222", root: "/srv/virki",
};
const GiB = 1024 ** 3;
const offlineArtifacts = {
  sourceArchiveBytes: 12 * 1024 ** 2,
  runtimeArchiveBytes: 900 * 1024 ** 2,
  migratorArchiveBytes: 1200 * 1024 ** 2,
  runtimeExpandedBytes: 1 * GiB,
  migratorExpandedBytes: 2 * GiB,
  databaseBytes: 500 * 1024 ** 2,
};

function fixture({ platform = "linux/amd64", free = "100" } = {}) {
  const commands = [];
  return {
    commands,
    execute(command, args, options = {}) {
      assert.equal(command, "ssh");
      commands.push({ args, script: options.input });
      if (args[0] === "-G") {
        return { status: 0, stdout: `user deploy\nhostname ${config.host}\nport ${config.port}\n` };
      }
      if (options.input.includes("VIRKI_PROBE_MARKER=")) {
        return { status: 0, stdout: "VIRKI_PROBE_ID=host\nVIRKI_PROBE_WD=/srv/virki\nVIRKI_PROBE_PLATFORM=linux-native\nVIRKI_PROBE_MARKER=valid\n" };
      }
      return { status: 0, stdout: `VIRKI_DOCKER_VERSION=29\nVIRKI_DOCKER_INFO=29\nVIRKI_COMPOSE_VERSION=5\nVIRKI_PLATFORM=${platform}\nVIRKI_FLOCK=available\nVIRKI_DISK_FREE_GB=${free}\nVIRKI_DEMANAGE_COUNT=4\n` };
    },
  };
}

test("hosted preflight still requires GHCR credentials in all eight probes", async () => {
  const environment = fixture();
  const result = await runProductionPreflight({
    config, sleep: async () => {}, execute: environment.execute,
  });
  assert.equal(result.status, 0);
  assert.equal(environment.commands.length, 10);
  for (const { script } of environment.commands.slice(1, 9)) {
    assert.match(script, /for name in \.env \.env\.oidc \.env\.oidc-data \.ghcr-read-token; do/u);
  }
});

test("explicit offline preflight does not require GHCR but retains the three secret files", async () => {
  const environment = fixture();
  const result = await runProductionPreflight({
    config, mode: "offline", offlineArtifacts, sleep: async () => {}, execute: environment.execute,
  });
  assert.equal(result.status, 0);
  assert.equal(result.platform, "linux/amd64");
  assert.equal(result.capacity.ok, true);
  assert.equal(result.deployAuthorized, false);
  assert.match(result.limitation, /never a release authorization/u);
  assert.equal(environment.commands.length, 10);
  for (const { args, script } of environment.commands.slice(1, 9)) {
    assert.match(args.at(-1), /^bash -s -- probe \/srv\/virki$/u);
    assert.match(script, /for name in \.env \.env\.oidc \.env\.oidc-data; do/u);
    assert.doesNotMatch(script, /\.ghcr-read-token/u);
    assert.match(script, /strict|stat -c '%a'/u);
    assert.match(script, /\*microsoft\*/u);
  }
});

test("offline preflight blocks missing measurements or inadequate free disk", async () => {
  for (const [measurements, free] of [[undefined, "100"], [offlineArtifacts, "9.5"]]) {
    const environment = fixture({ free });
    const result = await runProductionPreflight({
      config, mode: "offline", offlineArtifacts: measurements,
      sleep: async () => {}, execute: environment.execute,
    });
    assert.equal(result.status, 1);
    assert.match(result.lines.at(-1), /disk budget is unproven or insufficient/u);
  }
});

test("offline preflight refuses arm64 even when hosted mode can probe it", async () => {
  const environment = fixture({ platform: "linux/arm64" });
  const result = await runProductionPreflight({
    config, mode: "offline", offlineArtifacts,
    sleep: async () => {}, execute: environment.execute,
  });
  assert.equal(result.status, 1);
  assert.match(result.lines.at(-1), /requires native linux\/amd64/u);
});

test("an unknown preflight mode fails before any SSH command", async () => {
  const environment = fixture();
  const result = await runProductionPreflight({
    config, mode: "untrusted", sleep: async () => {}, execute: environment.execute,
  });
  assert.equal(result.status, 1);
  assert.deepEqual(environment.commands, []);
});
