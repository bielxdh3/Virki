import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync, readlinkSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { requireOfflineReleaseCapacity } from "./lib/offline-release-capacity.mjs";
import { disposableReleaseFixture, runProductionShellRehearsal } from "./lib/offline-release-rollback-rehearsal.mjs";
import { runProductionPreflight } from "./production-preflight.mjs";

const prior = "a".repeat(40);
const candidate = "b".repeat(40);

function initialState(f) {
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${prior}`);
  assert.equal(readFileSync(path.join(f.root, ".virki-deploy-revision"), "utf8"), `${prior}\n`);
  assert.equal(readFileSync(path.join(f.root, "releases", prior, "identity.txt"), "utf8"), "original identity\n");
  assert.equal(readFileSync(path.join(f.root, "backups", "prior.dump"), "utf8"), "original backup\n");
  assert.equal(existsSync(path.join(f.root, "releases", prior)), true);
}

function assertNoExternalMutation(result) {
  assert.doesNotMatch(result.operations, /demanage|volume rm|volume prune|system prune|\bssh\b|\bcloudflare\b/iu);
  assert.ok(result.operations.split("\n").every((entry) => entry.length === 0 || /^(?:compose|docker) /u.test(entry)));
}

test("production backup/restore workflow accepts a simulated successful clone and hashes the preserved backup", (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const result = runProductionShellRehearsal(f, ["cleanup_failed_backup_verification", "create_verified_backup"],
    "create_verified_backup", { revisions: candidate });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /backup restored and all committed migrations validated/u);
  const names = result.files("backups").filter((name) => /^virki-.*\.dump$/u.test(name));
  assert.equal(names.length, 1);
  const marker = readFileSync(path.join(f.root, ".virki-migration-verification"), "utf8");
  assert.match(marker, new RegExp(`^revision=${candidate}$`, "mu"));
  assert.match(marker, /backup_sha256=[0-9a-f]{64}/u);
  assert.equal(result.files("backups").some((name) => name.endsWith(".partial")), false);
  assert.equal(result.files(".deploy-tmp").some((name) => name.endsWith(".compose.yml")), false);
  initialState(f);
  assertNoExternalMutation(result);
  assert.match(result.operations, /docker exec .*pg_restore/u);
});

test("failed clone migration removes only unverified backup and clone artifacts; predecessor persists", (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const result = runProductionShellRehearsal(f, ["cleanup_failed_backup_verification", "create_verified_backup"],
    "create_verified_backup", { revisions: candidate, failure: "clone-migration" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /simulated clone migration failure/u);
  assert.equal(result.files("backups").join(","), "prior.dump", `exit=${result.status} stderr=${result.stderr} operations=${result.operations}`);
  assert.equal(existsSync(path.join(f.root, ".virki-migration-verification")), false);
  assert.equal(result.files(".deploy-tmp").length, 0);
  assert.match(result.operations, /docker exec .*pg_restore/u);
  initialState(f);
  assertNoExternalMutation(result);
});

test("failed real production migration remains in maintenance with intact predecessor release and backup", (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const result = runProductionShellRehearsal(f,
    ["maintenance_on", "stop_routed_services", "cleanup_failed_backup_verification", "create_verified_backup", "apply_production_migrations"],
    "maintenance_on; create_verified_backup; apply_production_migrations", { failure: "production-migration", revisions: candidate });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /simulated production migration failure/u);
  assert.match(readFileSync(path.join(f.root, ".virki-maintenance"), "utf8"), new RegExp(`revision=${candidate}`));
  assert.equal(existsSync(path.join(f.root, ".virki-migration-verification")), true);
  initialState(f);
  assertNoExternalMutation(result);
  assert.doesNotMatch(result.operations, /compose up .*cloudflared/u);
});

test("failed final health retains maintenance, stops routed services and keeps previous release recoverable", (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const marker = path.join(f.root, ".virki-migration-verification");
  writeFileSync(marker, "verified disposable backup\n");
  writeFileSync(path.join(f.root, ".virki-maintenance"), `revision=${candidate}\n`);
  const result = runProductionShellRehearsal(f,
    ["resume_services", "activate_source", "stop_routed_services"],
    "resume_services", { failure: "health", revisions: candidate });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /simulated health failure/u);
  assert.equal(existsSync(path.join(f.root, ".virki-maintenance")), true);
  assert.equal(existsSync(marker), true);
  assert.equal(readFileSync(path.join(f.root, "releases", prior, "identity.txt"), "utf8"), "original identity\n");
  assert.equal(readFileSync(path.join(f.root, "backups", "prior.dump"), "utf8"), "original backup\n");
  // Characterization of the existing script: candidate current link is written
  // before the health gate, but maintenance prevents automatic service start.
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${candidate}`);
  assert.equal(readFileSync(path.join(f.root, ".virki-deploy-revision"), "utf8"), `${prior}\n`);
  assert.match(result.operations, /compose stop cloudflared/u);
  assert.doesNotMatch(result.operations, /compose up .*cloudflared/u);
  assertNoExternalMutation(result);
});

test("transient disk deficit rejects before backup or maintenance, retry only after measured capacity recovers", (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const input = {
    freeBytes: 6 * 1024 ** 3,
    sourceArchiveBytes: 1024 ** 2, runtimeArchiveBytes: 1024 ** 2,
    migratorArchiveBytes: 1024 ** 2, runtimeExpandedBytes: 1024 ** 3,
    migratorExpandedBytes: 1024 ** 3, databaseBytes: 1024 ** 3,
  };
  assert.throws(() => requireOfflineReleaseCapacity(input), /insufficient target disk/u);
  assert.equal(existsSync(path.join(f.root, ".virki-maintenance")), false);
  initialState(f);
  assert.equal(requireOfflineReleaseCapacity({ ...input, freeBytes: 24 * 1024 ** 3 }).ok, true);
  // Safe retry remains a planning decision: this rehearsal never activates a host.
  initialState(f);
});

test("existing offline preflight rejects transient disk shortage then permits only a read-only verified retry", async (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const operatorConfig = { sshAlias: "disposable-fake", host: "rehearsal.invalid", port: "2222", root: "/srv/virki" };
  const sizes = {
    sourceArchiveBytes: 1024 ** 2, runtimeArchiveBytes: 1024 ** 2,
    migratorArchiveBytes: 1024 ** 2, runtimeExpandedBytes: 1024 ** 3,
    migratorExpandedBytes: 1024 ** 3, databaseBytes: 1024 ** 3,
  };
  const simulatedCalls = [];
  const check = (diskFreeGiB) => runProductionPreflight({
    config: operatorConfig, mode: "offline", offlineArtifacts: sizes,
    sleep: async () => {},
    execute: (command, args, options = {}) => {
      // No SSH binary is ever spawned: the preflight's executor is injected.
      assert.equal(command, "ssh");
      simulatedCalls.push(args.join(" "));
      if (args[0] === "-G") return { status: 0, stdout: "user disposable\nhostname rehearsal.invalid\nport 2222\n" };
      if (options.input.includes("VIRKI_PROBE_MARKER=")) {
        return { status: 0, stdout: "VIRKI_PROBE_ID=simulated\nVIRKI_PROBE_WD=/srv/virki\nVIRKI_PROBE_PLATFORM=linux-native\nVIRKI_PROBE_MARKER=valid\n" };
      }
      return { status: 0, stdout: `VIRKI_DOCKER_VERSION=29\nVIRKI_DOCKER_INFO=29\nVIRKI_COMPOSE_VERSION=5\nVIRKI_PLATFORM=linux/amd64\nVIRKI_FLOCK=available\nVIRKI_DISK_FREE_GB=${diskFreeGiB}\nVIRKI_DEMANAGE_COUNT=2\n` };
    },
  });
  const denied = await check("6.0");
  assert.equal(denied.status, 1);
  assert.match(denied.lines.at(-1), /disk budget is unproven or insufficient/u);
  assert.equal(existsSync(path.join(f.root, ".virki-maintenance")), false);
  initialState(f);

  const allowedToPlan = await check("24.0");
  assert.equal(allowedToPlan.status, 0);
  assert.equal(allowedToPlan.deployAuthorized, false);
  assert.equal(allowedToPlan.capacity.ok, true);
  assert.equal(simulatedCalls.length, 20); // Two rounds of eight probes + one Docker check each.
  initialState(f);
});

test("interrupted partial transfer cleans only target staging and leaves unrelated transfer and predecessor untouched", (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const id = "c".repeat(24);
  const other = "d".repeat(24);
  const stage = path.join(f.root, ".deploy-tmp");
  writeFileSync(path.join(stage, `source-${candidate}-${id}.tar`), "partial archive");
  writeFileSync(path.join(stage, `images-${candidate}-${id}.manifest`), "partial manifest");
  writeFileSync(path.join(stage, `source-${candidate}-${other}.tar`), "unrelated transfer");
  const result = runProductionShellRehearsal(f, ["cleanup_deploy_staging"],
    `cleanup_deploy_staging '${candidate}' '${id}'`);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.files(".deploy-tmp"), [`source-${candidate}-${other}.tar`]);
  initialState(f);
  assertNoExternalMutation(result);
});

test("maintenance cannot be silently cleared by a failed migration status or health gate", (t) => {
  const f = disposableReleaseFixture(t, prior, candidate);
  const marker = path.join(f.root, ".virki-maintenance");
  writeFileSync(marker, "revision=" + candidate + "\n");
  writeFileSync(path.join(f.root, ".virki-migration-verification"), "verified disposable backup\n");
  const result = runProductionShellRehearsal(f,
    ["resume_services", "activate_source", "stop_routed_services"],
    "resume_services", { failure: "migration-status", revisions: candidate });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /simulated migration status failure/u);
  assert.equal(existsSync(marker), true);
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${prior}`);
  initialState(f);
  assertNoExternalMutation(result);
});
