import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os, { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";
import {
  assertDisposablePgDockerEnvironment, buildDisposablePgDockerInvocation,
  requireSignedPgDockerCli,
} from "./lib/offline-pg-docker-transport.mjs";
import { runWithDurablePgOwnerIntent } from "./lib/offline-pg-owner-reconciliation.mjs";
import { runProtectedWindowsJournalOperation } from "../infra/offline/disposable-local-docker.mjs";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// Intentionally PIN the Windows Docker Desktop Linux-engine named pipe. A
// default Docker context/DOCKER_HOST could point at a remote/production host.
// Refuse on other hosts until separately scoped local-daemon proof exists.
const DOCKER_ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine";
const IMAGE = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const cases = [
  "happy", "tamper", "incompatible", "fail_live", "corrupt_backup", "crash_live", "race",
  "crash_admit", "crash_rollback_clone", "crash_rollback_proven", "crash_rollback_dropped",
  "crash_rollback_created", "crash_rollback_loaded", "crash_rollback_restored",
  "rollback_precheckpoint_error",
];
const allowed = { skip: process.env.VIRKI_OFFLINE_PG_CONTAINER_TEST !== "1" &&
  "requires explicit disposable PostgreSQL test opt-in" };
let verifiedEngine = false;

function localDocker(args, ownership) {
  // Never let a malicious PATH docker shim, inherited Docker context, or
  // populated user CLI config redirect a fixture at another daemon.
  assertDisposablePgDockerEnvironment();
  const binary = requireSignedPgDockerCli();
  const config = mkdtempSync(path.join(os.tmpdir(), "virki-pg-cli-config-"));
  try {
    const spec = buildDisposablePgDockerInvocation(args, config, ownership);
    assert.equal(spec.binary, binary);
    return spawnSync(spec.binary, spec.args, spec.options);
  } finally {
    rmSync(config, { recursive: true, force: true });
  }
}

function safeRollbackDiagnostic(stderr = "") {
  // Never echo raw Docker/PG stderr. Only enumerated journal phases and
  // numeric child statuses can appear in failed test output.
  const checkpoint = stderr.match(/^Unexpected protected rollback phase: (?:attempted|maintenance|backed_up|restored|restore_migrated|live_migrated|rollback_started|rollback_proven|rollback_rebuild|rollback_restored|rolled_back|completed|unknown) \(expected (?:rollback_started|rollback_proven|rollback_rebuild|rollback_restored)\)$/mu)?.[0];
  const signal = stderr.match(/^Expected injected SIGKILL, got child status (?:0|[1-9][0-9]{0,2})$/mu)?.[0];
  return checkpoint ?? signal ?? "no safe diagnostic";
}

function requireLocalDockerDesktop() {
  assert.equal(process.platform, "win32",
    "disposable runner requires the explicitly pinned local Windows Docker Desktop Linux engine");
  if (verifiedEngine) return;
  const result = localDocker(["info", "--format", "{{.OperatingSystem}}|{{.OSType}}"]);
  assert.equal(result.error, undefined, "local Docker Desktop engine is not available");
  assert.equal(result.status, 0, "pinned local Docker Desktop engine rejected connection");
  assert.equal(result.stdout.trim(), "Docker Desktop|linux",
    "Docker engine identity was not local Docker Desktop Linux");
  verifiedEngine = true;
}

function isolatedPostgres(fixtureCase, envOverride = null) {
    requireLocalDockerDesktop();
    const owner = randomBytes(16).toString("hex");
    const name = `virki-disposable-pg-${owner}`;
    const labelKey = "dev.virki.disposable.pg-owner";
    const args = [
      "run", "--rm", "--pull=never", "--platform=linux/amd64",
      "--name", name, "--label", `${labelKey}=${owner}`,
      "--network=none", "--read-only", "--user=postgres",
      "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128",
      "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=70,gid=70,mode=700",
      "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m,uid=70,gid=70,mode=700",
      "--mount", `type=bind,src=${sourceRoot},dst=/workspace,readonly`,
      "--workdir", "/workspace",
      "--env", "VIRKI_OFFLINE_PG_DISPOSABLE=1",
      ...(envOverride === null ? [] : ["--env", envOverride]),
      IMAGE, "sh", "/workspace/scripts/fixtures/offline-pg-recovery/run.sh", fixtureCase,
    ];
    // Existing Windows journal uses handle-bound ACL/inode checks and flushes
    // the intent before Docker launch. Its fixture key is deliberately NOT the
    // Docker container name; the protected record binds both exact values.
    const journalIdentity = {
      directory: path.join(homedir(), ".virki", "offline-docker-reconciliation"),
      name: `virki-offline-fixture-${owner}`, owner,
    };
    const journal = {
      create: () => runProtectedWindowsJournalOperation("create", {
        ...journalIdentity,
        line: JSON.stringify({ version: 1, fixture: "offline-postgres-recovery",
          containerName: name, owner, engine: DOCKER_ENDPOINT, image: IMAGE,
          state: "run_may_still_start", reconciliation: "manual_if_retained" }),
      }),
      append: (id) => runProtectedWindowsJournalOperation("append", {
        ...journalIdentity, line: JSON.stringify({ event: "owned_container_seen", id }),
      }),
      clear: () => runProtectedWindowsJournalOperation("remove", journalIdentity),
    };
    return runWithDurablePgOwnerIntent({
      name, owner, journal,
      expectedExitCode: envOverride === "DATABASE_URL=postgresql://reject.invalid/invalid" ? 97 : 0,
      launch: () => localDocker(args),
      inspect: (target) => localDocker(["inspect", "--format",
        `{{.Id}}|{{.Name}}|{{index .Config.Labels "${labelKey}"}}`, target],
      target === name ? undefined : { id: target, name, owner }),
      remove: (id) => localDocker(["rm", "--force", "--volumes", id], { id, name, owner }),
    });
}

for (const fixtureCase of cases) {
  test(`real PostgreSQL backup/migration/restore case: ${fixtureCase}`, allowed, () => {
    const result = isolatedPostgres(fixtureCase);
    assert.equal(result.error, undefined, `isolated container launch failed: ${result.error?.code ?? "unknown"}`);
    assert.equal(result.status, 0,
      `isolated PostgreSQL fixture case=${fixtureCase} failed (status=${result.status}, signal=${result.signal ?? "none"}; ${safeRollbackDiagnostic(result.stderr)}); private stderr redacted`);
    assert.equal(result.stdout.trim(), `PASS real PostgreSQL disposable ${fixtureCase} (NON_AUTHORIZING)`);
  });
}

test("rejects an externally provided PostgreSQL URL before starting the disposable database", allowed, () => {
  const result = isolatedPostgres("happy", "DATABASE_URL=postgresql://reject.invalid/invalid");
  assert.equal(result.status, 97, "external database configuration must fail before initdb");
});

test("disposable launcher accepts no external PG connection or host socket", () => {
  assert.equal(DOCKER_ENDPOINT, "npipe:////./pipe/dockerDesktopLinuxEngine");
  assert.equal(IMAGE.includes("@sha256:"), true);
  assert.equal(safeRollbackDiagnostic("Unexpected protected rollback phase: rollback_rebuild (expected rollback_restored)"),
    "Unexpected protected rollback phase: rollback_rebuild (expected rollback_restored)");
  assert.equal(safeRollbackDiagnostic("Expected injected SIGKILL, got child status 70"),
    "Expected injected SIGKILL, got child status 70");
  assert.equal(safeRollbackDiagnostic("postgresql://sensitive.invalid/opaque data"),
    "no safe diagnostic");
});
