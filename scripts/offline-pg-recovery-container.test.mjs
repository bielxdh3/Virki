import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

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
];
const allowed = { skip: process.env.VIRKI_OFFLINE_PG_CONTAINER_TEST !== "1" &&
  "requires explicit disposable PostgreSQL test opt-in" };
const options = { cwd: sourceRoot, timeout: 120_000, encoding: "utf8",
  env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
  windowsHide: true, maxBuffer: 65536 };
let verifiedEngine = false;

function localDocker(args) {
  return spawnSync("docker", ["--host", DOCKER_ENDPOINT, ...args], options);
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
    let result;
    try {
      result = localDocker(args);
    } finally {
      // A CLI crash or timeout must not orphan a live database. Verify the
      // independently assigned owner label BEFORE force-removing anything.
      // Never delete unknown containers, images, networks, or volumes.
      const inspection = localDocker([
        "inspect", "--format",
        `{{.Id}}|{{.Name}}|{{index .Config.Labels "${labelKey}"}}`, name,
      ]);
      if (inspection.status === 0) {
        const [id, returnedName, returnedOwner] = inspection.stdout.trim().split("|");
        assert.match(id, /^[a-f0-9]{64}$/u, "invalid immutable disposable Docker ID");
        assert.equal(returnedName, "/" + name, "disposable container name changed");
        assert.equal(returnedOwner, owner, "disposable container owner label changed");
        // Inspect-by-name is only discovery. Deletion is by immutable ID to
        // prevent removal of another container after a name-reuse race.
        const cleanup = localDocker(["rm", "--force", "--volumes", id]);
        assert.equal(cleanup.status, 0, "owned disposable database cleanup failed");
      } else {
        assert.equal(inspection.error, undefined, "Docker inspect unavailable during cleanup");
        assert.match(inspection.stderr, /no such object|no such container/iu,
          "unable to determine whether disposable database was removed");
      }
    }
    return result;
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
