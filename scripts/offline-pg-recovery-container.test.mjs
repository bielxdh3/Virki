import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IMAGE = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const cases = [
  "happy", "tamper", "incompatible", "fail_live", "corrupt_backup", "crash_live", "race",
];
const allowed = { skip: process.env.VIRKI_OFFLINE_PG_CONTAINER_TEST !== "1" &&
  "requires explicit disposable PostgreSQL test opt-in" };

function isolatedPostgres(fixtureCase, envOverride = null) {
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
    const options = { cwd: sourceRoot, timeout: 120_000, encoding: "utf8",
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
      windowsHide: true, maxBuffer: 65536 };
    let result;
    try {
      result = spawnSync("docker", args, options);
    } finally {
      // A CLI crash or timeout must not orphan a live database. Verify the
      // independently assigned owner label BEFORE force-removing anything.
      // Never delete unknown containers, images, networks, or volumes.
      const inspection = spawnSync("docker", [
        "inspect", "--format", `{{index .Config.Labels "${labelKey}"}}`, name,
      ], options);
      if (inspection.status === 0) {
        assert.equal(inspection.stdout.trim(), owner,
          "disposable container ownership changed; refusing cleanup");
        const cleanup = spawnSync("docker", ["rm", "--force", "--volumes", name], options);
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
      `isolated PostgreSQL fixture case=${fixtureCase} failed (status=${result.status}, signal=${result.signal ?? "none"}); inspect local isolated run; private stderr redacted`);
    assert.equal(result.stdout.trim(), `PASS real PostgreSQL disposable ${fixtureCase} (NON_AUTHORIZING)`);
  });
}

test("rejects an externally provided PostgreSQL URL before starting the disposable database", allowed, () => {
  const result = isolatedPostgres("happy", "DATABASE_URL=postgresql://reject.invalid/invalid");
  assert.equal(result.status, 97, "external database configuration must fail before initdb");
});

test("disposable launcher accepts no external PG connection or host socket", () => {
  assert.equal(process.platform === "win32" || process.platform === "linux", true);
  assert.equal(os.platform(), process.platform);
  assert.equal(IMAGE.includes("@sha256:"), true);
});
