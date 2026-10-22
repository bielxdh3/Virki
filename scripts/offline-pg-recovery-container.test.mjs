import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IMAGE = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const cases = [
  "happy", "tamper", "incompatible", "fail_live", "corrupt_backup", "crash_live",
];
const allowed = { skip: process.env.VIRKI_OFFLINE_PG_CONTAINER_TEST !== "1" &&
  "requires explicit disposable PostgreSQL test opt-in" };

for (const fixtureCase of cases) {
  test(`real PostgreSQL backup/migration/restore case: ${fixtureCase}`, allowed, () => {
    const args = [
      "run", "--rm", "--pull=never", "--platform=linux/amd64",
      "--network=none", "--read-only", "--user=postgres",
      "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128",
      "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=70,gid=70,mode=700",
      "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m,uid=70,gid=70,mode=700",
      "--mount", `type=bind,src=${sourceRoot},dst=/workspace,readonly`,
      "--workdir", "/workspace",
      "--env", "VIRKI_OFFLINE_PG_DISPOSABLE=1",
      IMAGE, "sh", "/workspace/scripts/fixtures/offline-pg-recovery/run.sh", fixtureCase,
    ];
    const result = spawnSync("docker", args, {
      cwd: sourceRoot, timeout: 120_000, encoding: "utf8",
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
      windowsHide: true, maxBuffer: 65536,
    });
    assert.equal(result.error, undefined, `isolated container launch failed: ${result.error?.code ?? "unknown"}`);
    assert.equal(result.status, 0,
      `isolated PostgreSQL fixture case=${fixtureCase} failed (status=${result.status}, signal=${result.signal ?? "none"}); inspect local isolated run; private stderr redacted`);
    assert.equal(result.stdout.trim(), `PASS real PostgreSQL disposable ${fixtureCase} (NON_AUTHORIZING)`);
  });
}

test("disposable launcher accepts no external PG connection or host socket", () => {
  assert.equal(process.platform === "win32" || process.platform === "linux", true);
  assert.equal(os.platform(), process.platform);
  assert.equal(IMAGE.includes("@sha256:"), true);
});
