import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const entry = new URL("./offline-manual-native-supervisor.mjs", import.meta.url);
test("fixed supervisor CLI refuses all input, including fabricated authority and environment", () => {
  for (const args of [[], ["activate"], ["rollback"], ["--trusted"], ["--executor", "docker"]]) {
    const child = spawnSync(process.execPath, [fileURLToPath(entry), ...args], {
      timeout: 5000, shell: false, encoding: "utf8",
      env: { PATH: process.env.PATH, VIRKI_DEPLOY_AUTHORIZED: "1",
        VIRKI_DISPOSABLE_NATIVE_SUPERVISOR: "1",
        VIRKI_DISPOSABLE_NATIVE_ACTIVATION: "1" },
    });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 2);
    assert.match(`${child.stdout}${child.stderr}`, /authorization BLOCKED/u);
    assert.doesNotMatch(`${child.stdout}${child.stderr}`, /sourceSha|privateKey|secret|password/iu);
  }
});
