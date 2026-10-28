// DEV-only cross-container crash/replay proof with one dedicated Docker
// disposable ext4 volume. Never mounts Docker's socket or a host directory
// writable by the container. The invoking test must remove its named volume.
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

assert.equal(process.env.VIRKI_DISPOSABLE_KILLABLE_STAGE, "1");
assert.equal(process.platform, "linux");
assert.equal(process.getuid(), 0);
const phase = process.argv[2];
assert.ok(phase === "seed-crash" || phase === "replay");
const target = "/journal/virki-killable-stage-REBOOT";
const binary = "/tmp/virki-killable-restart-probe";
const here = path.dirname(fileURLToPath(import.meta.url));
execFileSync("/usr/bin/gcc", [
  "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
  "-o", binary, path.join(here, "disposable-killable-stage.c"), "-lcrypto",
], { timeout: 20000 });
if (phase === "seed-crash") {
  mkdirSync(target, { mode: 0o700 });
  chmodSync(target, 0o700);
  for (const dirname of ["operator", "state"])
    mkdirSync(path.join(target, dirname), { mode: 0o700 });
  const bytes = Buffer.alloc(32 * 1024 + 7, 0x61);
  writeFileSync(path.join(target, "archive.bin"), bytes, { mode: 0o600, flag: "wx" });
  writeFileSync(path.join(target, "operator/expected.sha256"),
    createHash("sha256").update(bytes).digest("hex") + "\n",
    { mode: 0o600, flag: "wx" });
  const first = spawnSync(binary, [target, "parent-die-after-latch"], {
    encoding: "utf8", timeout: 3000,
    env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_KILLABLE_STAGE: "1" },
  });
  assert.notEqual(first.status, 0);
  assert.ok(existsSync(path.join(target, "state/attempt.lock")));
  assert.ok(!existsSync(path.join(target, "state/complete.json")));
  // Abruptly kill the container's PID 1 after the attempt reached ext4,
  // exercising survival of its durable latch across a fresh container.
  process.kill(process.pid, "SIGKILL");
  throw new Error("unreachable after SIGKILL");
}
const attempt = JSON.parse(readFileSync(path.join(target, "state/attempt.lock"), "utf8"));
assert.equal(attempt.status, "attempted");
assert.ok(/^[0-9a-f]{32}$/u.test(attempt.nonce));
const replay = spawnSync(binary, [target, "normal"], {
  encoding: "utf8", timeout: 3000,
  env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_KILLABLE_STAGE: "1" },
});
assert.equal(replay.status, 2);
assert.equal(JSON.parse(replay.stdout).deployAuthorized, false);
assert.ok(!existsSync(path.join(target, "state/complete.json")));
process.stdout.write("PERSISTENT_EXT4_LATCH_REPLAY_BLOCKED_DEV_ONLY\n");
