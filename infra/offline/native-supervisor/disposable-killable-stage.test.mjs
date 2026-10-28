import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const ENABLED = process.platform === "linux" &&
  process.env.VIRKI_DISPOSABLE_KILLABLE_STAGE === "1" &&
  process.getuid?.() === 0 &&
  existsSync("/sys/fs/cgroup/memory.max") && existsSync("/journal");
const opts = { skip: ENABLED ? false : "requires disposable root Linux, bounded cgroup and tmpfs" };
const sha = (b) => createHash("sha256").update(b).digest("hex");
const put = (file, value) => { writeFileSync(file, value, { flag: "wx", mode: 0o600 }); chmodSync(file, 0o600); };
const EXPECTED_BLOCK = /"status":"BLOCKED_DEV_ONLY"/u;

/* The old 18:12:59Z sanitizer PIE fixture exposed a different failure
 * boundary: two ASan processes ran at 100% CPU with no journal attempt,
 * while this test's old unbounded spawn/Promise.all waited forever.
 * Watch and reap EXACT owned child PIDs, including before native main().
 * A D-state child is fundamentally unreapable until the kernel returns;
 * preserve the failed test and never claim it was collected in that case. */
function runOwnedChild(command, args, options, deadlineMs = 4000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    let finished = false, expired = false, grace;
    const finish = (callback, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(watchdog);
      if (grace) clearTimeout(grace);
      callback(value);
    };
    const watchdog = setTimeout(() => {
      expired = true;
      /* Never use pkill, process groups, a container ID, or a name wildcard. */
      child.kill("SIGKILL");
      grace = setTimeout(() => {
        child.unref();
        finish(reject, new Error("owned child failed to reap after exact-PID SIGKILL"));
      }, 750);
    }, deadlineMs);
    child.once("error", (error) => finish(reject, error));
    child.once("close", (code, signal) => {
      if (expired)
        finish(reject, new Error(`owned process deadline; exact child reaped ${signal ?? code}`));
      else finish(resolve, code);
    });
  });
}

test("C stage subprocess has kernel watchdog, durable latch and fail-closed replay", opts, async (t) => {
  const build = mkdtempSync("/tmp/virki-killable-build-");
  chmodSync(build, 0o700);
  t.after(() => rmSync(build, { recursive: true, force: true }));
  const binary = path.join(build, "stage");
  const sanitize = process.env.VIRKI_DISPOSABLE_STAGE_SANITIZE === "1";
  const ubsan = process.env.VIRKI_DISPOSABLE_STAGE_SANITIZE === "undefined";
  execFileSync("/usr/bin/gcc", [
    "-std=c11", "-Wall", "-Wextra", "-Werror", sanitize ? "-O1" : "-O2",
    ...(sanitize ? ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
      "-fno-pie", "-no-pie"] :
      ubsan ? ["-g", "-fsanitize=undefined", "-fno-sanitize-recover=all"] :
        ["-D_FORTIFY_SOURCE=2"]),
    "-fstack-protector-strong",
    "-o", binary, path.join(DIR, "disposable-killable-stage.c"), "-lcrypto",
  ], { timeout: 20000 });
  const newFixture = (t) => {
    const root = mkdtempSync("/journal/virki-killable-stage-");
    chmodSync(root, 0o700);
    mkdirSync(path.join(root, "operator"), { mode: 0o700 });
    mkdirSync(path.join(root, "state"), { mode: 0o700 });
    const bytes = Buffer.alloc(256 * 1024 + 13);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 253;
    put(path.join(root, "archive.bin"), bytes);
    put(path.join(root, "operator", "expected.sha256"), sha(bytes) + "\n");
    t.after(() => rmSync(root, { recursive: true, force: true }));
    return { root, bytes };
  };
  const run = (root, fault = "normal", env = {}) => {
    const start = performance.now();
    const r = spawnSync(binary, [root, fault], {
      env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_KILLABLE_STAGE: "1", ...env },
      encoding: "utf8", timeout: 5000,
    });
    return { ...r, ms: performance.now() - start };
  };

  await t.test("real native SHA-pinned sealed memfd staging completes but never grants authority", (x) => {
    const f = newFixture(x);
    const r = run(f.root);
    assert.equal(r.status, 0, r.stderr);
    const result = JSON.parse(r.stdout.trim());
    assert.equal(result.status, "STAGED_DEV_ONLY");
    assert.equal(result.deployAuthorized, false);
    assert.equal(result.dockerLoadAuthorized, false);
    assert.equal(result.reaped, true);
    assert.ok(existsSync(path.join(f.root, "state", "attempt.lock")));
    assert.ok(existsSync(path.join(f.root, "state", "complete.json")));
    assert.ok(r.ms < 3000, `staging took ${r.ms}ms`);
    assert.deepEqual(readFileSync(path.join(f.root, "archive.bin")), f.bytes);
    const replay = run(f.root);
    assert.equal(replay.status, 2);
    assert.match(replay.stdout, EXPECTED_BLOCK);
  });

  for (const fault of ["blocking-read", "stopped-child", "late-receipt",
    "child-killed", "verifier-blocking-read", "verifier-hash-stall"]) {
    await t.test(`native kernel watchdog refuses ${fault} and retains latch without success artifact`, (x) => {
      const f = newFixture(x);
      const r = run(f.root, fault);
      assert.equal(r.status, 2, r.stderr);
      assert.match(r.stdout, EXPECTED_BLOCK);
      assert.ok(r.ms < 3500, `watchdog timeout on ${fault}: ${r.ms}ms`);
      assert.ok(existsSync(path.join(f.root, "state", "attempt.lock")));
      assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
      assert.equal(run(f.root).status, 2);
    });
  }
  await t.test("P2-A true pre-G parent SIGSTOP leaves child independently SIGKILLed", async (x) => {
    const f = newFixture(x);
    const parent = spawn(binary, [f.root, "pre-g-parent-stop"], {
      env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_KILLABLE_STAGE: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    parent.stdout.on("data", (bytes) => { stdout += bytes; });
    const exited = new Promise((resolve, reject) => {
      parent.once("error", reject);
      parent.once("close", resolve);
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 200));
      const proc = readFileSync(`/proc/${parent.pid}/stat`, "utf8");
      assert.match(proc, /\) T /u, "parent must stop before sending G");
      const childPid = readFileSync(`/proc/${parent.pid}/task/${parent.pid}/children`, "utf8").trim();
      assert.match(childPid, /^[0-9]+$/u);
      await new Promise((resolve) => setTimeout(resolve, 1800));
      assert.match(readFileSync(`/proc/${childPid}/stat`, "utf8"), /\) Z /u,
        "SIGKILL kernel timer must kill child before any start G");
    } finally {
      try { process.kill(parent.pid, "SIGCONT"); } catch { /* exited already */ }
    }
    assert.equal(await exited, 2);
    assert.match(stdout, EXPECTED_BLOCK);
    assert.ok(existsSync(path.join(f.root, "state", "attempt.lock")));
    assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
    assert.equal(run(f.root).status, 2);
  });
  await t.test("P2-B verifier's own pre-G timer kills even with its parent SIGSTOPped", async (x) => {
    const f = newFixture(x);
    const parent = spawn(binary, [f.root, "verifier-pre-g-parent-stop"], {
      env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_KILLABLE_STAGE: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    parent.stdout.on("data", (bytes) => { stdout += bytes; });
    const exited = new Promise((resolve, reject) => {
      parent.once("error", reject);
      parent.once("close", resolve);
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 200));
      assert.match(readFileSync(`/proc/${parent.pid}/stat`, "utf8"), /\) T /u);
      const childPid = readFileSync(`/proc/${parent.pid}/task/${parent.pid}/children`,
        "utf8").trim();
      assert.match(childPid, /^[0-9]+$/u);
      await new Promise((resolve) => setTimeout(resolve, 1800));
      assert.match(readFileSync(`/proc/${childPid}/stat`, "utf8"), /\) Z /u);
    } finally {
      try { process.kill(parent.pid, "SIGCONT"); } catch { /* already exited */ }
    }
    assert.equal(await exited, 2);
    assert.match(stdout, EXPECTED_BLOCK);
    assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
    assert.equal(run(f.root).status, 2);
  });
  await t.test("P2-C unprivileged child cannot open root-owned ext4 attempt for write", (x) => {
    const f = newFixture(x);
    const r = run(f.root, "child-journal-denial");
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).deployAuthorized, false);
    assert.ok(existsSync(path.join(f.root, "state", "attempt.lock")));
    assert.ok(existsSync(path.join(f.root, "state", "complete.json")));
    assert.equal(run(f.root).status, 2);
  });
  await t.test("kernel timer kills blocked staging child while its SUPERVISOR is SIGSTOPped", async (x) => {
    const f = newFixture(x);
    const supervisor = spawn(binary, [f.root, "blocking-read"], {
      env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_KILLABLE_STAGE: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    supervisor.stdout.on("data", (chunk) => { stdout += chunk; });
    const exit = new Promise((resolve, reject) => {
      supervisor.once("error", reject);
      supervisor.once("close", (code) => resolve(code));
    });
    let stopped = false;
    try {
      await new Promise((r) => setTimeout(r, 120));
      const children = readFileSync(`/proc/${supervisor.pid}/task/${supervisor.pid}/children`, "utf8").trim();
      assert.match(children, /^[0-9]+$/u, "child process must exist before freeze");
      process.kill(supervisor.pid, "SIGSTOP");
      stopped = true;
      await new Promise((r) => setTimeout(r, 1800));
      const stat = readFileSync(`/proc/${children}/stat`, "utf8");
      assert.match(stat, /\) Z /u, "child should be zombie-killed by kernel while parent is stopped");
    } finally {
      if (stopped) process.kill(supervisor.pid, "SIGCONT");
    }
    assert.equal(await exit, 2);
    assert.match(stdout, EXPECTED_BLOCK);
    assert.ok(existsSync(path.join(f.root, "state", "attempt.lock")));
    assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
    assert.equal(run(f.root).status, 2);
  });
  await t.test("sealed FD delivered but child refuses exit: uncertain outcome never completes", (x) => {
    const f = newFixture(x);
    const r = run(f.root, "uncertain-outcome");
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stdout, EXPECTED_BLOCK);
    assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
    assert.equal(run(f.root).status, 2);
  });
  for (const fault of ["parent-die-after-latch", "parent-die-after-receipt"]) {
    await t.test(`SIGKILL ${fault} preserves ambiguous attempt and refuses replay`, (x) => {
      const f = newFixture(x);
      const r = run(f.root, fault);
      assert.notEqual(r.status, 0);
      assert.ok(existsSync(path.join(f.root, "state", "attempt.lock")));
      assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
      assert.equal(run(f.root).status, 2);
      assert.deepEqual(readFileSync(path.join(f.root, "archive.bin")), f.bytes);
    });
  }
  await t.test("corrupt SHA fails before latch and preserves original archive", (x) => {
    const f = newFixture(x);
    const plan = path.join(f.root, "operator", "expected.sha256");
    rmSync(plan);
    put(plan, "0".repeat(64) + "\n");
    const r = run(f.root);
    assert.equal(r.status, 2);
    assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
    assert.deepEqual(readFileSync(path.join(f.root, "archive.bin")), f.bytes);
  });
  await t.test("symlink and hardlink source paths cannot stage", (x) => {
    for (const fault of ["symlink", "hardlink"]) {
      const f = newFixture(x);
      const source = path.join(f.root, "archive.bin");
      if (fault === "symlink") {
        rmSync(source);
        symlinkSync(path.join(f.root, "operator", "expected.sha256"), source);
      } else {
        linkSync(source, path.join(f.root, "archive-hardlink"));
      }
      assert.equal(run(f.root).status, 2);
      assert.ok(!existsSync(path.join(f.root, "state", "complete.json")));
    }
  });
  await t.test("concurrent OS processes admit at most one attempt via exclusive latch", async (x) => {
    const f = newFixture(x);
    const runAsync = () =>
      runOwnedChild(binary, [f.root, "normal"], {
        env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_KILLABLE_STAGE: "1" },
        stdio: "ignore",
      }, 4000);
    assert.deepEqual((await Promise.all([runAsync(), runAsync()])).sort(), [0, 2]);
    assert.deepEqual(readdirSync(path.join(f.root, "state")).sort(),
      ["attempt.lock", "complete.json"]);
  });
  await t.test("pre-main CPU spinner is SIGKILLed by exact child watchdog, not leaked", async () => {
    const started = performance.now();
    await assert.rejects(runOwnedChild(process.execPath,
      ["-e", "setInterval(() => {}, 1000)"], {
        env: { PATH: "/usr/bin:/bin" }, stdio: "ignore",
      }, 150), /owned process deadline; exact child reaped/u);
    assert.ok(performance.now() - started < 2000,
      "independently bounded test harness must not wait forever");
  });
  await t.test("wrong cgroup proof or unsafe path is never treated as staging authority", (x) => {
    const f = newFixture(x);
    assert.equal(run(f.root, "normal", { VIRKI_TEST_REQUIRE_IMPOSSIBLE_CGROUP: "1" }).status, 2);
    assert.equal(run(f.root + "/../" + path.basename(f.root)).status, 2);
  });
});
