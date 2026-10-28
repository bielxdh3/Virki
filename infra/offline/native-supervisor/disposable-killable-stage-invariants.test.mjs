import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./disposable-killable-stage.c", import.meta.url), "utf8");
const nativeTests = readFileSync(new URL("./disposable-killable-stage.test.mjs", import.meta.url), "utf8");

test("W12 old ASan PIE startup cannot strand a test Promise.all", () => {
  assert.match(nativeTests, /"-fno-pie", "-no-pie"/u,
    "ASan binary must not use the old PIE layout associated with 18:13Z CPU hang");
  assert.match(nativeTests, /function runOwnedChild/u);
  assert.match(nativeTests, /child\.kill\("SIGKILL"\)/u);
  assert.match(nativeTests, /pre-main CPU spinner is SIGKILLed/u);
  assert.doesNotMatch(nativeTests, /child\.once\("exit", \(code\) => resolve\(code\)\)/u);
});

test("P2-A child arms kernel timer before ALL potentially blocking start recv", () => {
  const child = source.slice(source.indexOf("static void child_work("),
    source.indexOf("static int timer(", source.indexOf("static void child_work(")));
  assert.ok(child.indexOf("arm_kernel_kill_timer()") >= 0);
  assert.ok(child.indexOf("arm_kernel_kill_timer()") < child.indexOf("recv(socket,"),
    "kernel timer MUST arm before potentially blocking start G");
  assert.match(source, /pre-g-parent-stop/u, "real SIGSTOP before G must be an adversarial test");
});

test("P2-B no parent full-file digest or pread outside killable verifier", () => {
  const parent = source.slice(source.indexOf("static bool supervision("));
  assert.doesNotMatch(parent, /verified_received_fd\(/u,
    "caller must not hash archive after stage child exited");
  const verifier = source.slice(source.indexOf("static void verifier_work("),
    source.indexOf("static int timer(", source.indexOf("static void verifier_work(")));
  assert.match(verifier, /verified_received_fd\(/u);
  assert.match(source, /verifier-blocking-read/u,
    "real verifier source pread stall must be deterministically tested");
  assert.match(source, /verifier-hash-stall/u,
    "full-file hash loop must have a deterministic blocked-kernel-read fault");
});

test("P2-C staging and verifier child lose root credentials/capabilities and journal access", () => {
  assert.match(source, /setgroups\(0, NULL\)/u);
  assert.match(source, /setresgid\(65534, 65534, 65534\)/u);
  assert.match(source, /setresuid\(65534, 65534, 65534\)/u);
  assert.match(source, /PR_SET_NO_NEW_PRIVS/u);
  assert.match(source, /child-journal-denial/u);
  assert.match(source, /SYS_close_range/u);
});

test("P2-C durable journal uses openat pinned state directory rather than pathname open/fsync", () => {
  assert.match(source, /openat\(state_fd, "attempt.lock"/u);
  assert.match(source, /fsync\(state_fd\)/u);
  assert.match(source, /same_dir_entry\(root_fd, "state"/u);
  assert.match(source, /fstatat\(parent, name, &actual/u);
  assert.doesNotMatch(source, /fsync_parent\(state\)/u);
});
