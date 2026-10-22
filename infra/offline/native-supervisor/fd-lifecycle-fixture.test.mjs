import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync, mkdtempSync, readFileSync, rmSync, chmodSync, lstatSync,
  unlinkSync, rmdirSync,
} from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const localWsl = process.env.VIRKI_DISPOSABLE_SUPERVISOR_WSL_TEST === "1" &&
  /microsoft-standard-WSL2/iu.test(readFileSync("/proc/sys/kernel/osrelease", "utf8"));
const eligible = process.platform === "linux" && process.arch === "x64" &&
  process.getuid?.() === 0 &&
  process.env.VIRKI_DISPOSABLE_SUPERVISOR_TEST === "1" &&
  (existsSync("/.dockerenv") || localWsl);

test("independent native same-FD kernel lifecycle remains nonauthorizing", {
  skip: eligible ? false : "root-only disposable Linux container required",
}, async (t) => {
  const owned = mkdtempSync("/tmp/virki-supervisor-build-");
  t.after(() => rmSync(owned, { recursive: true, force: true }));
  const binary = path.join(owned, "fd-supervisor");
  execFileSync("/usr/bin/gcc", [
    "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
    "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong",
    "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
    "-o", binary, path.join(directory, "fd-lifecycle-fixture.c"),
  ], { timeout: 15000, stdio: "pipe" });
  chmodSync(binary, 0o700);
  const invoke = (scenario, env = {}) => {
    const result = spawnSync(binary, [scenario], {
      timeout: 4800, encoding: "utf8", maxBuffer: 4096,
      env: { ...process.env, ...env },
    });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.signal, null);
    assert.ok(result.status === 0 || result.status === 2, result.stderr);
    const output = JSON.parse(result.stdout.trim());
    assert.equal(output.dockerLoadAuthorized, false);
    assert.equal(output.deployAuthorized, false);
    return { result, output };
  };
  await t.test("one connected FD holds SO_PEERCRED and pidfd for BOTH protocol requests", () => {
    const result = invoke("normal");
    assert.equal(result.result.status, 0, result.result.stderr);
    assert.equal(result.output.sameFdAcrossSyntheticLoadAndInspect, true);
    assert.equal(result.output.supervisedPidfdAcrossExchange, true);
    assert.equal(result.output.isolatedNamespacesApproved, false);
    assert.equal(result.output.status, "SAME_FD_KERNEL_PEER_AND_LIFECYCLE_TEST_ONLY");
  });
  await t.test("changed response after load fails closed while retaining daemon cleanup", () => {
    const result = invoke("bad-inspect");
    assert.equal(result.result.status, 2);
    assert.equal(result.output.status, "BLOCKED");
  });
  await t.test("daemon exit between load and inspect fails closed", () => {
    const result = invoke("dead-after-load");
    assert.equal(result.result.status, 2);
    assert.equal(result.output.status, "BLOCKED");
  });
  await t.test("daemon exit before accepting synthetic payload is refused", () => {
    assert.equal(invoke("dead-before-load").result.status, 2);
  });
  await t.test("daemon response smuggling after success cannot bypass bounded parser", () => {
    assert.equal(invoke("response-smuggling").result.status, 2);
  });
  await t.test("three prequeued syntactically valid acknowledgments cannot satisfy three separate requests", () => {
    const result = invoke("pipeline-valid");
    assert.equal(result.result.status, 2);
    assert.equal(result.output.status, "BLOCKED");
  });
  await t.test("late trailing payload after final authenticated response must fail before clean EOF", () => {
    const result = invoke("late-final-junk");
    assert.equal(result.result.status, 2);
    assert.equal(result.output.status, "BLOCKED");
  });
  await t.test("slow-trickle cannot reset a per-byte poll deadline indefinitely", () => {
    const start = Date.now();
    const result = invoke("slow-trickle");
    assert.equal(result.result.status, 2);
    assert.ok(Date.now() - start < 3900, "total exchange and reap must remain bounded");
  });
  await t.test("TERM-ignoring fake child escalates to SIGKILL and is reaped within deadline", () => {
    const start = Date.now();
    const result = invoke("ignore-term");
    assert.equal(result.result.status, 2);
    assert.ok(Date.now() - start < 3900, "SIGTERM alone cannot stall cleanup");
    const match = /DISPOSABLE_FIXTURE_CHILD_REAPED ([1-9][0-9]*)/u.exec(
      result.result.stderr);
    assert.ok(match, "the parent must confirm waitpid for its exact child");
    assert.equal(existsSync("/proc/" + match[1]), false, "reaped test PID must be gone");
  });
  await t.test("interrupted first waitpid retries EINTR and confirms the exact child was reaped", () => {
    const { result, output } = invoke("normal", {
      VIRKI_DISPOSABLE_SUPERVISOR_INJECT_WAITPID_EINTR: "1",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /DISPOSABLE_FIXTURE_WAITPID_EINTR_INJECTED/u);
    assert.match(result.stderr, /DISPOSABLE_FIXTURE_CHILD_REAPED [1-9][0-9]*/u);
    assert.equal(output.status, "SAME_FD_KERNEL_PEER_AND_LIFECYCLE_TEST_ONLY");
  });
  await t.test("lost reap confirmation refuses positive claim and preserves owned socket evidence", (t) => {
    const { result, output } = invoke("normal", {
      VIRKI_DISPOSABLE_SUPERVISOR_MASK_REAP_PROOF: "1",
    });
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /fixture child reap was not confirmed/u);
    assert.doesNotMatch(result.stderr, /DISPOSABLE_FIXTURE_CHILD_REAPED/u);
    assert.equal(output.status, "BLOCKED");
    const match = /DISPOSABLE_FIXTURE_ROOT_PRESERVED (\/tmp\/virki-supervisor-[A-Za-z0-9]{8})/u.exec(
      result.stderr);
    assert.ok(match, "unconfirmed child teardown must retain the socket path");
    const owned = match[1];
    assert.match(owned, /^\/tmp\/virki-supervisor-[A-Za-z0-9]{8}$/u);
    const stat = lstatSync(owned);
    assert.ok(stat.isDirectory());
    assert.equal(stat.uid, 0);
    assert.equal(stat.mode & 0o7777, 0o700);
    const socket = path.join(owned, "engine.sock");
    assert.ok(lstatSync(socket).isSocket());
    t.after(() => {
      if (existsSync(socket)) unlinkSync(socket);
      if (existsSync(owned)) rmdirSync(owned);
    });
  });
  await t.test("child swapping private socket root after ACK cannot make teardown erase replacement", (t) => {
    const { result, output } = invoke("swap-owned-root");
    assert.equal(result.status, 2, result.stderr);
    assert.equal(output.status, "BLOCKED");
    const match = /DISPOSABLE_FIXTURE_ROOT_PRESERVED (\/tmp\/virki-supervisor-[A-Za-z0-9]{8})/u.exec(
      result.stderr);
    assert.ok(match, "swapped root cannot be treated as owned");
    const replacement = match[1];
    const original = replacement + "-original";
    assert.equal(lstatSync(replacement).isDirectory(), true);
    assert.equal(lstatSync(original).isDirectory(), true);
    const originalSocket = path.join(original, "engine.sock");
    assert.ok(lstatSync(originalSocket).isSocket());
    t.after(() => {
      if (existsSync(originalSocket)) unlinkSync(originalSocket);
      if (existsSync(original)) rmdirSync(original);
      if (existsSync(replacement)) rmdirSync(replacement);
    });
  });
  await t.test("nonresponsive daemon is terminated and reaped after socket poll deadline", () => {
    const result = invoke("stall-on-inspect");
    assert.equal(result.result.status, 2);
  });
  await t.test("daemon lies about its storage root after inspect: deny", () => {
    const result = invoke("fake-rootdir");
    assert.equal(result.result.status, 2);
    assert.equal(result.output.status, "BLOCKED");
  });
  await t.test("no production socket, arbitrary command or environment escape", () => {
    for (const scenario of ["", "../run/docker.sock", "/var/run/docker.sock", "real-docker", "--authorize"]) {
      assert.equal(invoke(scenario).result.status, 2);
    }
    assert.equal(invoke("normal", { VIRKI_DISPOSABLE_SUPERVISOR_TEST: "0" }).result.status, 2);
    const source = readFileSync(path.join(directory, "fd-lifecycle-fixture.c"), "utf8");
    assert.doesNotMatch(source, /(?:execvp|system|popen|docker\s+load|\/var\/run\/docker\.sock)\s*\(/u);
    assert.match(source, /SO_PEERCRED/u);
    assert.match(source, /pidfd_open/u);
    assert.match(source, /dockerLoadAuthorized\\":false/u);
    assert.doesNotMatch(source, /\b(?:system|popen|execvp|execve|execl|dlopen)\s*\(/u);
    assert.match(source, /independent_owner_service_pin = false/u);
    assert.match(source, /SOCK_CLOEXEC/u);
    assert.match(source, /same_provenance\(child_pid, &observed\)/u);
    assert.match(source, /getrandom\(/u);
    assert.match(source, /CLOCK_MONOTONIC/u);
    assert.match(source, /SIGKILL/u);
    assert.match(source, /MSG_PEEK/u);
    assert.match(source, /independent_owner_service_pin = false/u);
  });
});
