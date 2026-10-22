import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, chmodSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const eligible = process.platform === "linux" && process.arch === "x64" &&
  process.getuid?.() === 0 &&
  process.env.VIRKI_DISPOSABLE_SUPERVISOR_TEST === "1" &&
  existsSync("/.dockerenv");

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
      timeout: 4000, encoding: "utf8", maxBuffer: 4096,
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
  });
});
