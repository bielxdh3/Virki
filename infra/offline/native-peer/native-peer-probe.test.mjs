import assert from "node:assert/strict";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync, linkSync, lstatSync, mkdirSync, readFileSync,
  rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join("/tmp", "virki-peer-fixture-" + randomBytes(8).toString("hex"));
const socket = path.join(fixture, "docker.sock");
const pin = path.join(fixture, "peer.pin");
const executable = path.join(fixture, "probe");
const isDisposable = process.platform === "linux" && process.arch === "x64" &&
  process.getuid?.() === 0 && process.env.VIRKI_DISPOSABLE_PEER_PROBE === "1" &&
  readFileSync("/.dockerenv", "utf8") !== null &&
  fixture.startsWith("/tmp/virki-peer-fixture-");

function readTicks(pid) {
  const raw = readFileSync("/proc/" + pid + "/stat", "utf8");
  const fields = raw.slice(raw.lastIndexOf(")") + 2).trim().split(/\s+/u);
  return fields[19];
}
function ownerPin(pid, ticks = readTicks(pid)) {
  writeFileSync(pin, `VIRKI_DISPOSABLE_PEER_PIN_V1\npid=${pid}\nstart_ticks=${ticks}\n`, {
    mode: 0o600,
  });
  chmodSync(pin, 0o600);
}
function run(endpoint = socket, env = {}) {
  const r = spawnSync(executable, [endpoint], {
    encoding: "utf8", timeout: 3000,
    env: { ...process.env, ...env },
    maxBuffer: 4096,
  });
  assert.equal(r.signal, null, r.stderr);
  assert.equal(r.error, undefined);
  assert.ok(r.status === 0 || r.status === 2, r.stderr);
  const result = JSON.parse(r.stdout.trim());
  assert.equal(result.dockerLoadAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  return { status: r.status, result };
}
async function launch(t) {
  const child = spawn(process.execPath, [
    path.join(here, "fake-peer-server.mjs"), socket,
  ], {
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    env: { ...process.env, VIRKI_DISPOSABLE_PEER_PROBE: "1" },
  });
  t.after(async () => {
    child.kill("SIGTERM");
    await new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) return resolve();
      child.once("exit", resolve);
    });
  });
  await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error("fixture exited early: " + code)));
    child.once("message", (message) => {
      if (message?.ready && message.pid === child.pid) resolve();
      else reject(new Error("fixture readiness invalid"));
    });
  });
  return child;
}

test("native kernel AF_UNIX probe is fail-closed against proxies and changes", {
  skip: isDisposable ? false : "only explicit isolated root Linux disposable fixture may run",
}, async (t) => {
  assert.equal(os.platform(), "linux");
  mkdirSync(fixture, { mode: 0o700 });
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  execFileSync("gcc", [
    "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-fPIE", "-pie",
    "-o", executable, path.join(here, "native-peer-probe.c"),
  ], { timeout: 15000, stdio: "pipe" });
  chmodSync(executable, 0o700);
  const daemon = await launch(t);
  await t.test("SO_PEERCRED ties the exact connected FD to pinned daemon PID and pidfd", () => {
    ownerPin(daemon.pid);
    const proof = run();
    assert.equal(proof.status, 0, JSON.stringify(proof));
    assert.equal(proof.result.status, "KERNEL_PEER_MATCHES_TEST_PIN_ONLY");
    assert.equal(proof.result.peerPid, daemon.pid);
    assert.equal(proof.result.pidfdHeldDuringObservation, true);
  });
  await t.test("PID replay or stale starttime blocks", () => {
    ownerPin(daemon.pid, String(BigInt(readTicks(daemon.pid)) + 1n));
    assert.equal(run().status, 2);
    ownerPin(daemon.pid + 1, readTicks(daemon.pid));
    assert.equal(run().status, 2);
  });
  await t.test("untrusted paths cannot target host Docker daemon", () => {
    assert.equal(run("/var/run/docker.sock").status, 2);
    assert.equal(run("/run/virki-offline-import/docker.sock").status, 2);
    assert.equal(run("/tmp/../var/run/docker.sock").status, 2);
    assert.equal(run(socket, { VIRKI_DISPOSABLE_PEER_PROBE: "0" }).status, 2);
  });
  await t.test("root policy must be private regular non-linked canonical bytes", () => {
    chmodSync(pin, 0o644);
    assert.equal(run().status, 2);
    chmodSync(pin, 0o600);
    writeFileSync(pin, "VIRKI_DISPOSABLE_PEER_PIN_V1\npid=1\nstart_ticks=1\nextra=1\n");
    assert.equal(run().status, 2);
    rmSync(pin);
    symlinkSync(socket, pin);
    assert.equal(run().status, 2);
    rmSync(pin);
    const other = path.join(fixture, "other");
    ownerPin(process.pid);
    linkSync(pin, other);
    assert.equal(run().status, 2);
    rmSync(other);
  });
  await t.test("socket must be a private owner-held Unix socket", () => {
    // No live production socket, no Docker CLI and no daemon operations.
    const sock = lstatSync(socket);
    assert.equal(sock.isSocket(), true);
    chmodSync(socket, 0o666);
    assert.equal(run().status, 2);
    chmodSync(socket, 0o600);
  });
  await t.test("another root process behind the same socket cannot impersonate the pinned daemon", async (t2) => {
    const oldTicks = readTicks(daemon.pid);
    daemon.kill("SIGTERM");
    await new Promise((resolve) => daemon.once("exit", resolve));
    rmSync(socket, { force: true });
    const proxy = await launch(t2);
    assert.notEqual(proxy.pid, daemon.pid);
    ownerPin(daemon.pid, oldTicks);
    assert.equal(run().status, 2);
    ownerPin(proxy.pid);
    assert.equal(run().status, 0);
  });
});
