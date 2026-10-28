import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, chmodSync, readFileSync, readlinkSync, rmSync, symlinkSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const enabled = process.platform === "linux" && process.arch === "x64" &&
  process.env.VIRKI_DISPOSABLE_DOCKER_RO_BRIDGE_TEST === "1";

function startTicks(pid) {
  const raw = readFileSync(`/proc/${pid}/stat`, "utf8");
  return raw.slice(raw.lastIndexOf(")") + 2).trim().split(/\s+/u)[19];
}

function listenerInode(server) {
  const fd = server._handle?.fd;
  assert.ok(Number.isInteger(fd) && fd >= 0);
  const match = /^socket:\[([1-9][0-9]*)\]$/u.exec(readlinkSync(`/proc/self/fd/${fd}`));
  assert.ok(match);
  return match[1];
}

function externalListenerInode(pid, socket) {
  const lines = readFileSync(`/proc/${pid}/net/unix`, "utf8").split("\n");
  const matching = lines.filter((line) => line.trim().endsWith(" " + socket));
  assert.equal(matching.length, 1, "fixture listener must be unique");
  return matching[0].trim().split(/\s+/u)[6];
}

test("disposable inherited-FD Docker diagnostics are bounded and never authorized", {
  skip: enabled ? false : "explicit Linux development fixture only",
}, async (t) => {
  const directory = mkdtempSync("/tmp/virki-readonly-fd-");
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const socketFile = path.join(directory, "daemon.sock");
  const binary = path.join(directory, "bridge");
  execFileSync("gcc", [
    "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-fanalyzer",
    "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", "-fPIE", "-pie",
    "-DVDT_DISPOSABLE_READONLY=1", "-o", binary,
    path.join(here, "native-docker-readonly-bridge.c"),
    path.join(here, "native-docker-fd-transport.c"), "-lcrypto",
  ], { timeout: 30000 });

  async function exchange(mode, options = {}) {
    let seen = [];
    let accepted = null;
    const server = net.createServer((socket) => {
      accepted = socket;
      let received = "";
      socket.on("data", (chunk) => {
        received += chunk.toString("latin1");
        for (;;) {
          const end = received.indexOf("\r\n\r\n");
          if (end === -1) break;
          const request = received.slice(0, end + 4);
          received = received.slice(end + 4);
          seen.push(request);
          if (mode === "stall") continue;
          if (mode === "partial") {
            socket.write("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\n{");
            continue;
          }
          if (mode === "duplicate") {
            socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK");
            continue;
          }
          if (mode === "smuggle") {
            socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\nOK");
            continue;
          }
          const body = seen.length === 1 ? "OK" : '{"fixture":true}';
          if (mode === "listener-closed" && seen.length === 1) {
            // The connected peer survives but its independently pinned
            // listening socket is gone before the next exchange.
            server.close();
          }
          socket.write(`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: keep-alive\r\n\r\n${body}`);
        }
      });
    });
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(socketFile, resolve);
      });
      chmodSync(socketFile, 0o600);
      const expectedInode = listenerInode(server);
      const client = net.createConnection(socketFile);
      await new Promise((resolve, reject) => {
        client.once("connect", resolve);
        client.once("error", reject);
      });
      // The test harness retains the original client descriptor only to pass
      // it to the child; libuv must never compete with the child's recvmsg.
      client.pause();
      client._handle.readStop();
      const fd = client._handle.fd;
      if (options.symlinkSocket) {
        rmSync(socketFile);
        symlinkSync(path.join(directory, "absent-disposable-socket"), socketFile);
      }
      const args = [
        String(options.pid ?? process.pid),
        String(options.ticks ?? startTicks(process.pid)),
        String(options.inode ?? expectedInode), options.pinPath ?? socketFile,
      ];
      const child = spawn(binary, args, {
        stdio: ["ignore", "pipe", "pipe", fd],
        env: { ...process.env, VIRKI_DISPOSABLE_DOCKER_RO_BRIDGE_TEST:
          options.env ?? "1" },
      });
      const outcome = await new Promise((resolve, reject) => {
        let stdout = "", stderr = "";
        const timeout = setTimeout(() => child.kill("SIGKILL"), 6000);
        child.stdout.on("data", (v) => { stdout += v; });
        child.stderr.on("data", (v) => { stderr += v; });
        child.once("error", reject);
        child.once("close", (code, signal) => {
          clearTimeout(timeout);
          resolve({ code, signal, stdout, stderr });
        });
      });
      assert.equal(outcome.signal, null, outcome.stderr);
      const result = JSON.parse(outcome.stdout.trim());
      assert.equal(result.dockerLoadAuthorized, false);
      assert.equal(result.deployAuthorized, false);
      assert.equal(result.status, "NOT_AUTHORIZED");
      return { ...outcome, result, seen };
    } finally {
      accepted?.destroy();
      await new Promise((resolve) => server.close(resolve));
      rmSync(socketFile, { force: true });
    }
  }

  await t.test("same connection accepts precisely GET ping and GET info, no POST", async () => {
    const r = await exchange("normal");
    assert.equal(r.code, 0, JSON.stringify(r));
    assert.equal(r.result.diagnosticOk, true);
    assert.equal(r.result.independentDaemonPolicyVerified, false);
    assert.equal(r.result.isolatedLifecycleVerified, false);
    assert.equal(r.seen.length, 2);
    assert.match(r.seen[0], /^GET \/_ping HTTP\/1\.1\r\n/u);
    assert.match(r.seen[1], /^GET \/v1\.45\/info HTTP\/1\.1\r\n/u);
    assert.ok(r.seen.every((request) => !request.includes("POST ")));
  });
  for (const [label, options] of [
    ["wrong daemon PID", { pid: 1 }],
    ["stale process start ticks", { ticks: String(BigInt(startTicks(process.pid)) + 1n) }],
    ["wrong listener inode", { inode: "9" }],
    ["missing opt-in", { env: "0" }],
    ["socket pathname replaced by symlink", { symlinkSocket: true }],
    ["production Docker socket pathname is refused even with fixture FD",
      { pinPath: "/var/run/docker.sock" }],
  ]) {
    await t.test(label + " rejects before any HTTP", async () => {
      const r = await exchange("normal", options);
      assert.equal(r.code, 2, r.stderr);
      assert.equal(r.result.diagnosticOk, false);
      assert.equal(r.seen.length, 0);
    });
  }
  for (const mode of ["stall", "partial", "duplicate", "smuggle"]) {
    await t.test(mode + " fails closed with empty receipt", async () => {
      const r = await exchange(mode);
      assert.equal(r.code, 2, r.stderr);
      assert.equal(r.result.diagnosticOk, false);
      assert.ok(r.seen.length <= 1);
    });
  }
  await t.test("listener disappears after PING: INFO is never sent", async () => {
    const r = await exchange("listener-closed");
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 1, JSON.stringify(r.seen));
  });
  await t.test("SCM_RIGHTS reply injection fails closed", async () => {
    const python = [
      "import socket,sys,os,array,time",
      "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)",
      "s.bind(sys.argv[1])",
      "os.chmod(sys.argv[1],0o600)",
      "s.listen(1)",
      "print('READY',flush=True)",
      "c,_=s.accept()",
      "data=c.recv(4096)",
      "assert data.startswith(b'GET /_ping HTTP/1.1')",
      "payload=b'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\nOK'",
      "c.sendmsg([payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[s.fileno()]))])",
      "print('SENT_RIGHTS',flush=True)",
      "time.sleep(4)",
    ].join("\n");
    const daemon = spawn("python3", ["-u", "-c", python, socketFile], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      const ready = await new Promise((resolve, reject) => {
        daemon.stdout.once("data", (chunk) => resolve(chunk.toString()));
        daemon.once("error", reject);
        daemon.once("exit", (code) => reject(new Error("fake daemon exited: " + code)));
      });
      assert.match(ready, /READY/u);
      const inode = externalListenerInode(daemon.pid, socketFile);
      const client = net.createConnection(socketFile);
      await new Promise((resolve, reject) => {
        client.once("connect", resolve);
        client.once("error", reject);
      });
      client.pause();
      client._handle.readStop();
      const child = spawn(binary, [
        String(daemon.pid), startTicks(daemon.pid), inode, socketFile,
      ], {
        stdio: ["ignore", "pipe", "pipe", client._handle.fd],
        env: { ...process.env, VIRKI_DISPOSABLE_DOCKER_RO_BRIDGE_TEST: "1" },
      });
      const [result, sent] = await Promise.all([
        new Promise((resolve, reject) => {
          let stdout = "", stderr = "";
          child.stdout.on("data", (v) => { stdout += v; });
          child.stderr.on("data", (v) => { stderr += v; });
          child.once("error", reject);
          child.once("close", (code) => resolve({ code, stdout, stderr }));
        }),
        new Promise((resolve) => daemon.stdout.once("data", (data) => resolve(data.toString()))),
      ]);
      client.destroy();
      assert.match(sent, /SENT_RIGHTS/u);
      assert.equal(result.code, 2, result.stderr);
      assert.equal(JSON.parse(result.stdout).status, "NOT_AUTHORIZED");
    } finally {
      daemon.kill("SIGTERM");
      rmSync(socketFile, { force: true });
    }
  });
  assert.ok(/microsoft|WSL/iu.test(os.release()) || process.platform === "linux");
});
