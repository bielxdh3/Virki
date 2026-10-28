import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, chmodSync, rmSync, readFileSync, truncateSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const linux = process.platform === "linux" && process.arch === "x64" &&
  process.env.VIRKI_DISPOSABLE_FD_TRANSPORT_TEST === "1" &&
  (/microsoft-standard-WSL2/iu.test(os.release()) ||
    readFileSync("/proc/1/cgroup", "utf8").includes("docker") ||
    readFileSync("/proc/sys/kernel/osrelease", "utf8").includes("Linux"));

test("bounded, reusable native Linux FD transport remains nonauthorizing", {
  skip: linux ? false : "opt-in disposable Linux/WSL test only",
}, async (t) => {
  const dir = mkdtempSync("/tmp/virki-fd-bound-");
  chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = path.join(dir, "probe");
  const sanitizer = process.env.VIRKI_DISPOSABLE_FD_TRANSPORT_SANITIZE === "1";
  execFileSync("/usr/bin/gcc", [
    "-std=c11", "-Wall", "-Wextra", "-Werror", sanitizer ? "-O1" : "-O2",
    ...(sanitizer ? ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"] : []),
    "-DVDT_DISPOSABLE_TEST_SOURCE_FAULT=1",
    "-D_FORTIFY_SOURCE=2",
    "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
    "-o", binary, path.join(here, "native-docker-fd-transport.c"),
    path.join(here, "native-docker-fd-transport-fixture.c"),
    path.join(here, "native-docker-fd-transport-test-fault.c"),
    "-lcrypto",
  ], { timeout: 20000 });
  const file = path.join(dir, "archive.data");
  const payload = Buffer.alloc(1024 * 1024 + 7);
  for (let i = 0; i < payload.length; i++) payload[i] = i % 251;
  writeFileSync(file, payload, { mode: 0o600 });

  async function run(mode, { pid = process.pid, clientMode = "normal", oversize = false } = {}) {
    const socketFile = path.join(dir, "daemon.sock");
    const seen = [];
    let mutated = false;
    if (oversize) truncateSync(file, 64 * 1024 * 1024 + 1);
    const server = net.createServer((socket) => {
      let incoming = Buffer.alloc(0);
      let phase = 0;
      // A rejected frame closes the client FD abruptly. The disposable peer
      // must tolerate ECONNRESET without obscuring the client's refusal.
      socket.on("error", () => {});
      socket.on("data", (bytes) => {
        incoming = Buffer.concat([incoming, bytes]);
        // The source inode is deliberately overwritten while the import is
        // underway. The transport must send only its already-sealed snapshot.
        if (mode === "mutate-on-load" && !mutated &&
            incoming.includes(Buffer.from("POST /v1.45/images/load?quiet=1"))) {
          mutated = true;
          writeFileSync(file, Buffer.alloc(payload.length, 0x5a));
        }
        for (;;) {
          const end = incoming.indexOf("\r\n\r\n");
          if (end < 0) return;
          const header = incoming.subarray(0, end + 4).toString("ascii");
          const length = Number(/\r\nContent-Length: ([0-9]+)\r\n/u.exec(header)?.[1] ?? 0);
          if (incoming.length < end + 4 + length) return;
          const body = incoming.subarray(end + 4, end + 4 + length);
          incoming = incoming.subarray(end + 4 + length);
          seen.push({ header, size: body.length,
            sha: createHash("sha256").update(body).digest("hex") });
          const responseBody = phase === 0 ? "OK" :
            phase === 1 ? '{"ID":"disposable"}' :
            phase === 2 ? '{"stream":"test import receipt"}\n' :
            '{"Id":"sha256:' + "a".repeat(64) + '"}';
          let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
            "Content-Length: " + Buffer.byteLength(responseBody) +
            "\r\nConnection: keep-alive\r\n\r\n";
          if (mode === "duplicate-length" && phase === 0)
            headers = headers.replace("Connection: keep-alive",
              "Content-Length: 2\r\nConnection: keep-alive");
          if (mode === "duplicate-content-type" && phase === 0)
            headers = headers.replace("Connection: keep-alive",
              "Content-Type: application/json\r\nConnection: keep-alive");
          if (mode === "chunked-smuggling" && phase === 0)
            headers = headers.replace("Connection: keep-alive",
              "Transfer-Encoding: chunked\r\nConnection: keep-alive");
          if (["chunked-valid", "fragment-chunked", "chunked-trailer"].includes(mode) &&
              phase === 2)
            headers = headers.replace(/Content-Length: [0-9]+\r\n/u,
              "Transfer-Encoding: chunked\r\n");
          if (mode === "bad-length" && phase === 0)
            headers = headers.replace("Content-Length: 2", "Content-Length: 3");
          if (mode === "status-redirect" && phase === 0)
            headers = headers.replace("200 OK", "302 Found");
          if (mode === "response-smuggling" && phase === 0)
            headers = headers + responseBody + "JUNK";
          if (mode === "oversized-headers" && phase === 0)
            headers = headers.replace("Connection: keep-alive",
              "X-Pad: " + "A".repeat(9000) + "\r\nConnection: keep-alive");
          if (mode === "dead-on-load" && phase === 2) { socket.destroy(); return; }
          if (mode === "stall-on-load" && phase === 2) return;
          if (["chunked-valid", "fragment-chunked", "chunked-trailer"].includes(mode) &&
              phase === 2) {
            const framed = Buffer.byteLength(responseBody).toString(16) + "\r\n" +
              responseBody + "\r\n0\r\n" +
              (mode === "chunked-trailer" ? "X-Forbidden: value\r\n\r\n" : "\r\n");
            socket.write(headers);
            if (mode === "fragment-chunked") {
              // Fragment each chunk delimiter across separate kernel reads.
              for (let k = 0; k < framed.length; k++)
                setTimeout(() => { if (!socket.destroyed) socket.write(framed[k]); }, k * 2);
            } else socket.write(framed);
            phase++;
            continue;
          }
          if (mode === "response-smuggling" && phase === 0)
            socket.write(headers);
          else if (mode === "wrong-body" && phase === 0)
            socket.write(headers + "NO");
          else socket.write(headers + responseBody);
          if (mode === "mutate-after-info" && phase === 1) {
            mutated = true;
            writeFileSync(file, Buffer.alloc(payload.length, 0x5a));
          }
          phase++;
        }
      });
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketFile, resolve);
    });
    const child = spawn(binary, [socketFile, file, String(pid), clientMode,
      createHash("sha256").update(payload).digest("hex")], {
      env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_FD_TRANSPORT_TEST: "1",
        ...(clientMode === "slow-staging" ?
          { VIRKI_TEST_DELAY_SOURCE_PREAD_MS: "4700" } : {}),
        ...(clientMode === "slow-write" ?
          { VIRKI_TEST_DELAY_STAGE_PWRITE_MS: "4700" } : {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = await new Promise((resolve, reject) => {
      let stdout = "", stderr = "";
      child.stdout.on("data", (b) => { stdout += b; });
      child.stderr.on("data", (b) => { stderr += b; });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stdout, stderr }));
    });
    await new Promise((resolve) => server.close(resolve));
    if (mutated || oversize) writeFileSync(file, payload);
    return { ...result, seen, mutated,
      json: JSON.parse(result.stdout.trim()) };
  }

  await t.test("streams actual archive FD over one socket across ping/info/load/inspect", async () => {
    const r = await run("normal");
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.json.status, "DISPOSABLE_FD_TRANSPORT_ONLY");
    assert.equal(r.json.dockerLoadAuthorized, false);
    assert.equal(r.json.deployAuthorized, false);
    assert.deepEqual(r.seen.map((v) => v.header.split(" ")[0]),
      ["GET", "GET", "POST", "GET"]);
    assert.equal(r.seen[2].size, payload.length);
    assert.equal(r.seen[2].sha, createHash("sha256").update(payload).digest("hex"));
  });
  await t.test("peer identity mismatch refuses before any Docker HTTP exchange", async () => {
    const r = await run("normal", { pid: 1 });
    assert.equal(r.code, 2);
    assert.equal(r.seen.length, 0);
    assert.equal(r.json.dockerLoadAuthorized, false);
  });
  await t.test("kernel GID mismatch refuses before any API call", async () => {
    const r = await run("normal", { clientMode: "wrong-gid" });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 0);
  });
  await t.test("replacing FD with another connection to the SAME peer is refused", async () => {
    const r = await run("normal", { clientMode: "swap-fd" });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 0);
    assert.equal(r.json.dockerLoadAuthorized, false);
  });
  await t.test("midflight borrowed-FD replacement cannot redirect upload", async () => {
    const r = await run("normal", { clientMode: "swap-midflight" });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 2);
  });
  await t.test("active reattach is refused and leaves held peer FDs intact", async () => {
    const r = await run("normal", { clientMode: "reattach-active" });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.seen.length, 4);
  });
  await t.test("delayed source pread expires staging deadline without any POST", async () => {
    const r = await run("normal", { clientMode: "slow-staging" });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 2);
    assert.equal(r.json.dockerLoadAuthorized, false);
  });
  await t.test("delayed memfd pwrite expires staging deadline without any POST", async () => {
    const r = await run("normal", { clientMode: "slow-write" });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 2);
    assert.equal(r.json.dockerLoadAuthorized, false);
  });
  await t.test("oversized sparse source is denied before memfd allocation or POST", async () => {
    const r = await run("normal", { oversize: true });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 2);
    assert.equal(r.json.dockerLoadAuthorized, false);
  });
  await t.test("unverified archive digest blocks POST before mutation", async () => {
    const r = await run("normal", { clientMode: "bad-digest" });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 2);
  });
  await t.test("source mutated after info is denied before sending POST bytes", async () => {
    const r = await run("mutate-after-info");
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.mutated, true);
    assert.equal(r.seen.length, 2);
  });
  await t.test("source mutated during load cannot change sealed upload bytes", async () => {
    const r = await run("mutate-on-load");
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.mutated, true);
    assert.equal(r.seen.length, 4);
    assert.equal(r.seen[2].size, payload.length);
    assert.equal(r.seen[2].sha, createHash("sha256").update(payload).digest("hex"));
  });
  await t.test("Docker chunked stream receipt is decoded with strict framing", async () => {
    const r = await run("chunked-valid");
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.seen.length, 4);
  });
  await t.test("fragmented chunked receipt survives short recvmsg reads", async () => {
    const r = await run("fragment-chunked");
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.seen.length, 4);
  });
  await t.test("image ID injection cannot reach Docker inspect endpoint", async () => {
    const r = await run("normal", { clientMode: "bad-image-id" });
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.seen.length, 3);
  });
  await t.test("refused HTTP reply cannot leave a stale response receipt", async () => {
    const r = await run("duplicate-length", { clientMode: "poison-output" });
    assert.equal(r.code, 2);
    assert.doesNotMatch(r.stderr, /STALE_RESPONSE_RETAINED/u);
  });
  for (const mode of ["duplicate-length", "duplicate-content-type",
    "chunked-smuggling", "bad-length",
    "response-smuggling",
    "chunked-trailer", "status-redirect", "oversized-headers", "dead-on-load", "stall-on-load"]) {
    await t.test(mode + " aborts the session", async () => {
      const r = await run(mode);
      assert.equal(r.code, 2, r.stderr);
      assert.equal(r.json.dockerLoadAuthorized, false);
      assert.equal(r.json.deployAuthorized, false);
      assert.ok(r.seen.length <= 3);
    });
  }
  await t.test("invalid ping body cannot become receipt", async () => {
    const r = await run("wrong-body");
    assert.equal(r.code, 2);
    assert.equal(r.seen.length, 1);
  });
});
