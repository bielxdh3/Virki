import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readlinkSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyNativeManualImageBatchReceipt } from "../manual-native-image-receipt.mjs";

const enabled = process.platform === "linux" && process.arch === "x64" &&
  process.env.VIRKI_DISPOSABLE_MANUAL_BATCH === "1";
const here = path.dirname(fileURLToPath(import.meta.url));
const REV = "b".repeat(40);
const IDS = ["sha256:" + "a".repeat(64), "sha256:" + "c".repeat(64)];
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("native owner-image sink exercise: 2 independently identified archives on ONE kernel peer", {
  skip: enabled ? false : "opt-in disposable Linux fixture only",
}, async (t) => {
  const directory = mkdtempSync("/tmp/virki-native-manual-");
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const binary = path.join(directory, "manual-native-batch");
  assert.throws(() => execFileSync("/usr/bin/gcc", ["-fsyntax-only",
    path.join(here, "manual-native-image-batch-fixture.c")], { timeout: 10000,
    stdio: "pipe" }), "fixture must not compile without explicit disposable define");
  execFileSync("/usr/bin/gcc", [
    "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-D_FORTIFY_SOURCE=2",
    "-DVIRKI_DISPOSABLE_MANUAL_BATCH=1", "-fstack-protector-strong",
    "-fPIE", "-pie", "-Wl,-z,relro,-z,now", "-o", binary,
    path.join(here, "native-docker-fd-transport.c"),
    path.join(here, "manual-native-image-batch-fixture.c"), "-lcrypto",
  ], { timeout: 20000 });
  const budgetDeniedBinary = path.join(directory, "budget-denied-native-batch");
  execFileSync("/usr/bin/gcc", [
    "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-D_FORTIFY_SOURCE=2",
    "-DVIRKI_DISPOSABLE_MANUAL_BATCH=1", "-DVIRKI_DISPOSABLE_DENY_LARGE_MEMORY=1",
    "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
    "-o", budgetDeniedBinary, path.join(here, "native-docker-fd-transport.c"),
    path.join(here, "manual-native-image-batch-fixture.c"), "-lcrypto",
  ], { timeout: 20000 });
  const payloads = [Buffer.alloc(8192, 0x47), Buffer.alloc(16384, 0x63)];
  const SHAS = payloads.map(hash);
  const largeSize = 64 * 1024 * 1024 + 512;
  const largeHash = createHash("sha256").update(payloads[0]);
  for (let remaining = largeSize - payloads[0].length; remaining;) {
    const n = Math.min(remaining, 1024 * 1024);
    largeHash.update(Buffer.alloc(n));
    remaining -= n;
  }
  const largeSha = largeHash.digest("hex");
  writeFileSync(path.join(directory, "runtime.data"), payloads[0], { mode: 0o600 });
  writeFileSync(path.join(directory, "migrator.data"), payloads[1], { mode: 0o600 });
  const expected = {
    sourceSha: REV, manifestSha256: "f".repeat(64),
    runtime: { imageId: IDS[0], archiveSha256: SHAS[0] },
    migrator: { imageId: IDS[1], archiveSha256: SHAS[1] },
  };
  function inspector(index, bad) {
    return JSON.stringify({ Id: bad ? IDS[1 - index] : IDS[index],
      Os: "linux", Architecture: "amd64", RepoTags: [], RepoDigests: [],
      Config: { User: "node:node", Labels: {
        "org.opencontainers.image.revision": REV,
        "org.opencontainers.image.source": "https://github.com/bielxdh3/Virki",
      } },
    });
  }

  async function run({ badPid = false, badSecondSha = false, badInspect = false,
    secondLoadError = false, mutateSecondAfterFirstInspect = false,
    missingFixtureGate = false, malformedStaging = null, denyBudget = false,
    firstSha = SHAS[0] } = {}) {
    const calls = [];
    let incoming = Buffer.alloc(0);
    const socketPath = path.join(directory, "daemon.sock");
    const server = net.createServer((socket) => {
      socket.on("error", () => {});
      socket.on("data", (bytes) => {
        incoming = Buffer.concat([incoming, bytes]);
        for (;;) {
          const end = incoming.indexOf("\r\n\r\n");
          if (end < 0) break;
          const header = incoming.subarray(0, end + 4).toString("ascii");
          const length = Number(/\r\nContent-Length: ([0-9]+)\r\n/u.exec(header)?.[1]);
          if (!Number.isSafeInteger(length) || incoming.length < end + 4 + length) break;
          const body = incoming.subarray(end + 4, end + 4 + length);
          incoming = incoming.subarray(end + 4 + length);
          const index = calls.length;
          calls.push({ method: header.split(" ")[0], path: header.split(" ")[1],
            bodySize: body.length, bodySha: hash(body) });
          const data = index === 0 ? "OK" : index === 1 ? "{\"ID\":\"isolated-fixture\"}" :
            index === 2 ? '{"stream":"Loaded image ID: ' + IDS[0] + '"}\n' :
            index === 3 ? inspector(0, badInspect) : index === 4 ?
              (secondLoadError ? '{"error":"rejected second load"}\n' :
                '{"stream":"Loaded image ID: ' + IDS[1] + '"}\n') :
              inspector(1, badInspect);
          socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
            "Content-Length: " + Buffer.byteLength(data) +
            "\r\nConnection: keep-alive\r\n\r\n" + data);
          if (mutateSecondAfterFirstInspect && index === 3) {
            writeFileSync(path.join(directory, "migrator.data"),
              Buffer.alloc(payloads[1].length, 0x15));
          }
        }
      });
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });
    const child = spawn(denyBudget ? budgetDeniedBinary : binary,
      [directory, String(badPid ? 1 : process.pid), REV,
      ...IDS, firstSha, badSecondSha ? "0".repeat(64) : SHAS[1],
      ...(malformedStaging ? [malformedStaging] : [])], {
      env: { PATH: "/usr/bin:/bin",
        ...(missingFixtureGate ? {} : { VIRKI_DISPOSABLE_MANUAL_BATCH: "1" }) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = await new Promise((resolve, reject) => {
      let stdout = "", stderr = "";
      child.stdout.on("data", (part) => { stdout += part; });
      child.stderr.on("data", (part) => { stderr += part; });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stdout, stderr }));
    });
    await new Promise((resolve) => server.close(resolve));
    if (mutateSecondAfterFirstInspect) {
      writeFileSync(path.join(directory, "migrator.data"), payloads[1]);
    }
    return { ...result, calls, receipt: JSON.parse(result.stdout) };
  }

  await t.test("both verified runtime/migrator Docker loads and inspect receipts share one live peer", async () => {
    const value = await run();
    assert.equal(value.code, 0, value.stderr);
    assert.deepEqual(value.calls.map((c) => c.method),
      ["GET", "GET", "POST", "GET", "POST", "GET"]);
    assert.deepEqual(value.calls.filter((c) => c.method === "POST").map((c) => c.bodySha), SHAS);
    assert.deepEqual(value.calls.filter((c) => c.method === "POST").map((c) => c.bodySize),
      payloads.map((payload) => payload.length));
    const reconciled = verifyNativeManualImageBatchReceipt({ batch: value.receipt, expected });
    assert.equal(reconciled.status, "DISPOSABLE_TWO_IMAGES_RECONCILED_NONAUTHORIZING");
    assert.equal(reconciled.deployAuthorized, false);
  });
  await t.test("mismatched native daemon peer PID refuses before any HTTP", async () => {
    const value = await run({ badPid: true });
    assert.equal(value.code, 2);
    assert.equal(value.calls.length, 0);
    assert.equal(value.receipt.deployAuthorized, false);
  });
  await t.test("missing disposable opt-in refuses even to connect", async () => {
    const value = await run({ missingFixtureGate: true });
    assert.equal(value.code, 2);
    assert.equal(value.calls.length, 0);
  });
  await t.test("wrong second archive digest refuses both image loads before any HTTP", async () => {
    const value = await run({ badSecondSha: true });
    assert.equal(value.code, 2);
    assert.equal(value.calls.length, 0);
  });
  await t.test("outstanding staging writer cannot change the separately sealed upload snapshot", async () => {
    const value = await run({ malformedStaging: "hold-writer" });
    assert.equal(value.code, 0);
    assert.deepEqual(value.calls.filter((c) => c.method === "POST").map((c) => c.bodySha), SHAS);
  });
  await t.test("named source cannot enter detached large-archive streaming path", async () => {
    const value = await run({ malformedStaging: "named-source" });
    assert.equal(value.code, 2);
    assert.deepEqual(value.calls.map((c) => c.method), ["GET", "GET"]);
  });
  await t.test("real runtime TAR size 959170560 B scans anonymous sparse FD then rejects wrong digest before POST", async () => {
    const value = await run({ malformedStaging: "large-runtime" });
    assert.equal(value.code, 2);
    assert.deepEqual(value.calls.map((c) => c.method), ["GET", "GET"]);
  });
  await t.test("real migrator TAR size 1330946048 B scans anonymous sparse FD then rejects wrong digest before POST", async () => {
    const value = await run({ malformedStaging: "large-migrator" });
    assert.equal(value.code, 2);
    assert.deepEqual(value.calls.map((c) => c.method), ["GET", "GET"]);
  });
  await t.test("insufficient measured memory refuses >64MiB even with fully matching hash BEFORE POST", async () => {
    const value = await run({
      malformedStaging: "large-stream", denyBudget: true, firstSha: largeSha,
    });
    assert.equal(value.code, 2);
    assert.deepEqual(value.calls.map((c) => c.method), ["GET", "GET"]);
    assert.equal(value.receipt.deployAuthorized, false);
  });
  await t.test("forged Docker image identity never reconciles", async () => {
    const value = await run({ badInspect: true });
    assert.equal(value.code, 0);
    assert.throws(() => verifyNativeManualImageBatchReceipt({ batch: value.receipt, expected }));
  });
  await t.test("second source pathname mutation cannot alter anonymous private FD image bytes", async () => {
    const value = await run({ mutateSecondAfterFirstInspect: true });
    assert.equal(value.code, 0, value.stderr);
    assert.deepEqual(value.calls.map((c) => c.method), ["GET", "GET", "POST", "GET", "POST", "GET"]);
    assert.deepEqual(value.calls.filter((c) => c.method === "POST").map((c) => c.bodySha), SHAS);
    assert.equal(value.receipt.status, "DISPOSABLE_NATIVE_BATCH_COMPLETE");
  });
  await t.test("second load error poisons result even after first POST", async () => {
    const value = await run({ secondLoadError: true });
    assert.equal(value.code, 2);
    assert.deepEqual(value.calls.map((c) => c.method), ["GET", "GET", "POST", "GET", "POST"]);
    assert.equal(value.receipt.status, "BLOCKED_DISPOSABLE_BATCH_UNCERTAIN");
    assert.equal(value.receipt.deployAuthorized, false);
  });
  await t.test("65MiB+512 detached O_TMPFILE transfers FULL bytes from a sealed memfd despite hostile same-UID writer", async () => {
    const bigSize = largeSize;
    const digest = largeSha;
    const observed = [];
    let snapshotProof;
    const socketFile = path.join(directory, "daemon.sock");
    const server = net.createServer((socket) => {
      let partial = Buffer.alloc(0), bodyLeft = 0, current, sha;
      socket.on("error", () => {});
      function finish() {
        current.bodySha = sha.digest("hex");
        observed.push(current);
        const i = observed.length - 1;
        const response = i === 0 ? "OK" : i === 1 ? '{"ID":"disposable"}' :
          i === 2 ? '{"stream":"runtime image imported"}\n' :
            i === 3 ? inspector(0, false) :
              i === 4 ? '{"stream":"migrator image imported"}\n' : inspector(1, false);
        socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
          `Content-Length: ${Buffer.byteLength(response)}\r\nConnection: keep-alive\r\n\r\n` + response);
        current = null;
      }
      socket.on("data", (chunk) => {
        let data = chunk;
        while (data.length) {
          if (bodyLeft) {
            const n = Math.min(bodyLeft, data.length);
            sha.update(data.subarray(0, n));
            current.bodySize += n;
            bodyLeft -= n;
            data = data.subarray(n);
            if (!bodyLeft) finish();
            continue;
          }
          partial = Buffer.concat([partial, data]);
          const end = partial.indexOf("\r\n\r\n");
          if (end < 0) {
            assert.ok(partial.length < 8192, "bounded header buffer");
            return;
          }
          const header = partial.subarray(0, end + 4).toString("ascii");
          const match = /\r\nContent-Length: ([0-9]+)\r\n/u.exec(header);
          assert.ok(match);
          bodyLeft = Number(match[1]);
          const [method, url] = header.split(" ");
          current = { method, url, bodySize: 0 };
          if (method === "POST" && observed.length === 2) {
            const fdRoot = `/proc/${child.pid}/fd`;
            const sealed = readdirSync(fdRoot).find((n) => {
              try { return readlinkSync(path.join(fdRoot, n)).includes("memfd:virki-"); }
              catch { return false; }
            });
            if (sealed) {
              const script = [
                "import os, fcntl, sys, json",
                "p = sys.argv[1]",
                "r = os.open(p, os.O_RDONLY)",
                "seals = fcntl.fcntl(r, fcntl.F_GET_SEALS)",
                "os.close(r)",
                "refused = False",
                "try:",
                "    w = os.open(p, os.O_WRONLY | os.O_NONBLOCK)",
                "    try:",
                "        os.pwrite(w, b'HOSTILE', 0)",
                "    except OSError:",
                "        refused = True",
                "    finally:",
                "        os.close(w)",
                "except OSError:",
                "    refused = True",
                "print(json.dumps({'seals': seals, 'writerRefused': refused}))",
              ].join("\n");
              snapshotProof = JSON.parse(execFileSync("/usr/bin/python3",
                ["-c", script, path.join(fdRoot, sealed)], { timeout: 5000 }).toString());
            }
          }
          sha = createHash("sha256");
          data = partial.subarray(end + 4);
          partial = Buffer.alloc(0);
          if (bodyLeft === 0) finish();
        }
      });
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketFile, resolve);
    });
    const child = spawn(binary, [directory, String(process.pid), REV, ...IDS,
      digest, SHAS[1], "large-stream"], {
      env: { PATH: "/usr/bin:/bin", VIRKI_DISPOSABLE_MANUAL_BATCH: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = await new Promise((resolve, reject) => {
      let stdout = "", stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stdout, stderr }));
    });
    await new Promise((resolve) => server.close(resolve));
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(snapshotProof, { seals: 15, writerRefused: true },
      "large POST must read fully F_SEAL_WRITE/GROW/SHRINK/SEAL memfd that resists same-UID pwrite");
    assert.deepEqual(observed.map((call) => call.method), ["GET", "GET", "POST", "GET", "POST", "GET"]);
    assert.equal(observed[2].bodySize, bigSize);
    assert.equal(observed[2].bodySha, digest);
    assert.equal(observed[4].bodySize, payloads[1].length);
    assert.equal(observed[4].bodySha, SHAS[1]);
    const reconciled = verifyNativeManualImageBatchReceipt({
      batch: JSON.parse(result.stdout),
      expected: { ...expected, runtime: { ...expected.runtime, archiveSha256: digest } },
    });
    assert.equal(reconciled.deployAuthorized, false);
  });
});
