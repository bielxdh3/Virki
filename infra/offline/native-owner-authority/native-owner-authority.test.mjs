import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import net from "node:net";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url));
const LINUX_NATIVE_SKIP = process.platform !== "linux"
  ? "Linux-only native owner authority tests"
  : (typeof process.getuid === "function" && process.getuid() === 0
    ? "Non-root Linux user required for native owner authority tests"
    : false);
const GCC_HARDEN = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong"];
const GCC_PIE = ["-fPIE", "-pie", "-Wl,-z,relro,-z,now"];

test("Owner Authority - C unit tests (TweetNaCl Ed25519 and wire struct sizes)", { skip: LINUX_NATIVE_SKIP }, (t) => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-unit-"));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const binPath = path.join(binDir, "owner-unit");
  execFileSync("/usr/bin/gcc", [...GCC_HARDEN, ...GCC_PIE, path.join(SRC_DIR, "native-owner-authority.test.c"), "-o", binPath]);
  const out = execFileSync(binPath, [], { encoding: "utf8" });
  assert.match(out, /All Owner Authority Unit Tests PASSED/);
});

test("Owner Authority - V3 native stream parser requires canonical WalkDir paths and order", { skip: LINUX_NATIVE_SKIP }, (t) => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-stream-canonical-"));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const binPath = path.join(binDir, "owner-stream-v3");
  execFileSync("/usr/bin/gcc", [...GCC_HARDEN, ...GCC_PIE,
    path.join(SRC_DIR, "native-owner-v3-stream-adversarial.test.c"), "-o", binPath]);
  assert.match(execFileSync(binPath, { encoding: "utf8" }), /C4_NATIVE_CANONICAL_WALK_STREAM_PASS/);
});

test("Owner Authority - V3 JSON keys cannot hide escaped aliases from C4", { skip: LINUX_NATIVE_SKIP }, (t) => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-json-canonical-"));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const binPath = path.join(binDir, "owner-json-v3");
  execFileSync("/usr/bin/gcc", [...GCC_HARDEN, ...GCC_PIE,
    path.join(SRC_DIR, "native-owner-v3-json-adversarial.test.c"), "-o", binPath]);
  assert.match(execFileSync(binPath, { encoding: "utf8" }), /C4_NATIVE_JSON_KEY_CANONICAL_PASS/);
});

test("Owner Authority - static binary has zero PT_INTERP and zero PT_DYNAMIC", { skip: LINUX_NATIVE_SKIP }, (t) => {
  const authoritySrc = path.join(SRC_DIR, "native-owner-authority.c");
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-static-"));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const binPath = path.join(binDir, "virki-owner-authority-static-bin");

  execFileSync("/usr/bin/gcc", ["-static", ...GCC_HARDEN, authoritySrc, "-o", binPath]);
  const readelfOut = execFileSync("readelf", ["-l", binPath], { encoding: "utf8" });
  assert.doesNotMatch(readelfOut, /INTERP/);
  assert.doesNotMatch(readelfOut, /DYNAMIC/);
});

test("Owner Authority - preview-only mode displays security parameters and exits cleanly", { skip: LINUX_NATIVE_SKIP }, (t) => {
  const authoritySrc = path.join(SRC_DIR, "native-owner-authority.c");
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-prev-"));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const binPath = path.join(binDir, "virki-owner-authority-prev-bin");

  execFileSync("/usr/bin/gcc", [...GCC_HARDEN, ...GCC_PIE, authoritySrc, "-o", binPath]);
  const out = execFileSync(binPath, [
    "--socket", path.join(binDir, "owner.sock"),
    "--ledger-dir", path.join(binDir, "ledger"),
    "--preview-only",
  ], { encoding: "utf8" });

  assert.match(out, /VIRKI INDEPENDENT OWNER AUTHORITY SERVICE INSTALL PREVIEW/);
  assert.match(out, /Role: Independent Owner Trust Anchor & Fencing Authority/);
  assert.match(out, /Dev Same-UID Allowed: NO \(FAIL CLOSED\)/);
});

test("Owner Authority - V20 durable ledger append-budget boundary (Linux sparse fixture)", { skip: LINUX_NATIVE_SKIP }, (t) => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-v20-"));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const binPath = path.join(binDir, "virki-owner-v20-budget");
  execFileSync("/usr/bin/gcc", [...GCC_HARDEN, ...GCC_PIE, path.join(SRC_DIR, "owner-ledger-replay-v20.boundary.test.c"), "-o", binPath]);
  assert.match(execFileSync(binPath, { encoding: "utf8" }), /V20_REPLAY_APPEND_BUDGET_BOUNDARY_PASS/);
});

test("Owner Authority - full lifecycle, same-UID refusal, durable nonce reservation, and unconditional no-sign", { skip: LINUX_NATIVE_SKIP }, async (t) => {
  const authoritySrc = path.join(SRC_DIR, "native-owner-authority.c");
  const clientSrc = path.join(SRC_DIR, "owner-authority-client-fixture.c");

  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-bins-"));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const srvBin = path.join(binDir, "virki-owner-srv-bin");
  const clientBin = path.join(binDir, "virki-owner-cli-bin");

  execFileSync("/usr/bin/gcc", [...GCC_HARDEN, ...GCC_PIE, authoritySrc, "-o", srvBin]);
  execFileSync("/usr/bin/gcc", [...GCC_HARDEN, ...GCC_PIE, clientSrc, "-o", clientBin]);

  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-owner-test-"));
  const sockPath = path.join(testDir, "owner.sock");
  const ledgerDir = path.join(testDir, "ledger");
  fs.mkdirSync(ledgerDir, { mode: 0o700 });

  // Generate Ed25519 keypair for test
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const rawPriv = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
  const rawPub = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  // TweetNaCl secret key format is 64 bytes: 32 bytes seed/priv + 32 bytes pub
  const naclSecretKey = Buffer.concat([rawPriv, rawPub]);
  const keyFilePath = path.join(testDir, "owner.key");
  fs.writeFileSync(keyFilePath, naclSecretKey, { mode: 0o400 });

  function runClient(action, nonce = "11223344556677889900aabbccddeeff", scopeToken = "", epoch = 1) {
    const out = execFileSync(clientBin, [sockPath, action, nonce, scopeToken, String(epoch)], { encoding: "utf8" });
    const result = {};
    for (const line of out.trim().split("\n")) {
      const idx = line.indexOf("=");
      if (idx !== -1) {
        result[line.substring(0, idx)] = line.substring(idx + 1);
      }
    }
    return result;
  }

  const activeDaemons = new Set();

  // Helper to start daemon
  function startDaemon(allowSameUid = true, useKey = true, daemonGroup = false) {
    const args = [
      "--socket", sockPath,
      "--ledger-dir", ledgerDir,
    ];
    if (allowSameUid) args.push("--dev-allow-same-uid");
    else args.push("--daemon-uid", String(process.getuid()+1));
    if (daemonGroup) args.push("--daemon-gid", String(process.getgid()));
    if (useKey) {
      args.push("--key-file", keyFilePath);
      args.push("--key-id", "test-owner-key-01");
    }

    const proc = spawn(srvBin, args, { stdio: ["ignore", "pipe", "inherit"] });
    activeDaemons.add(proc);
    proc.once("exit", () => { activeDaemons.delete(proc); });
    return new Promise((resolve, reject) => {
      let stdoutBuf = "";
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          proc.kill("SIGKILL");
          reject(new Error("Owner authority daemon startup timed out"));
        }
      }, 5000);
      proc.stdout.on("data", (data) => {
        stdoutBuf += data.toString("utf8");
        if (!settled && stdoutBuf.includes("VIRKI_OWNER_AUTHORITY_READY:") && stdoutBuf.includes("\n")) {
          settled = true;
          clearTimeout(timer);
          resolve(proc);
        }
      });
      proc.on("error", (err) => {
        if (!settled) { settled = true; clearTimeout(timer); reject(err); }
      });
      proc.on("exit", (code, signal) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error(`Daemon exited unexpectedly (code=${code}, signal=${signal})`));
        }
      });
    });
  }

  async function stopDaemon(proc) {
    if (proc.exitCode !== null || proc.signalCode !== null) {
      activeDaemons.delete(proc);
      return;
    }
    await new Promise((resolve, reject) => {
      const killTimer = setTimeout(() => {
        proc.kill("SIGKILL");
      }, 3000);
      const failTimer = setTimeout(() => {
        reject(new Error("owner daemon did not terminate"));
      }, 5000);
      proc.once("exit", () => {
        clearTimeout(killTimer);
        clearTimeout(failTimer);
        activeDaemons.delete(proc);
        resolve();
      });
      if (!proc.kill("SIGTERM")) {
        clearTimeout(killTimer);
        clearTimeout(failTimer);
        reject(new Error("SIGTERM failed"));
      }
    });
  }

  try {
    // 1. Test Strict Mode (No --dev-allow-same-uid): Same-UID must be REJECTED!
    {
      const missingUid = spawnSync(srvBin,
        ["--socket",sockPath,"--ledger-dir",ledgerDir],
        {encoding:"utf8",timeout:3000});
      assert.equal(missingUid.error,undefined);
      assert.notEqual(missingUid.status,0,
        "strict owner must fail before any ledger/socket mutation without daemon UID");
      assert.match(missingUid.stderr,/--daemon-uid/);
      const invalidUid = spawnSync(srvBin,
        ["--socket",sockPath,"--ledger-dir",ledgerDir,"--daemon-uid",String(process.getuid())],
        {encoding:"utf8",timeout:3000});
      assert.notEqual(invalidUid.status,0,"owner and daemon UIDs cannot be equal in strict mode");
      // V23 pins both peer credentials if group-sharing was requested.
      // Root GID would be unusable by non-root peers and must not create a
      // misleading 0660 owner socket or silently disable GID identity.
      const invalidGid = spawnSync(srvBin,
        ["--socket",sockPath,"--ledger-dir",ledgerDir,
         "--daemon-uid",String(process.getuid()+1),"--daemon-gid","0"],
        {encoding:"utf8",timeout:3000});
      assert.notEqual(invalidGid.status,0,"strict owner must reject root daemon GID");
      assert.match(invalidGid.stderr,/non-root numeric GID/);
      const strictProc = await startDaemon(false, true);
      assert.equal(fs.statSync(sockPath).mode & 0o777,0o600,
        "strict owner socket must not inherit unsafe host umask");
      const res = runClient("status");
      assert.equal(res.STATUS, "10", "Strict mode must reject same-UID client with ERR_PEERCRED (10)");
      assert.equal(res.EPOCH, "0", "ERR_PEERCRED must not leak ledger epoch");
      assert.equal(res.SEQ, "0", "ERR_PEERCRED must not leak ledger sequence");
      assert.equal(res.KEY_ID ?? "", "", "ERR_PEERCRED must not leak owner key ID");
      await stopDaemon(strictProc);

      // Explicit daemon group only widens connect permission, never who
      // passes SO_PEERCRED UID. This fixture cannot claim real cross-UID
      // ownership; it proves the intended socket inode mode and same-UID
      // denial without privileged OS user switching.
      const groupProc = await startDaemon(false,true,true);
      assert.equal(fs.statSync(sockPath).mode & 0o777,0o660,
        "explicit daemon group must be exactly 0660, never inherited umask");
      assert.equal(runClient("status").STATUS,"10",
        "owner UID remains forbidden even when socket group can connect");
      await stopDaemon(groupProc);
    }

    // 2. Test DEV mode with key loaded: Status succeeds
    let daemonProc = await startDaemon(true, true);
    assert.equal(fs.statSync(sockPath).mode & 0o777,0o600,
      "same-UID DEV socket still restricts arbitrary host principals");
    const resStatus = runClient("status");
    assert.equal(resStatus.STATUS, "0");
    const activeEpoch = Number(resStatus.EPOCH);
    assert.ok(activeEpoch >= 1);
    assert.equal(runClient("status-fragmented").STATUS,"0",
      "a valid fragmented SOCK_STREAM STATUS must be reassembled");
    assert.equal(runClient("status").SEQ,resStatus.SEQ,
      "segmented STATUS must not touch the durable sequence");
    assert.equal(runClient("status-with-fd").STATUS,"11",
      "STATUS carrying unauthorized SCM_RIGHTS must fail before command dispatch");
    const beforeFdNegatives=fs.readdirSync(`/proc/${daemonProc.pid}/fd`).length;
    const negativeFdNonce="f00df00df00df00df00df00df00df00d";
    assert.equal(runClient("sign-fifth-fd",negativeFdNonce,"a".repeat(64),activeEpoch).STATUS,"11",
      "fifth context descriptor must fail BAD_FRAME before SIGN_ACK gate");
    assert.equal(runClient("sign-excess-fd",negativeFdNonce,"a".repeat(64),activeEpoch).STATUS,"11",
      "nine context descriptors must trigger SCM_RIGHTS truncation/denial");
    assert.equal(runClient("status").STATUS,"0",
      "malicious descriptor submissions must not kill the owner listener");
    assert.equal(fs.readdirSync(`/proc/${daemonProc.pid}/fd`).length,beforeFdNegatives,
      "extra context descriptors must not leak inside owner daemon");
    const beforeSurplus = runClient("status").SEQ;
    assert.equal(runClient("status-trailing").STATUS,"11",
      "one complete STATUS followed by extra bytes must fail exact-frame EOF check");
    assert.equal(runClient("status-delayed-tail").STATUS,"11",
      "delayed post-frame bytes must not race ahead of authorization");
    assert.equal(runClient("status-no-fin").STATUS,"11",
      "legacy v2 client that leaves its write side open must be explicitly rejected");
    const unframedNonce="012345678901234567890123456789ab";
    assert.equal(runClient("begin-no-fin",unframedNonce,"",activeEpoch).STATUS,"11",
      "full BEGIN without request EOF must fail before reservation");
    const trailingNonce="bada55bada55bada55bada55bada55ba";
    assert.equal(runClient("begin-trailing",trailingNonce,"",activeEpoch).STATUS,"11",
      "BEGIN followed by arbitrary tail must never create a durable scope");
    assert.equal(runClient("status").SEQ,beforeSurplus,
      "surplus bytes cannot consume a nonce or change epoch or sequence");
    assert.equal(runClient("begin",trailingNonce,"",activeEpoch).STATUS,"0",
      "rejected surplus BEGIN must leave exact nonce available");
    const disconnect = execFileSync(clientBin,
      [sockPath,"begin-disconnect","cedecedecedecedecedecedecedecede","",String(activeEpoch)],
      {encoding:"utf8"});
    assert.match(disconnect,/V21_TEST_PEER_DISCONNECTED/);
    assert.equal(runClient("status").STATUS,"0",
      "a disconnected peer must not kill native owner through SIGPIPE");
    // A fragmented but incomplete frame must be rejected after a *TOTAL*
    // two-second deadline. A per-recv deadline that resets forever would
    // permit an approved idle peer to pin the serial C4 listener.
    const beforePartial = runClient("status").SEQ;
    const partial = net.createConnection(sockPath);
    const partialReply = [];
    const startedPartialNs = process.hrtime.bigint();
    await new Promise((resolve,reject) => {
      partial.once("connect",resolve);
      partial.once("error",reject);
    });
    partial.write(Buffer.from([0x56]));
    await new Promise((resolve,reject) => {
      const deadline = setTimeout(() => {
        partial.destroy();
        reject(new Error("V21 incomplete frame did not return by its total deadline"));
      },4500);
      partial.on("data",(bytes) => partialReply.push(bytes));
      partial.once("end",() => {clearTimeout(deadline);resolve();});
      partial.once("error",(err)=>{clearTimeout(deadline);reject(err);});
    });
    const elapsedPartialMs = Number(process.hrtime.bigint() - startedPartialNs) / 1e6;
    assert.ok(elapsedPartialMs < 3800,
      "V21 incomplete frame exceeded bounded total receive deadline");
    const partialBytes=Buffer.concat(partialReply);
    assert.equal(partialBytes.length, 4455, "daemon should return exact fixed VROA_V2 response frame");
    assert.equal(partialBytes.subarray(0, 8).toString("utf8"), "VROA_V2\0");
    assert.equal(partialBytes.readUInt32LE(8), 2);
    assert.equal(partialBytes.readUInt32LE(12), 11,
      "incomplete but legitimate partial stream must fail BAD_FRAME without owner mutation");
    assert.equal(runClient("status").SEQ,beforePartial,
      "timed-out partial frame must not reserve an owner nonce or advance ledger");
    const segmentedNonce = "12344321123443211234432112344321";
    const segmentedBegin = runClient("begin-fragmented",segmentedNonce,"",activeEpoch);
    assert.equal(segmentedBegin.STATUS,"0",
      "fragmented BEGIN must reserve exactly one durable nonce");
    assert.equal(runClient("begin",segmentedNonce,"",activeEpoch).STATUS,"15",
      "segmented BEGIN must share the same replay/fencing state as normal BEGIN");
    denyEarlySignCheckV21();
    function denyEarlySignCheckV21() {
      const frame = runClient("sign-fragmented",segmentedNonce,
        segmentedBegin.SCOPE_TOKEN,activeEpoch);
      assert.equal(frame.STATUS,"22",
        "fragmented SIGN_ACK with SCM_RIGHTS must stay hard-disabled");
      assert.equal(frame.SIG_B64,"");
      assert.equal(frame.ACK_SHA,"");
    }

    // A second daemon MUST NOT increment the live epoch, replace the
    // incumbent's AF_UNIX socket or race with the same ledger inode.
    const second = spawnSync(srvBin, ["--socket", sockPath, "--ledger-dir", ledgerDir,
      "--dev-allow-same-uid", "--key-file", keyFilePath, "--key-id", "test-owner-key-01"],
      { encoding: "utf8", timeout: 3000 });
    assert.equal(second.error, undefined, "second owner daemon should fail promptly, not hang");
    assert.ok(second.status !== null && second.status !== 0,
      "second owner daemon illegally acquired the live ledger/socket");
    assert.equal(Number(runClient("status").EPOCH), activeEpoch,
      "second owner process changed live epoch while first served requests");

    const staleBeginNonce = "12341234123412341234123412341234";
    assert.equal(runClient("begin", staleBeginNonce, "", activeEpoch - 1).STATUS, "16",
      "stale BEGIN must not reserve a nonce or mutate the ledger");
    assert.equal(runClient("begin", staleBeginNonce, "", activeEpoch).STATUS, "0",
      "stale BEGIN should not consume the otherwise valid nonce");

    // 3. Test Nonce Replay in Single Process
    const nonce1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const beforeUppercase = runClient("status").SEQ;
    assert.equal(runClient("begin", nonce1.toUpperCase(), "", activeEpoch).STATUS, "11",
      "uppercase ASCII nonce must be refused rather than replayed as a distinct binary identity");
    assert.equal(runClient("status").SEQ, beforeUppercase,
      "invalid mixed-case nonce must not consume owner sequence or reserve scope");
    const begin1 = runClient("begin", nonce1, "", activeEpoch);
    assert.equal(begin1.STATUS, "0");
    assert.ok(begin1.SCOPE_TOKEN.length > 0);
    const token1 = begin1.SCOPE_TOKEN;

    // Second begin with same nonce MUST FAIL with ERR_NONCE_REPLAY (15)
    const beginReplay = runClient("begin", nonce1, "", activeEpoch);
    assert.equal(beginReplay.STATUS, "15", "Replay of same nonce must fail closed with STATUS 15");

    // 4. SIGN_ACK is ALWAYS disabled until independently verified C1/C4
    // physical provenance, native replay state and signed approval exist.
    // BEGIN is not sufficient authority, even with real sealed FDs+key.
    const denySign = (result, label) => {
      assert.equal(result.STATUS, "22", `${label}: native signing MUST be disabled`);
      assert.equal(result.SIG_B64, "", `${label}: no Ed25519 signature`);
      assert.equal(result.ACK_SHA, "", `${label}: no signed ACK digest`);
      assert.equal(result.ACK_JSON, undefined, `${label}: no ACK payload`);
    };
    denySign(runClient("sign", "00000000000000000000000000000000", "unknown-scope", activeEpoch),
      "sign without BEGIN / fabricated scope");
    denySign(runClient("sign", "11111111111111111111111111111111", token1, activeEpoch),
      "wrong nonce for prepared scope");
    const beforeSign = runClient("status");
    const signOk = runClient("sign", nonce1, token1, activeEpoch);
    denySign(signOk, "valid 4-FD signed ACK candidate");
    denySign(runClient("sign", nonce1, token1, activeEpoch), "duplicate sign");
    assert.equal(runClient("status").SEQ, beforeSign.SEQ,
      "refused SIGN_ACK must not consume a COMMIT/ledger sequence");

    const denySignWithStatus = (result, expectedStatus, label) => {
      assert.equal(result.STATUS, expectedStatus, `${label}: expected status ${expectedStatus}`);
      assert.equal(result.SIG_B64, "", `${label}: no Ed25519 signature`);
      assert.equal(result.ACK_SHA, "", `${label}: no signed ACK digest`);
      assert.equal(result.ACK_JSON, undefined, `${label}: no ACK payload`);
    };

    // 5. Adversarial FD Tests:
    // A: Missing descriptor seal
    const nonceMissingSeal = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const beginSeal = runClient("begin", nonceMissingSeal, "", activeEpoch);
    const signMissingSeal = runClient("sign-missing-seal", nonceMissingSeal, beginSeal.SCOPE_TOKEN, activeEpoch);
    denySignWithStatus(signMissingSeal, "12", "missing FD seal");

    // B: Duplicate descriptor (aliased inode)
    const nonceDup = "cccccccccccccccccccccccccccccccc";
    const beginDup = runClient("begin", nonceDup, "", activeEpoch);
    const signDup = runClient("sign-duplicate-fd", nonceDup, beginDup.SCOPE_TOKEN, activeEpoch);
    denySignWithStatus(signDup, "12", "duplicate descriptor");

    // C: Stream digest corruption
    const nonceCorrupt = "dddddddddddddddddddddddddddddddd";
    const beginCorrupt = runClient("begin", nonceCorrupt, "", activeEpoch);
    const signCorrupt = runClient("sign-corrupt-stream", nonceCorrupt, beginCorrupt.SCOPE_TOKEN, activeEpoch);
    denySignWithStatus(signCorrupt, "13", "corrupted stream digest");

    // D: Forged image ID
    const nonceBadImg = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const beginBadImg = runClient("begin", nonceBadImg, "", activeEpoch);
    const signBadImg = runClient("sign-bad-image", nonceBadImg, beginBadImg.SCOPE_TOKEN, activeEpoch);
    denySignWithStatus(signBadImg, "19", "forged output image");

    // 6. Test Scope Abort
    const nonceAbort = "ffffffffffffffffffffffffffffffff";
    const beginAbort = runClient("begin", nonceAbort, "", activeEpoch);
    assert.equal(beginAbort.STATUS, "0");
    assert.equal(runClient("abort", "11111111111111111111111111111111", beginAbort.SCOPE_TOKEN, activeEpoch).STATUS, "18",
      "ABORT with a foreign nonce must fail before writing a tombstone");
    assert.equal(runClient("abort", nonceAbort.toUpperCase(), beginAbort.SCOPE_TOKEN, activeEpoch).STATUS, "11",
      "ABORT must reject uppercase encoding for the same cryptographic nonce");
    assert.equal(runClient("abort", nonceAbort, beginAbort.SCOPE_TOKEN.toUpperCase(), activeEpoch).STATUS, "20",
      "ABORT must reject noncanonical uppercase scope token without mutating prepared scope");
    assert.equal(runClient("abort", nonceAbort, beginAbort.SCOPE_TOKEN, activeEpoch - 1).STATUS, "16",
      "ABORT from a stale epoch must not consume live prepared scope");
    const abortRes = runClient("abort", nonceAbort, beginAbort.SCOPE_TOKEN, activeEpoch);
    assert.equal(abortRes.STATUS, "0");
    const secondAbort = runClient("abort", nonceAbort, beginAbort.SCOPE_TOKEN, activeEpoch);
    assert.equal(secondAbort.STATUS, "21", "second ABORT must not append duplicate tombstone");
    const unknownAbort = runClient("abort", nonceAbort, "1111111111111111111111111111111111111111111111111111111111111111", activeEpoch);
    assert.equal(unknownAbort.STATUS, "20", "unknown scope must not be accepted as aborted");
    denySign(runClient("sign", nonceAbort, beginAbort.SCOPE_TOKEN, activeEpoch), "sign after ABORT");

    // 7. Test Durable Anti-Replay Across Process Restart
    await stopDaemon(daemonProc);

    // Restart daemon against same ledger
    daemonProc = await startDaemon(true, true);
    const restartStatus = runClient("status");
    assert.equal(restartStatus.STATUS, "0");
    const newEpoch = Number(restartStatus.EPOCH);
    assert.equal(newEpoch, activeEpoch + 1, "Epoch must increment on restart");

    // Stale epoch SIGN_ACK fails epoch check before signing-disabled gate.
    const staleEpochRes = runClient("sign", "99999999999999999999999999999999", "dummy_token", activeEpoch);
    denySignWithStatus(staleEpochRes, "16", "stale epoch SIGN_ACK");

    // Replay of previously committed nonce1 across restart MUST FAIL
    const replayAfterRestart = runClient("begin", nonce1, "", newEpoch);
    assert.equal(replayAfterRestart.STATUS, "15", "Replay of committed nonce after restart must be rejected from durable ledger");

    // Hostile same-UID peer connects but never sends a frame. A serial
    // owner service must time out that connection, serve the NEXT caller,
    // and permit SIGTERM/ledger flock release during a later idle peer.
    const idle = net.createConnection(sockPath);
    await new Promise((resolve, reject) => {
      idle.once("connect", resolve);
      idle.once("error", reject);
    });
    idle.on("error", () => {});
    const started = Date.now();
    assert.equal(runClient("status").STATUS, "0", "idle peer blocked the owner listener");
    assert.ok(Date.now() - started < 5000, "owner serial socket timeout was not bounded");
    idle.destroy();

    const idleOnShutdown = net.createConnection(sockPath);
    await new Promise((resolve, reject) => {
      idleOnShutdown.once("connect", resolve);
      idleOnShutdown.once("error", reject);
    });
    idleOnShutdown.on("error", () => {});

    await stopDaemon(daemonProc);
    idleOnShutdown.destroy();

    // Deliberately corrupt a DISPOSABLE, owner-test-only ledger after
    // terminating its daemon. No production ledger or daemon is touched.
    const ledgerPath = path.join(ledgerDir, "owner_authority_ledger.dat");
    const preserved = fs.readFileSync(ledgerPath);
    const tryCorruptedStartup = (bytes, label) => {
      fs.writeFileSync(ledgerPath, bytes, { mode: 0o600 });
      const result = spawnSync(srvBin, ["--socket", sockPath, "--ledger-dir", ledgerDir,
        "--dev-allow-same-uid", "--key-file", keyFilePath, "--key-id", "test-owner-key-01"],
        { encoding: "utf8", timeout: 3000 });
      assert.equal(result.error, undefined, `${label}: unexpected launch/timeout error`);
      assert.ok(result.status !== null && result.status !== 0,
        `${label}: corrupted ledger unexpectedly opened as a valid owner epoch`);
      assert.doesNotMatch(result.stdout ?? "", /VIRKI_OWNER_AUTHORITY_READY/,
        `${label}: daemon announced readiness for invalid ledger`);
    };
    tryCorruptedStartup(Buffer.concat([preserved, Buffer.from([0x5a])]),
      "torn append-only ledger record");
    const malformed = Buffer.from(preserved);
    const firstTypeOffset = Buffer.byteLength("VIRKI_OWNER_LEDGER_V2\n");
    assert.ok(malformed.length > firstTypeOffset + 4);
    malformed.writeUInt32LE(0xffffffff, firstTypeOffset);
    tryCorruptedStartup(malformed, "unknown ledger record type without torn tail");
    const epochOverflow = Buffer.from(preserved);
    epochOverflow.writeBigUInt64LE(0xffffffffffffffffn, firstTypeOffset + 4);
    tryCorruptedStartup(epochOverflow, "forged first epoch (not an arithmetic-overflow proof)");
    const sequenceOverflow = Buffer.from(preserved);
    sequenceOverflow.writeBigUInt64LE(0xffffffffffffffffn, firstTypeOffset + 12);
    tryCorruptedStartup(sequenceOverflow, "forged first sequence (not an arithmetic-overflow proof)");

    // V20: these records have valid length and individually VALID SHAPES.
    // The earlier scanner accepted several of them because it checked
    // only a monotonically increasing sequence/epoch, not prior PREPARE
    // and once-only terminal state. Each case restores the original bytes.
    const RECORD_BYTES = 4 + 8 + 8 + 65 + 33 + 73 + 4;
    const lastEpoch = BigInt(restartStatus.EPOCH);
    const lastSeq = BigInt(restartStatus.SEQ);
    const makeRecord = (type, {
      epoch = lastEpoch, seq = lastSeq + 1n,
      scope = "1".repeat(64), nonce = "", image = "", status = 0,
    } = {}) => {
      const record = Buffer.alloc(RECORD_BYTES);
      record.writeUInt32LE(type, 0);
      record.writeBigUInt64LE(epoch, 4);
      record.writeBigUInt64LE(seq, 12);
      const put = (value, offset, width) => {
        assert.ok(Buffer.byteLength(value) < width);
        record.write(value, offset, width-1, "ascii");
      };
      put(scope, 20, 65);
      put(nonce, 85, 33);
      put(image, 118, 73);
      record.writeUInt32LE(status, 191);
      return record;
    };
    const corruptWith = (record, label) =>
      tryCorruptedStartup(Buffer.concat([preserved, record]), label);

    corruptWith(makeRecord(3, {status:1}), "shape-valid orphan ABORT without PREPARE");
    corruptWith(makeRecord(2, {
      seq:lastSeq+1n, nonce:"2".repeat(32), image:"sha256:"+"3".repeat(64),
    }), "shape-valid orphan COMMIT without PREPARE");
    corruptWith(makeRecord(1, {
      seq:lastSeq+2n, nonce:"4".repeat(32),
    }), "shape-valid PREPARE sequence gap");
    corruptWith(makeRecord(1, {
      nonce:nonce1,
    }), "reused prior-epoch nonce after restart");
    corruptWith(makeRecord(1, {
      scope:token1, nonce:"5".repeat(32),
    }), "reused prior-epoch scope token after restart");
    const prepare = makeRecord(1, {scope:"6".repeat(64), nonce:"7".repeat(32)});
    const abort = makeRecord(3, {
      scope:"6".repeat(64),seq:lastSeq+2n,status:1,
    });
    tryCorruptedStartup(Buffer.concat([preserved,prepare,abort,abort]),
      "duplicate ABORT terminal record");
    const wrongCommit = makeRecord(2, {
      scope:"6".repeat(64), nonce:"8".repeat(32),
      image:"sha256:"+"9".repeat(64), seq:lastSeq+2n,
    });
    tryCorruptedStartup(Buffer.concat([preserved,prepare,wrongCommit]),
      "COMMIT nonce mismatch for prepared scope");

    const validAbortLedger = Buffer.concat([preserved,prepare,abort]);
    fs.writeFileSync(ledgerPath,validAbortLedger,{mode:0o600});
    const validAbortOwner = await startDaemon(true,true);
    assert.equal(runClient("status").STATUS,"0",
      "control: a legitimate PREPARE→ABORT replay must recover");
    await stopDaemon(validAbortOwner);
    const nonzeroPadding = Buffer.from(validAbortLedger);
    nonzeroPadding[preserved.length + prepare.length + 85 + 1] = 0x41;
    tryCorruptedStartup(nonzeroPadding,
      "shape-valid PREPARE→ABORT with noncanonical NUL padding");

    // A crash after fsyncing the virgin ledger MAGIC but before the first
    // epoch record must recover deterministically. Previous V20 draft could
    // emit seq=1 and then reject its own ledger on the second restart.
    fs.writeFileSync(ledgerPath, Buffer.from("VIRKI_OWNER_LEDGER_V2\n"), { mode: 0o600 });
    let recovered = await startDaemon(true, true);
    const headerOnlyRecovered = runClient("status");
    assert.equal(headerOnlyRecovered.STATUS, "0");
    assert.equal(headerOnlyRecovered.EPOCH, "1", "header-only recovery must begin epoch one");
    assert.equal(headerOnlyRecovered.SEQ, "1001", "header-only recovery must use canonical first sequence");
    await stopDaemon(recovered);
    recovered = await startDaemon(true, true);
    const secondRecovery = runClient("status");
    assert.equal(secondRecovery.STATUS, "0");
    assert.equal(secondRecovery.EPOCH, "2", "header-only recovered ledger must survive second restart");
    assert.equal(secondRecovery.SEQ, "1002", "second restart must advance durable sequence once");
    await stopDaemon(recovered);

    // V17 accepted upper-case nonces on BEGIN and persisted them. V20 must
    // recover that legitimate historical DEV file yet refuse reuse of the
    // same 128-bit nonce under lower-case spelling. This is a synthetic
    // V17-shaped record; no real prior owner signature is asserted.
    const legacyUpper = "ABCDEF0123456789ABCDEF0123456789";
    const legacyRecord = makeRecord(1, {
      epoch:2n, seq:1003n, scope:"b".repeat(64), nonce:legacyUpper,
    });
    fs.appendFileSync(ledgerPath,legacyRecord);
    const migrated = await startDaemon(true, true);
    const migratedState = runClient("status");
    assert.equal(migratedState.STATUS,"0");
    assert.equal(migratedState.EPOCH,"3");
    assert.equal(migratedState.SEQ,"1004");
    assert.equal(runClient("begin",legacyUpper.toLowerCase(),"",3).STATUS,"15",
      "V17 uppercase nonce must fence same binary nonce in V20 lowercase encoding");
    assert.equal(runClient("begin",legacyUpper,"",3).STATUS,"11",
      "new uppercase nonce must remain noncanonical");
    await stopDaemon(migrated);

    // Historical 0e22b29 signed COMMIT used NEW sequence+1 (unlike the
    // V17 static comment). Rebuild its real wire-compatible transaction
    // structure in a disposable ledger; V20 must load and fence its nonce,
    // not reject a legitimate earlier signed epoch's structural history.
    const firstBump = makeRecord(1, {
      epoch:1n,seq:1001n,scope:"EPOCH_ADVANCE",
      nonce:"0".repeat(32),
    });
    const olderPrepare = makeRecord(1, {
      epoch:1n,seq:1002n,scope:"c".repeat(64),nonce:"d".repeat(32),
    });
    const olderCommit = makeRecord(2, {
      epoch:1n,seq:1003n,scope:"c".repeat(64),nonce:"d".repeat(32),
      image:"sha256:"+"e".repeat(64),
    });
    fs.writeFileSync(ledgerPath,Buffer.concat([
      Buffer.from("VIRKI_OWNER_LEDGER_V2\n"),firstBump,olderPrepare,olderCommit,
    ]),{mode:0o600});
    const historical = await startDaemon(true,true);
    assert.equal(runClient("status").EPOCH,"2",
      "legacy valid COMMITTED history must permit fenced restart");
    assert.equal(runClient("status").SEQ,"1004",
      "legacy COMMITTED sequence advances floor before restart epoch bump");
    assert.equal(runClient("begin","d".repeat(32),"",2).STATUS,"15",
      "historical prepared/committed nonce remains spent");
    denySign(runClient("sign","d".repeat(32),"c".repeat(64),2),
      "historical COMMIT is never permission to sign again");
    await stopDaemon(historical);

    // 5. CLI & key-custody fail-closed regressions
    {
      const badKeyFd = spawnSync(srvBin,
        ["--socket", sockPath, "--ledger-dir", ledgerDir, "--dev-allow-same-uid", "--key-fd", "0"],
        { encoding: "utf8", timeout: 3000 });
      assert.notEqual(badKeyFd.status, 0, "--key-fd 0 (stdin) must be rejected");

      const nonNumericKeyFd = spawnSync(srvBin,
        ["--socket", sockPath, "--ledger-dir", ledgerDir, "--dev-allow-same-uid", "--key-fd", "invalid"],
        { encoding: "utf8", timeout: 3000 });
      assert.notEqual(nonNumericKeyFd.status, 0, "non-numeric --key-fd must be rejected");

      const looseKey = path.join(testDir, "loose.key");
      fs.writeFileSync(looseKey, naclSecretKey, { mode: 0o644 });
      const looseKeyRes = spawnSync(srvBin,
        ["--socket", sockPath, "--ledger-dir", ledgerDir, "--dev-allow-same-uid", "--dev-test-v9fs", "--key-file", looseKey],
        { encoding: "utf8", timeout: 3000 });
      assert.notEqual(looseKeyRes.status, 0, "0644 key file must fail closed on non-v9fs even with --dev-test-v9fs");

      const overlongSock = spawnSync(srvBin,
        ["--socket", "/" + "a".repeat(1030), "--ledger-dir", ledgerDir, "--dev-allow-same-uid"],
        { encoding: "utf8", timeout: 3000 });
      assert.notEqual(overlongSock.status, 0, "overlong --socket path must fail closed without truncation");
    }
  } finally {
    await Promise.allSettled([...activeDaemons].map((proc) => stopDaemon(proc)));
    fs.rmSync(testDir, { recursive: true, force: true });
  }
});
