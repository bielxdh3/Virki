import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, linkSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { completeOfflineReleaseAcceptance, recordOfflineReleaseAcceptance, validateOfflineLedgerTransition } from "./lib/offline-release-ledger.mjs";

const predecessor = "a".repeat(40);
const next = "b".repeat(40);
const later = "c".repeat(40);
const digest = "1".repeat(64);
const approval = "2".repeat(64);
const nonce = "3".repeat(32);
const LOCK = ".offline-release.lock";
const FINISHING = ".offline-release.finalizing";
const LEDGER = "ledger.json";
const healthReportSha256 = "7".repeat(64);
const moduleUrl = new URL("./lib/offline-release-ledger.mjs", import.meta.url).href;
// The production guard has no injectable kernel fallback. This isolated test
// switch exercises Linux inode/fsync operations in a Docker Desktop WSL kernel;
// it is not evidence of a native-Linux host rehearsal.
const simulatedNative = process.platform === "linux" &&
  /microsoft|wsl/iu.test(os.release()) && process.env.VIRKI_LEDGER_TEST_SIMULATE_NATIVE === "1";
if (simulatedNative) os.release = () => "linux-ledger-test-only";
const nativeKernel = process.platform === "linux" && !/microsoft|wsl/iu.test(os.release());

function fixture(t) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-offline-ledger-"));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(path.join(directory, LEDGER), JSON.stringify({
    version: 1,
    anchorSha: predecessor,
    entries: [],
  }), { mode: 0o600, flag: "wx" });
  return { directory, manifestSha256: digest, priorSha: predecessor, nextSha: next,
    nonce, sequence: 1, approvalDigest: approval };
}

function state(directory) {
  return JSON.parse(readFileSync(path.join(directory, LEDGER), "utf8"));
}

function assertLatch(directory) {
  assert.equal(lstatSync(path.join(directory, LOCK)).isFile(), true);
  assert.equal(lstatSync(path.join(directory, LOCK)).mode & 0o777, 0o600);
}

function commandScript(extra = "") {
  return `
    ${simulatedNative ? 'import os from "node:os"; os.release = () => "linux-ledger-test-only";' : ""}
    ${extra}
    const { recordOfflineReleaseAcceptance } = await import(${JSON.stringify(moduleUrl)});
    recordOfflineReleaseAcceptance(JSON.parse(process.env.VIRKI_TEST_LEDGER_REQUEST));
  `;
}

function runChild(request, extra = "") {
  return spawnSync(process.execPath, ["--input-type=module", "-e", commandScript(extra)], {
    encoding: "utf8", timeout: 10_000,
    env: { ...process.env, VIRKI_TEST_LEDGER_REQUEST: JSON.stringify(request) },
  });
}

function runCompletionChild(request, extra = "") {
  const code = `
    ${simulatedNative ? 'import os from "node:os"; os.release = () => "linux-ledger-test-only";' : ""}
    ${extra}
    const { completeOfflineReleaseAcceptance } = await import(${JSON.stringify(moduleUrl)});
    completeOfflineReleaseAcceptance(JSON.parse(process.env.VIRKI_TEST_LEDGER_REQUEST));
  `;
  return spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    encoding: "utf8", timeout: 10_000,
    env: { ...process.env, VIRKI_TEST_LEDGER_REQUEST: JSON.stringify({
      ...request, observedActiveSha: request.nextSha, healthReportSha256,
    }) },
  });
}

if (!nativeKernel) {
  test("offline ledger refuses non-native kernel before filesystem mutation", (t) => {
    const request = fixture(t);
    assert.throws(() => recordOfflineReleaseAcceptance(request), /native Linux/iu);
    assert.equal(existsSync(path.join(request.directory, LOCK)), false);
  });

  test("pure transition appends a new monotonic state without mutating predecessor", () => {
    const request = { directory: "/tmp/virki-test-only", manifestSha256: digest, priorSha: predecessor,
      nextSha: next, nonce, sequence: 1, approvalDigest: approval };
    const seed = { version: 1, anchorSha: predecessor, entries: [] };
    const first = validateOfflineLedgerTransition(seed, request);
    assert.deepEqual(seed.entries, []);
    assert.equal(first.entries.length, 1);
    assert.equal(first.entries[0].nextSha, next);
    const second = validateOfflineLedgerTransition(first, {
      ...request, priorSha: next, nextSha: later, sequence: 2,
      nonce: "4".repeat(32), manifestSha256: "5".repeat(64), approvalDigest: "6".repeat(64),
    });
    assert.equal(second.entries.length, 2);
    assert.equal(first.entries.length, 1);
  });

  test("pure transition fails closed on predecessor forgery, replay and dirty history", async (t) => {
    const request = { directory: "/tmp/virki-test-only", manifestSha256: digest, priorSha: predecessor,
      nextSha: next, nonce, sequence: 1, approvalDigest: approval };
    const initial = { version: 1, anchorSha: predecessor, entries: [] };
    const first = validateOfflineLedgerTransition(initial, request);
    const invalid = [
      ["forged predecessor", initial, { ...request, priorSha: "f".repeat(40) }],
      ["out-of-order sequence", initial, { ...request, sequence: 3 }],
      ["stale sequence", first, request],
      ["replayed nonce", first, { ...request, priorSha: next, nextSha: later, sequence: 2 }],
      ["replayed manifest digest", first, { ...request, priorSha: next, nextSha: later, nonce: "4".repeat(32), sequence: 2 }],
      ["replayed approval digest", first, { ...request, priorSha: next, nextSha: later, nonce: "4".repeat(32), manifestSha256: "5".repeat(64), sequence: 2 }],
      ["downgrade to seen SHA", first, { ...request, priorSha: next, nextSha: predecessor, nonce: "4".repeat(32), manifestSha256: "5".repeat(64), approvalDigest: "6".repeat(64), sequence: 2 }],
      ["broken historical chain", { ...first, entries: [{ ...first.entries[0], priorSha: "f".repeat(40) }] }, { ...request, priorSha: next, nextSha: later, nonce: "4".repeat(32), manifestSha256: "5".repeat(64), approvalDigest: "6".repeat(64), sequence: 2 }],
      ["unknown history field", { ...first, extra: true }, { ...request, priorSha: next, nextSha: later, nonce: "4".repeat(32), manifestSha256: "5".repeat(64), approvalDigest: "6".repeat(64), sequence: 2 }],
    ];
    for (const [name, stateValue, requestValue] of invalid) {
      await t.test(name, () => assert.throws(() => validateOfflineLedgerTransition(stateValue, requestValue)));
    }
  });

  test.skip("native filesystem, O_EXCL concurrency, fsync, and SIGKILL integration require non-WSL Linux kernel");
} else {
  test("runtime native-Linux guard rejects WSL kernel before taking a lock", (t) => {
    const request = fixture(t);
    const oldRelease = os.release;
    try {
      os.release = () => "6.18.33.1-microsoft-standard-WSL2";
      assert.throws(() => recordOfflineReleaseAcceptance(request), /native Linux/iu);
      assert.equal(existsSync(path.join(request.directory, LOCK)), false);
    } finally {
      os.release = oldRelease;
    }
  });

  test("durably records an attempted release, blocks next release until independently confirmed completion", (t) => {
    const request = fixture(t);
    const result = recordOfflineReleaseAcceptance(request);
    assert.deepEqual(Object.keys(result).sort(), ["pendingSha", "sequence", "status"].sort());
    assert.equal(result.sequence, 1);
    assert.equal(result.pendingSha, next);
    assert.equal(result.status, "attempted");
    assert.equal(state(request.directory).entries.length, 0);
    assertLatch(request.directory);
    const followOn = { ...request, priorSha: next, nextSha: later, sequence: 2,
      nonce: "4".repeat(32), approvalDigest: "5".repeat(64), manifestSha256: "6".repeat(64) };
    assert.throws(() => recordOfflineReleaseAcceptance(followOn));
    assert.equal(state(request.directory).entries.length, 0);
    assert.equal(completeOfflineReleaseAcceptance({ ...request, observedActiveSha: next,
      healthReportSha256 }).status, "completed");
    assert.deepEqual(state(request.directory).entries[0], {
      sequence: 1, priorSha: predecessor, nextSha: next, manifestSha256: digest,
      nonce, approvalDigest: approval,
    });
    assert.equal(existsSync(path.join(request.directory, LOCK)), false);
    assert.equal(existsSync(path.join(request.directory, FINISHING)), false);
    assert.deepEqual(readdirSync(request.directory), [LEDGER]);
    assert.equal(lstatSync(path.join(request.directory, LEDGER)).mode & 0o777, 0o600);
    assert.equal(lstatSync(path.join(request.directory, LEDGER)).uid, process.getuid());
    assert.equal(recordOfflineReleaseAcceptance(followOn).sequence, 2);
    assert.equal(state(request.directory).entries.length, 1);
    assertLatch(request.directory);
  });

  test("a successful recorder process followed by crash before activation keeps new attempts blocked", (t) => {
    const request = fixture(t);
    const child = runChild(request);
    assert.equal(child.status, 0, child.stderr);
    assert.equal(state(request.directory).entries.length, 0);
    assertLatch(request.directory);
    assert.throws(() => recordOfflineReleaseAcceptance({ ...request, priorSha: next,
      nextSha: later, sequence: 2, nonce: "4".repeat(32),
      approvalDigest: "5".repeat(64), manifestSha256: "6".repeat(64) }));
  });

  test("completion refuses forged health or identity without consuming pending approval", (t) => {
    const request = fixture(t);
    recordOfflineReleaseAcceptance(request);
    for (const changes of [{ observedActiveSha: predecessor, healthReportSha256 },
      { observedActiveSha: next, healthReportSha256: "unverified" },
      { observedActiveSha: next, healthReportSha256, manifestSha256: "f".repeat(64) }]) {
      assert.throws(() => completeOfflineReleaseAcceptance({ ...request, ...changes }));
      assert.equal(state(request.directory).entries.length, 0);
      assertLatch(request.directory);
    }
  });

  test("rejects unsafe argument shapes before creating any lock", async (t) => {
    const request = fixture(t);
    const malicious = [
      { directory: null }, { directory: "../relative" }, { priorSha: "A".repeat(40) },
      { nextSha: predecessor }, { nextSha: "0".repeat(12) }, { manifestSha256: "bad" },
      { nonce: "A".repeat(32) }, { sequence: 0 }, { sequence: 1.5 },
      { approvalDigest: "0".repeat(20) },
    ];
    for (const [index, replacement] of malicious.entries()) {
      await t.test(`input ${index}`, () => {
        assert.throws(() => recordOfflineReleaseAcceptance({ ...request, ...replacement }));
        assert.equal(existsSync(path.join(request.directory, LOCK)), false);
      });
    }
  });

  test("refuses symlinked ledger directory without following it", (t) => {
    const request = fixture(t);
    const alias = `${request.directory}-alias`;
    symlinkSync(request.directory, alias, "dir");
    t.after(() => rmSync(alias, { force: true }));
    assert.throws(() => recordOfflineReleaseAcceptance({ ...request, directory: alias }));
    assert.equal(existsSync(path.join(request.directory, LOCK)), false);
  });

  test("refuses a symlinked lock without removing or following it", (t) => {
    const request = fixture(t);
    const victim = path.join(request.directory, "victim");
    writeFileSync(victim, "untouched", { mode: 0o600 });
    symlinkSync(victim, path.join(request.directory, LOCK));
    assert.throws(() => recordOfflineReleaseAcceptance(request));
    assert.equal(readFileSync(victim, "utf8"), "untouched");
    assert.equal(lstatSync(path.join(request.directory, LOCK)).isSymbolicLink(), true);
  });

  test("refuses symlinked or hard-linked ledger files and keeps lock latched", async (t) => {
    for (const type of ["symlink", "hardlink"]) {
      await t.test(type, (t2) => {
        const request = fixture(t2);
        const payload = readFileSync(path.join(request.directory, LEDGER));
        const victim = path.join(request.directory, "trusted-seed");
        writeFileSync(victim, payload, { mode: 0o600 });
        rmSync(path.join(request.directory, LEDGER));
        if (type === "symlink") symlinkSync(victim, path.join(request.directory, LEDGER));
        else linkSync(victim, path.join(request.directory, LEDGER));
        assert.throws(() => recordOfflineReleaseAcceptance(request));
        assertLatch(request.directory);
        assert.equal(readFileSync(victim).equals(payload), true);
      });
    }
  });

  test("refuses owner-unsafe directory, ledger or unreadable seed", async (t) => {
    for (const type of ["directory", "ledger", "absent", "noncanonical", "extra-file"]) {
      await t.test(type, (t2) => {
        const request = fixture(t2);
        if (type === "directory") chmodSync(request.directory, 0o750);
        if (type === "ledger") chmodSync(path.join(request.directory, LEDGER), 0o640);
        if (type === "absent") rmSync(path.join(request.directory, LEDGER));
        if (type === "noncanonical") writeFileSync(path.join(request.directory, LEDGER), '{"version":1,"entries":[],"anchorSha":"' + predecessor + '"}');
        if (type === "extra-file") writeFileSync(path.join(request.directory, "unrelated.txt"), "not accepted");
        assert.throws(() => recordOfflineReleaseAcceptance(request));
        if (type !== "directory") assertLatch(request.directory);
      });
    }
  });

  test("forged predecessor, skipped or replayed sequence latch without advancing state", async (t) => {
    for (const [name, changes] of [
      ["forged predecessor", { priorSha: "f".repeat(40) }],
      ["skipped sequence", { sequence: 3 }],
    ]) {
      await t.test(name, (t2) => {
        const request = fixture(t2);
        assert.throws(() => recordOfflineReleaseAcceptance({ ...request, ...changes }));
        assert.equal(state(request.directory).entries.length, 0);
        assertLatch(request.directory);
      });
    }
    await t.test("stale sequence after a prior success", (t2) => {
      const request = fixture(t2);
      recordOfflineReleaseAcceptance(request);
      completeOfflineReleaseAcceptance({ ...request, observedActiveSha: next, healthReportSha256 });
      assert.throws(() => recordOfflineReleaseAcceptance(request));
      assert.equal(state(request.directory).entries.length, 1);
      assertLatch(request.directory);
    });
    for (const type of ["replayed nonce", "reused earlier SHA", "replayed approval digest", "replayed manifest digest"]) {
      await t.test(type, (t2) => {
        const request = fixture(t2);
        recordOfflineReleaseAcceptance(request);
        completeOfflineReleaseAcceptance({ ...request, observedActiveSha: next, healthReportSha256 });
        const laterRequest = {
          ...request, priorSha: next, nextSha: later, sequence: 2,
          nonce: "4".repeat(32), approvalDigest: "5".repeat(64), manifestSha256: "6".repeat(64),
        };
        if (type === "replayed nonce") laterRequest.nonce = nonce;
        if (type === "reused earlier SHA") laterRequest.nextSha = predecessor;
        if (type === "replayed approval digest") laterRequest.approvalDigest = approval;
        if (type === "replayed manifest digest") laterRequest.manifestSha256 = digest;
        assert.throws(() => recordOfflineReleaseAcceptance(laterRequest));
        assert.equal(state(request.directory).entries.length, 1);
        assertLatch(request.directory);
      });
    }
  });

  test("exclusive lock permits only one competing native-Linux process", async (t) => {
    const request = fixture(t);
    const children = Array.from({ length: 2 }, () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", commandScript()], {
        env: { ...process.env, VIRKI_TEST_LEDGER_REQUEST: JSON.stringify(request) },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal, stderr }));
    }));
    const observed = await Promise.all(children);
    assert.equal(observed.filter(({ code }) => code === 0).length, 1, JSON.stringify(observed));
    assert.equal(observed.filter(({ code }) => code !== 0).length, 1);
    assert.equal(state(request.directory).entries.length, 0);
    assertLatch(request.directory);
  });

  test("SIGKILL during attempt journal write keeps previous ledger and durable fail-closed latch", (t) => {
    const request = fixture(t);
    const child = runChild(request, `
      import fs from "node:fs";
      import { syncBuiltinESMExports } from "node:module";
      const originalWrite = fs.writeSync;
      let writes = 0;
      fs.writeSync = (fd, ...args) => {
        writes += 1;
        if (writes === 1) {
          originalWrite(fd, Buffer.from("partial"));
          process.kill(process.pid, "SIGKILL");
        }
        return originalWrite(fd, ...args);
      };
      syncBuiltinESMExports();
    `);
    assert.equal(child.signal, "SIGKILL", `child unexpectedly exited: ${child.status} ${child.stderr}`);
    assert.equal(state(request.directory).entries.length, 0);
    assertLatch(request.directory);
    assert.equal(readdirSync(request.directory).includes(LOCK), true);
    assert.throws(() => recordOfflineReleaseAcceptance(request));
    assert.equal(state(request.directory).entries.length, 0);
  });

  test("SIGKILL while finalizing cannot silently advance the release or remove the latch", (t) => {
    const request = fixture(t);
    recordOfflineReleaseAcceptance(request);
    const child = runCompletionChild(request, `
      import fs from "node:fs";
      import { syncBuiltinESMExports } from "node:module";
      fs.renameSync = () => process.kill(process.pid, "SIGKILL");
      syncBuiltinESMExports();
    `);
    assert.equal(child.signal, "SIGKILL", child.stderr);
    assert.equal(state(request.directory).entries.length, 0);
    assertLatch(request.directory);
    assert.equal(existsSync(path.join(request.directory, FINISHING)), true);
    assert.throws(() => completeOfflineReleaseAcceptance({ ...request,
      observedActiveSha: next, healthReportSha256 }));
    assert.throws(() => recordOfflineReleaseAcceptance({ ...request, priorSha: next,
      nextSha: later, sequence: 2, nonce: "4".repeat(32),
      approvalDigest: "5".repeat(64), manifestSha256: "6".repeat(64) }));
  });

  test("SIGKILL after durable ledger rename but before unlock leaves manual recovery latch", (t) => {
    const request = fixture(t);
    recordOfflineReleaseAcceptance(request);
    const child = runCompletionChild(request, `
      import fs from "node:fs";
      import { syncBuiltinESMExports } from "node:module";
      fs.unlinkSync = () => process.kill(process.pid, "SIGKILL");
      syncBuiltinESMExports();
    `);
    assert.equal(child.signal, "SIGKILL", child.stderr);
    assert.equal(state(request.directory).entries.length, 1);
    assertLatch(request.directory);
    assert.equal(existsSync(path.join(request.directory, FINISHING)), true);
    assert.throws(() => recordOfflineReleaseAcceptance({ ...request, priorSha: next,
      nextSha: later, sequence: 2, nonce: "4".repeat(32),
      approvalDigest: "5".repeat(64), manifestSha256: "6".repeat(64) }));
  });

  test("a persisted lock or partial transaction is never automatically deleted", (t) => {
    const request = fixture(t);
    writeFileSync(path.join(request.directory, LOCK), "unresolved", { mode: 0o600 });
    assert.throws(() => recordOfflineReleaseAcceptance(request));
    assertLatch(request.directory);
    assert.equal(state(request.directory).entries.length, 0);
  });

  test("ledger rejects tampered history and bogus follow-on chronology", (t) => {
    const request = fixture(t);
    const file = path.join(request.directory, LEDGER);
    writeFileSync(file, JSON.stringify({
      version: 1, anchorSha: predecessor,
      entries: [{ sequence: 1, priorSha: "f".repeat(40), nextSha: next, manifestSha256: digest, nonce, approvalDigest: approval }],
    }));
    assert.throws(() => recordOfflineReleaseAcceptance({ ...request, sequence: 2, priorSha: next, nextSha: later }));
    assertLatch(request.directory);
  });
}
