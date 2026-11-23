import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";

import {
  appendAuthStateTransition,
  initAnchoredAuthState,
  loadAndVerifyAuthState,
} from "./c1-c4-contract.mjs";

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-c1-c4-fsync-fault-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "state.json");
  initAnchoredAuthState(file, "a".repeat(40));
  return file;
}

function prepare(file, nonce = "1".repeat(32)) {
  return appendAuthStateTransition(file, {
    epoch: 1,
    nonce,
    contractSha256: "b".repeat(64),
    status: "PREPARED",
  });
}

function failParentSyncWhen(file, condition, action) {
  const original = fs.fsyncSync;
  let injected = false;
  fs.fsyncSync = (fd) => {
    if (!injected && fs.fstatSync(fd).isDirectory() &&
      JSON.parse(fs.readFileSync(file, "utf8")).sequenceFloor === 1 && condition()) {
      injected = true;
      const error = new Error("SYNTHETIC_POST_RENAME_PARENT_FSYNC_EIO");
      error.code = "EIO";
      throw error;
    }
    return original(fd);
  };
  syncBuiltinESMExports();
  try {
    assert.throws(action, (error) =>
      error?.message?.includes("SYNTHETIC_POST_RENAME_PARENT_FSYNC_EIO") ||
      error?.errors?.some((inner) => inner?.message?.includes("SYNTHETIC_POST_RENAME_PARENT_FSYNC_EIO")) === true);
  } finally {
    fs.fsyncSync = original;
    syncBuiltinESMExports();
  }
  assert.equal(injected, true, "fault must happen after the new state has been renamed, not before the write");
}

function assertAmbiguityFenced(file) {
  assert.ok(fs.lstatSync(`${file}.pending`).isFile(), "durable ambiguous-transition marker must remain");
  assert.throws(() => loadAndVerifyAuthState(file), /pending|ambiguous|reconciliation/u);
  assert.throws(() => prepare(file, "2".repeat(32)), /pending|ambiguous|reconciliation/u,
    "a different valid DEV authorization must not be accepted after ambiguous fsync");
}

function failGenesisSyncWhen(t, condition) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-c1-c4-genesis-fsync-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "state.json");
  const original = fs.fsyncSync;
  let injected = false;
  fs.fsyncSync = (fd) => {
    let ready = false;
    if (!injected && fs.fstatSync(fd).isDirectory() && fs.existsSync(file)) {
      try { ready = JSON.parse(fs.readFileSync(file, "utf8")).sequenceFloor === 0; }
      catch { /* An unfinished empty reservation is not yet an auth state. */ }
    }
    if (ready && condition(file)) {
      injected = true;
      const error = new Error("SYNTHETIC_GENESIS_PARENT_FSYNC_EIO");
      error.code = "EIO";
      throw error;
    }
    return original(fd);
  };
  syncBuiltinESMExports();
  try {
    assert.throws(() => initAnchoredAuthState(file, "a".repeat(40)),
      /SYNTHETIC_GENESIS_PARENT_FSYNC_EIO/u);
  } finally {
    fs.fsyncSync = original;
    syncBuiltinESMExports();
  }
  assert.equal(injected, true, "genesis fault must follow a complete but not durably committed initial state");
  assert.equal(fs.existsSync(file), true, "the initial file was created before the injected sync failure");
  assertAmbiguityFenced(file);
}

test("C1->C4 DEV genesis parent fsync EIO leaves a durable intent and refuses future reads/writes", {
  skip: process.platform !== "linux",
}, (t) => failGenesisSyncWhen(t, () => true));

test("C1->C4 DEV genesis post-unlink fsync EIO reinstates the recovery marker", {
  skip: process.platform !== "linux",
}, (t) => failGenesisSyncWhen(t, (file) => !fs.existsSync(`${file}.pending`)));

test("C1->C4 DEV initialization never overwrites an already initialized state", (t) => {
  const file = fixture(t);
  assert.throws(() => initAnchoredAuthState(file, "c".repeat(40)), { code: "EEXIST" });
  assert.equal(loadAndVerifyAuthState(file).anchorSha, "a".repeat(40));
  assert.equal(fs.existsSync(`${file}.pending`), false);
});

test("C1->C4 DEV state refuses later transitions after post-rename directory fsync EIO", {
  skip: process.platform !== "linux",
}, (t) => {
  const file = fixture(t);
  failParentSyncWhen(file, () => true, () => prepare(file));
  assertAmbiguityFenced(file);
});

test("C1->C4 DEV state reestablishes the recovery marker when final marker-unlink fsync fails", {
  skip: process.platform !== "linux",
}, (t) => {
  const file = fixture(t);
  failParentSyncWhen(file, () => !fs.existsSync(`${file}.pending`), () => prepare(file));
  assertAmbiguityFenced(file);
});

test("C1->C4 DEV ambiguous-fsync marker recovery atomically replaces a substituted dangling symlink", {
  skip: process.platform !== "linux",
}, (t) => {
  const file = fixture(t);
  failParentSyncWhen(file, () => {
    if (fs.existsSync(`${file}.pending`)) return false;
    fs.symlinkSync(`${file}.not-found`, `${file}.pending`);
    return true;
  }, () => prepare(file));
  assertAmbiguityFenced(file);
});

test("C1->C4 DEV state can finish normal transitions without stale ambiguity markers", (t) => {
  const file = fixture(t);
  prepare(file);
  prepare(file, "2".repeat(32));
  assert.equal(loadAndVerifyAuthState(file).sequenceFloor, 2);
  assert.equal(fs.existsSync(`${file}.pending`), false);
});

test("C1->C4 DEV state refuses read and mutation after a writer exits with a durable pending intent", {
  skip: process.platform !== "linux",
}, (t) => {
  const file = fixture(t);
  const code = `
    import fs from "node:fs";
    import { syncBuiltinESMExports } from "node:module";
    import { appendAuthStateTransition } from ${JSON.stringify(new URL("./c1-c4-contract.mjs", import.meta.url).href)};
    const statePath = process.argv[1];
    const original = fs.fsyncSync;
    fs.fsyncSync = (fd) => {
      if (fs.fstatSync(fd).isDirectory() && fs.existsSync(statePath + ".pending") &&
        JSON.parse(fs.readFileSync(statePath, "utf8")).sequenceFloor === 0) process.exit(79);
      return original(fd);
    };
    syncBuiltinESMExports();
    appendAuthStateTransition(statePath, { epoch: 1, nonce: "3".repeat(32), contractSha256: "b".repeat(64), status: "PREPARED" });
  `;
  const child = spawnSync(process.execPath, ["--input-type=module", "--eval", code, file], { encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 79, `expected injected process exit, not a normal mutation: ${child.stderr}`);
  assert.ok(fs.lstatSync(`${file}.pending`).isFile());
  assert.throws(() => loadAndVerifyAuthState(file), /pending|ambiguous|reconciliation/u);
  assert.throws(() => prepare(file), /pending|ambiguous|reconciliation/u);
});

test("C1->C4 DEV state refuses a substituted or dangling ambiguous-intent marker", {
  skip: process.platform !== "linux",
}, (t) => {
  const file = fixture(t);
  const pending = `${file}.pending`;
  fs.symlinkSync(path.join(path.dirname(file), "nonexistent-marker-target"), pending);
  assert.throws(() => loadAndVerifyAuthState(file), /pending|ambiguous|reconciliation/u);
  assert.throws(() => prepare(file), /pending|ambiguous|reconciliation/u);
});
