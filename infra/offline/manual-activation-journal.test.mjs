import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  createDisposableManualActivationJournal, inspectDisposableManualActivationJournal,
  persistDisposableManualActivationIntent, persistDisposableManualActivationCompletion,
} from "./manual-activation-journal.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const fixtureOnly = { skip: process.platform !== "linux" ||
  process.getuid?.() !== 0 || !/microsoft|wsl/iu.test(os.release()) };
const genesis = () => ({
  version: 1, attemptId: "c".repeat(32), hostIdentitySha256: "a".repeat(64),
  manifestSha256: "b".repeat(64), sequence: 0, receiptSha256: "d".repeat(64),
  completed: [], pending: null, previousDigest: "0".repeat(64),
});
function withFixture(run) {
  const directory = mkdtempSync(path.join("/dev/shm", "virki-manual-activation-fixture-"));
  chmodSync(directory, 0o700);
  try { return run(directory); } finally { rmSync(directory, { recursive: true, force: true }); }
}
function prepared(prev) {
  const previousDigest = hash(JSON.stringify(prev));
  return { ...prev, previousDigest, pending: {
    stage: "fence-writers", sequence: 1,
    ownerApprovalSha256: "e".repeat(64),
    witnessReceiptSha256: "f".repeat(64), previousDigest,
  } };
}
function completed(pending) {
  return { ...pending, sequence: 1, receiptSha256: pending.pending.witnessReceiptSha256,
    completed: [{ stage: "fence-writers", result: "completed", snapshotSha256: "1".repeat(64) }],
    pending: null, previousDigest: hash(JSON.stringify(pending)),
  };
}

test("RED: persist exclusive intent before mutation; restart sees pending and refuses retry", fixtureOnly, () => withFixture((directory) => {
  const start = genesis();
  assert.equal(createDisposableManualActivationJournal({ directory, checkpoint: start }).status,
    "DISPOSABLE_JOURNAL_CREATED_NONAUTHORIZING");
  assert.equal(persistDisposableManualActivationIntent({ directory, checkpoint: prepared(start) }).status,
    "DISPOSABLE_INTENT_DURABLE_NONAUTHORIZING");
  assert.equal(inspectDisposableManualActivationJournal({ directory }).status,
    "DISPOSABLE_PENDING_OPERATOR_RECONCILIATION");
  assert.throws(() => persistDisposableManualActivationIntent({ directory, checkpoint: prepared(start) }));
  assert.throws(() => createDisposableManualActivationJournal({ directory, checkpoint: start }));
}));

test("RED: only matching completion advances; no rollback of committed state", fixtureOnly, () => withFixture((directory) => {
  const start = genesis();
  createDisposableManualActivationJournal({ directory, checkpoint: start });
  const intent = prepared(start);
  persistDisposableManualActivationIntent({ directory, checkpoint: intent });
  assert.throws(() => persistDisposableManualActivationCompletion({ directory,
    checkpoint: { ...completed(intent), receiptSha256: "2".repeat(64) } }));
  assert.equal(persistDisposableManualActivationCompletion({ directory,
    checkpoint: completed(intent) }).status, "DISPOSABLE_COMMIT_DURABLE_NONAUTHORIZING");
  assert.equal(inspectDisposableManualActivationJournal({ directory }).status,
    "DISPOSABLE_COMMITTED_NONAUTHORIZING");
  assert.throws(() => persistDisposableManualActivationCompletion({ directory, checkpoint: completed(intent) }));
}));

test("RED: manual edits, symlink and wrong-root fixture are refused", fixtureOnly, () => withFixture((directory) => {
  const start = genesis();
  createDisposableManualActivationJournal({ directory, checkpoint: start });
  assert.throws(() => createDisposableManualActivationJournal({ directory: "/dev/shm", checkpoint: start }));
  const filename = path.join(directory, "00000000.complete");
  writeFileSync(filename, JSON.stringify({ state: "forged" }));
  assert.throws(() => inspectDisposableManualActivationJournal({ directory }));
  assert.throws(() => persistDisposableManualActivationIntent({ directory, checkpoint: prepared(start) }));
}));

test("RED: noncanonical and unreviewed file cannot silently reset a pending intent", fixtureOnly, () => withFixture((directory) => {
  const start = genesis();
  createDisposableManualActivationJournal({ directory, checkpoint: start });
  persistDisposableManualActivationIntent({ directory, checkpoint: prepared(start) });
  writeFileSync(path.join(directory, "operator-reset"), "yes");
  assert.throws(() => inspectDisposableManualActivationJournal({ directory }));
  assert.throws(() => persistDisposableManualActivationCompletion({ directory,
    checkpoint: completed(prepared(start)) }));
}));
