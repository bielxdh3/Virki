import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { inventoryBackupDirectory } from "./backup-retention-inventory.mjs";

const revision = "a".repeat(40);
const backupName = "bielos-20261003-120000-a1b2c3.dump";

async function withInventoryFixture(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), "bielos-backup-inventory-"));
  try {
    await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function fakeStatfs(availablePercent) {
  return async () => ({ blocks: 100, bsize: 1024, bavail: availablePercent });
}

test("inventory preserves every backup and identifies only a hash-matching current restore marker", async () => {
  await withInventoryFixture(async (root) => {
    const contents = Buffer.from("disposable backup fixture");
    const digest = createHash("sha256").update(contents).digest("hex");
    await writeFile(path.join(root, backupName), contents, { mode: 0o600 });
    await writeFile(path.join(root, "bielos-20261002-120000-d4e5f6.dump"), "older backup", { mode: 0o600 });
    await writeFile(path.join(root, ".bielos-partial.dump.partial"), "partial", { mode: 0o600 });
    await writeFile(path.join(root, "operator-note.txt"), "unknown files remain untouched", { mode: 0o600 });
    await writeFile(path.join(root, ".bielos-migration-verification"), [
      `revision=${revision}`,
      `backup_name=${backupName}`,
      `backup_sha256=${digest}`,
      "verified_at=2026-10-03T12:00:00Z",
      "",
    ].join("\n"), { mode: 0o600 });

    const inventory = await inventoryBackupDirectory(root, { now: Date.parse("2026-10-03T12:30:00Z"), getStatfs: fakeStatfs(60) });
    assert.equal(inventory.readOnly, true);
    assert.equal(inventory.deletionCapability, false);
    assert.deepEqual(inventory.retentionPlan.plannedDeletions, []);
    if (process.platform === "win32") {
      assert.equal(inventory.verificationMarker.status, "unsafe");
      assert.equal(inventory.verificationMarker.currentForNextDeployment, false);
    } else {
      assert.equal(inventory.verificationMarker.status, "present");
      assert.equal(inventory.verificationMarker.currentForNextDeployment, true);
    }
    assert.equal(inventory.disk.pressureAlert, false);
    const expectedVerifiedClassification = process.platform === "win32" ? "backup_without_durable_verification" : "matches_current_verification_marker";
    assert.deepEqual(inventory.files.map((file) => file.classification).sort(), [
      "backup_without_durable_verification",
      expectedVerifiedClassification,
      "partial_or_temporary",
      "unknown_file",
    ]);
    assert.ok(inventory.files.every((file) => file.action === "PRESERVE"));
    assert.equal(await readFile(path.join(root, backupName), "utf8"), contents.toString());
  });
});

test("stale, mismatched and malformed verification evidence never makes a backup a deletion candidate", async () => {
  await withInventoryFixture(async (root) => {
    await writeFile(path.join(root, backupName), "unmatched bytes", { mode: 0o600 });
    const wrongDigest = "b".repeat(64);
    await writeFile(path.join(root, ".bielos-migration-verification"), [
      `revision=${revision}`,
      `backup_name=${backupName}`,
      `backup_sha256=${wrongDigest}`,
      "verified_at=2026-10-01T12:00:00Z",
      "",
    ].join("\n"), { mode: 0o600 });

    const inventory = await inventoryBackupDirectory(root, { now: Date.parse("2026-10-03T12:00:00Z"), getStatfs: fakeStatfs(70) });
    assert.equal(inventory.verificationMarker.status, process.platform === "win32" ? "unsafe" : "unmatched");
    assert.equal(inventory.verificationMarker.currentForNextDeployment, false);
    assert.equal(inventory.files[0].classification, process.platform === "win32" ? "backup_without_durable_verification" : "verification_hash_mismatch");
    assert.deepEqual(inventory.retentionPlan.plannedDeletions, []);
  });
});

test("a stale but hash-matching record stays retained and is flagged as unsuitable for the next deployment", { skip: process.platform === "win32" ? "Windows does not expose the POSIX owner-only mode required by the production marker." : false }, async () => {
  await withInventoryFixture(async (root) => {
    const contents = "previously restore-validated fixture";
    const digest = createHash("sha256").update(contents).digest("hex");
    await writeFile(path.join(root, backupName), contents, { mode: 0o600 });
    await writeFile(path.join(root, ".bielos-migration-verification"), [
      `revision=${revision}`,
      `backup_name=${backupName}`,
      `backup_sha256=${digest}`,
      "verified_at=2026-09-30T12:00:00Z",
      "",
    ].join("\n"), { mode: 0o600 });

    const inventory = await inventoryBackupDirectory(root, { now: Date.parse("2026-10-03T12:00:00Z"), getStatfs: fakeStatfs(50) });
    assert.equal(inventory.verificationMarker.status, "present");
    assert.equal(inventory.verificationMarker.currentForNextDeployment, false);
    assert.equal(inventory.files[0].classification, "matches_current_verification_marker");
    assert.deepEqual(inventory.retentionPlan.plannedDeletions, []);
  });
});

test("symlinks and backup candidates whose verification restore was not completed are preserved", { skip: process.platform === "win32" ? "Creating filesystem symlinks requires Windows privilege or Developer Mode." : false }, async () => {
  await withInventoryFixture(async (root) => {
    const external = path.join(root, "outside.txt");
    await writeFile(external, "outside fixture");
    await symlink(external, path.join(root, "bielos-20261003-120001-abcdef.dump"));
    await writeFile(path.join(root, "bielos-20261003-120002-abcdef.dump"), "backup without marker", { mode: 0o600 });

    const inventory = await inventoryBackupDirectory(root, { getStatfs: fakeStatfs(60) });
    assert.ok(inventory.files.some((file) => file.classification === "symlink" && file.action === "PRESERVE"));
    assert.ok(inventory.files.some((file) => file.classification === "backup_without_durable_verification"));
    assert.equal(await readFile(external, "utf8"), "outside fixture");
  });
});

test("low filesystem capacity raises an alert without changing any files", async () => {
  await withInventoryFixture(async (root) => {
    await writeFile(path.join(root, backupName), "fixture", { mode: 0o600 });
    const inventory = await inventoryBackupDirectory(root, { getStatfs: fakeStatfs(5) });
    assert.equal(inventory.disk.pressureAlert, true);
    assert.deepEqual(inventory.retentionPlan.plannedDeletions, []);
    assert.equal(await readFile(path.join(root, backupName), "utf8"), "fixture");
  });
});

test("inventory rejects relative directories, symlink roots and unsafe marker files", async () => {
  await assert.rejects(inventoryBackupDirectory("relative/backups"), /absolute backup inventory directory/u);
  await withInventoryFixture(async (root) => {
    await mkdir(path.join(root, "folder.dump"));
    await writeFile(path.join(root, ".bielos-migration-verification"), "revision=not-safe", { mode: 0o600 });
    const inventory = await inventoryBackupDirectory(root, { getStatfs: fakeStatfs(60) });
    assert.equal(inventory.verificationMarker.status, "unsafe");
    assert.deepEqual(inventory.retentionPlan.plannedDeletions, []);
  });
});

test("inventory rejects a symlink root", { skip: process.platform === "win32" ? "Creating filesystem symlinks requires Windows privilege or Developer Mode." : false }, async () => {
  await withInventoryFixture(async (root) => {
    const parent = path.dirname(root);
    const link = path.join(parent, `${path.basename(root)}-link`);
    try {
      await symlink(root, link, "dir");
      await assert.rejects(inventoryBackupDirectory(link), /real directory/u);
    } finally {
      await rm(link, { force: true, recursive: true });
    }
  });
});

test("inventory rejects a symlink verification marker", { skip: process.platform === "win32" ? "Creating filesystem symlinks requires Windows privilege or Developer Mode." : false }, async () => {
  await withInventoryFixture(async (root) => {
    await mkdir(path.join(root, "folder.dump"));
    await symlink(path.join(root, "folder.dump"), path.join(root, ".bielos-migration-verification"), "file");
    const inventory = await inventoryBackupDirectory(root, { getStatfs: fakeStatfs(60) });
    assert.equal(inventory.verificationMarker.status, "unsafe");
    assert.deepEqual(inventory.retentionPlan.plannedDeletions, []);
  });
});
