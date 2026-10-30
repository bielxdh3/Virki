import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  inspectProtectedManualPgRollback, nativePgRollbackRuntimeEligibility,
} from "./native-manual-pg-rollback-preflight.mjs";

// Do NOT launch root Node from a checkout, including WSL/DrvFS. Even a skip
// executes after Node has loaded the test module. Native root testing requires
// a separately verified owner-installed copy at a fixed root-private path.
const TRUSTED_ROOT_TEST = "/usr/local/lib/virki/offline-release/infra/offline/native-manual-pg-rollback-preflight.test.mjs";
const LINUX_ROOT = { skip: process.platform !== "linux" || process.getuid?.() !== 0 ||
  process.geteuid?.() !== 0 || /microsoft|wsl/iu.test(os.release()) ||
  fileURLToPath(import.meta.url) !== TRUSTED_ROOT_TEST };

test("nonroot contract: WSL, wrong effective root and mutable checkout cannot be a native rollback verifier", () => {
  const installed = "/usr/local/lib/virki/offline-release/infra/offline/native-manual-pg-rollback-preflight.mjs";
  const valid = { platform: "linux", arch: "x64", uid: 0, euid: 0, gid: 0,
    egid: 0, kernelRelease: "6.9.0-native", entryPath: installed };
  assert.equal(nativePgRollbackRuntimeEligibility(valid), true,
    "identity/OS/path eligibility is NOT proof of an owner-installed trusted loader");
  for (const change of [
    { kernelRelease: "5.15.153-microsoft-standard-WSL2" },
    { kernelRelease: "6.6.0-wsl" },
    { platform: "win32" }, { arch: "arm64" },
    { uid: 1000 }, { euid: 1000 }, { gid: 1000 }, { egid: 1000 },
    { entryPath: "/mnt/e/Virki/infra/offline/native-manual-pg-rollback-preflight.mjs" },
    { entryPath: "/tmp/native-manual-pg-rollback-preflight.mjs" },
  ]) assert.equal(nativePgRollbackRuntimeEligibility({ ...valid, ...change }), false);
  if (process.platform !== "linux" || process.getuid?.() !== 0) {
    assert.throws(() => inspectProtectedManualPgRollback({}), /refused/iu,
      "unprivileged checkout must fail without consulting caller-controlled production paths");
  }
});
const NEW = "a".repeat(40);
const OLD = "b".repeat(40);
const sha = (data) => createHash("sha256").update(data).digest("hex");

function fixture(t) {
  const base = mkdtempSync("/dev/shm/virki-pg-rollback-w37-");
  t.after(() => rmSync(base, { force: true, recursive: true }));
  const root = path.join(base, "production");
  mkdirSync(root, { mode: 0o700 });
  for (const name of ["backups", "releases", `releases/${OLD}`, `releases/${NEW}`]) {
    mkdirSync(path.join(root, name), { mode: 0o700 });
  }
  function put(relative, bytes) {
    const name = path.join(root, relative);
    writeFileSync(name, bytes, { mode: 0o600 });
    chmodSync(name, 0o600);
    return name;
  }
  const orig = Buffer.from("REAL EXAMPLE BACKUP BYTES - NEVER A PRODUCTION DUMP\n");
  const originalName = "virki-20261028-120000-aabbcc.dump";
  const backupName = "virki-20261028-120001-bbccdd.dump";
  put(`backups/${originalName}`, orig);
  put(`backups/${backupName}`, orig);
  put(`releases/${OLD}/.virki-release`, `revision=${OLD}\narchive_sha256=${"1".repeat(64)}\n`);
  put(`releases/${NEW}/.virki-release`, `revision=${NEW}\narchive_sha256=${"2".repeat(64)}\n`);
  symlinkSync(`releases/${OLD}`, path.join(root, "current"));
  put(".virki-maintenance", `revision=${NEW}\nstarted_at=2026-10-28T12:00:00Z\n`);
  const record = ["phase=VERIFIED", `revision=${NEW}`, `backup_name=${backupName}`,
    `backup_sha256=${sha(orig)}`, "snapshot_identity=1|2|3",
    `snapshot_recovery=${"c".repeat(64)}`, `origin_backup_name=${originalName}`,
    `origin_backup_sha256=${sha(orig)}`].join("\n") + "\n";
  put(".virki-migration-integrity-guard", record);
  put(".virki-migration-verification", [
    `revision=${NEW}`, `backup_name=${backupName}`, `backup_sha256=${sha(orig)}`,
    "verified_at=2026-10-28T12:00:00Z",
  ].join("\n") + "\n");
  const request = { productionRoot: root, expectedNewSha: NEW, expectedPredecessorSha: OLD };
  return { root, put, request, orig, backupName, originalName };
}

test("TDD: separately pinned read-only backup and predecessor inspection is nonauthorizing", LINUX_ROOT, (t) => {
  const f = fixture(t);
  const before = readdirSync(f.root).sort();
  const result = inspectProtectedManualPgRollback(f.request);
  assert.equal(result.status, "PROTECTED_PG_ROLLBACK_EVIDENCE_ONLY");
  assert.equal(result.checkpointPhase, "VERIFIED");
  assert.equal(result.expectedPredecessorSha, OLD);
  assert.equal(result.rollbackAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.writerFenceVerified, false);
  assert.equal(result.ownerApprovalVerified, false);
  assert.equal(result.witnessFloorVerified, false);
  assert.deepEqual(readdirSync(f.root).sort(), before);
});

test("TDD: mutated original dump, backup hash, and symlinked dump all refuse", LINUX_ROOT, (t) => {
  for (const variant of ["altered", "hardlink", "symlink"]) {
    const f = fixture(t);
    const original = path.join(f.root, "backups", f.originalName);
    if (variant === "altered") writeFileSync(original, "CORRUPTED\n");
    if (variant === "hardlink") linkSync(original, path.join(f.root, "backups/other.dump"));
    if (variant === "symlink") {
      rmSync(original);
      symlinkSync(path.join(f.root, "backups", f.backupName), original);
    }
    assert.throws(() => inspectProtectedManualPgRollback(f.request), /refused/iu, variant);
  }
});

test("TDD: predecessor route must stay pinned and maintenance checkpoint present", LINUX_ROOT, (t) => {
  const f = fixture(t);
  rmSync(path.join(f.root, "current"));
  symlinkSync(`releases/${NEW}`, path.join(f.root, "current"));
  assert.throws(() => inspectProtectedManualPgRollback(f.request), /refused/iu);
  rmSync(path.join(f.root, "current"));
  symlinkSync(`releases/${OLD}`, path.join(f.root, "current"));
  rmSync(path.join(f.root, ".virki-maintenance"));
  assert.throws(() => inspectProtectedManualPgRollback(f.request), /refused/iu);
});

test("TDD: guard, verification and original backup must agree exactly", LINUX_ROOT, (t) => {
  const f = fixture(t);
  const file = path.join(f.root, ".virki-migration-verification");
  const original = readFileSync(file, "utf8");
  f.put(".virki-migration-verification", original.replace(`backup_sha256=${sha(f.orig)}`, `backup_sha256=${"0".repeat(64)}`));
  assert.throws(() => inspectProtectedManualPgRollback(f.request), /refused/iu);
});

test("TDD: PREPARED checkpoint is inspectable but cannot imply recovery completion", LINUX_ROOT, (t) => {
  const f = fixture(t);
  const file = path.join(f.root, ".virki-migration-integrity-guard");
  f.put(".virki-migration-integrity-guard", readFileSync(file, "utf8").replace("phase=VERIFIED", "phase=PREPARED"));
  const result = inspectProtectedManualPgRollback(f.request);
  assert.equal(result.checkpointPhase, "PREPARED");
  assert.equal(result.rollbackAuthorized, false);
});

test("TDD: malformed SHA, unknown fields and external files are refused", LINUX_ROOT, (t) => {
  const f = fixture(t);
  assert.throws(() => inspectProtectedManualPgRollback({ ...f.request,
    expectedPredecessorSha: "../evil" }), /refused/iu);
  assert.throws(() => inspectProtectedManualPgRollback({ ...f.request,
    allowUnsigned: true }), /refused/iu);
  const file = path.join(f.root, ".virki-migration-integrity-guard");
  f.put(".virki-migration-integrity-guard", readFileSync(file, "utf8") + "unknown=true\n");
  assert.throws(() => inspectProtectedManualPgRollback(f.request), /refused/iu);
});

test("TDD: rollback evidence rejects an unprotected writable ancestor even when leaf is root 0700", LINUX_ROOT, (t) => {
  const f = fixture(t);
  const parent = path.dirname(f.root);
  chmodSync(parent, 0o777);
  try {
    assert.throws(() => inspectProtectedManualPgRollback(f.request), /refused/iu,
      "an attacker may replace the trusted directory through a writable non-sticky parent");
  } finally {
    chmodSync(parent, 0o700);
  }
});
