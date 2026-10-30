import { createHash } from "node:crypto";
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  readlinkSync, readSync, realpathSync, statfsSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Read-only native rollback precondition. This module provides no restore,
// Docker command, approval minting, route switch or production entrypoint.
// The separately installed OWNER must authenticate its executable, current
// native host, writer quiescence, source/images, stage signatures, witness CAS
// and out-of-host floor before consuming this inspection as one input.
const SHA40 = /^[a-f0-9]{40}$/u;
const SHA64 = /^[a-f0-9]{64}$/u;
const BACKUP = /^virki-[0-9]{8}-[0-9]{6}-[a-f0-9]{6}\.dump$/u;
const SNAPSHOT = /^[0-9]+\|[0-9]+\|[0-9]+$/u;
const IO_BLOCK = 64 * 1024;
// The existing owner-installed supervisor imports this exact sibling module.
// Do not introduce a disconnected second installation path for rollback.
const INSTALLED_ENTRY = "/usr/local/lib/virki/offline-release/infra/offline/native-manual-pg-rollback-preflight.mjs";
const NATIVE_FS = new Set([0xef53n, 0x58465342n, 0x9123683en]); // ext4, XFS, btrfs

function refuse() { throw new Error("Protected manual PostgreSQL rollback preflight refused"); }
function need(condition) { if (!condition) refuse(); }
function exact(value, fields) {
  need(value && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(fields));
}
function same(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
function secureDirectory(folder) {
  need(typeof folder === "string" && path.isAbsolute(folder) &&
    path.normalize(folder) === folder && realpathSync.native(folder) === folder);
  const stat = lstatSync(folder, { bigint: true });
  need(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0n &&
    (stat.mode & 0o7777n) === 0o700n);
  // A protected 0700 leaf is not protected if an attacker can rename its
  // parent. A root-owned sticky public parent (/tmp or /dev/shm) is allowed:
  // non-owners cannot rename the root-owned child in that directory.
  for (let ancestor = path.dirname(folder);;) {
    const parent = lstatSync(ancestor, { bigint: true });
    need(parent.isDirectory() && !parent.isSymbolicLink() && parent.uid === 0n &&
      ((parent.mode & 0o022n) === 0n || (parent.mode & 0o1000n) !== 0n));
    if (ancestor === path.dirname(ancestor)) break;
    ancestor = path.dirname(ancestor);
  }
}
/** Pure eligibility predicate, NEVER an installation/signature/first-exec proof. */
export function nativePgRollbackRuntimeEligibility({
  platform, arch, uid, euid, gid, egid, kernelRelease, entryPath,
} = {}) {
  return platform === "linux" && arch === "x64" && uid === 0 &&
    euid === 0 && gid === 0 && egid === 0 &&
    typeof kernelRelease === "string" && !/microsoft|wsl/iu.test(kernelRelease) &&
    entryPath === INSTALLED_ENTRY;
}
function requireNativeInstalledPgInspector() {
  const filename = fileURLToPath(import.meta.url);
  need(nativePgRollbackRuntimeEligibility({
    platform: process.platform, arch: process.arch,
    uid: process.getuid?.(), euid: process.geteuid?.(),
    gid: process.getgid?.(), egid: process.getegid?.(),
    kernelRelease: os.release(), entryPath: filename,
  }));
  // Any Node code from a checkout was already loaded before this check. Do
  // NOT execute root Node from DrvFS/checkout; a separately trusted native
  // owner installer/launcher is indispensable for actual first-exec safety.
  need(realpathSync.native(filename) === filename &&
    NATIVE_FS.has(statfsSync(filename, { bigint: true }).type));
  secureDirectory(path.dirname(filename));
  const source = lstatSync(filename, { bigint: true });
  need(source.isFile() && !source.isSymbolicLink() && source.uid === 0n &&
    source.gid === 0n && source.nlink === 1n &&
    (source.mode & 0o7777n) === 0o600n);
}
function openProtectedFile(filename, maxSize = BigInt(Number.MAX_SAFE_INTEGER)) {
  const before = lstatSync(filename, { bigint: true });
  need(before.isFile() && !before.isSymbolicLink() && before.uid === 0n &&
    before.nlink === 1n && (before.mode & 0o7777n) === 0o600n &&
    before.size > 0n && before.size <= maxSize);
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const actual = fstatSync(fd, { bigint: true });
  if (!same(before, actual)) { closeSync(fd); refuse(); }
  return { fd, before, filename };
}
function closeProtected({ fd, before, filename }) {
  try {
    need(same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(filename, { bigint: true })));
  } finally { closeSync(fd); }
}
function readBoundedText(filename, maxBytes = 4096) {
  const opened = openProtectedFile(filename, BigInt(maxBytes));
  try {
    const bytes = readFileSync(opened.fd);
    need(bytes.length === Number(opened.before.size));
    const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    need(!value.includes("\r") && !value.includes("\0"));
    closeProtected(opened);
    return value;
  } catch { try { closeSync(opened.fd); } catch { /* already closed */ } refuse(); }
}
function readFields(filename, names) {
  const value = readBoundedText(filename);
  need(value.endsWith("\n"));
  const lines = value.slice(0, -1).split("\n");
  need(lines.length === names.length);
  const fields = Object.create(null);
  for (let i = 0; i < names.length; i++) {
    const prefix = `${names[i]}=`;
    need(lines[i].startsWith(prefix));
    fields[names[i]] = lines[i].slice(prefix.length);
  }
  return fields;
}
function hashProtectedBackup(filename, expectedSha) {
  need(SHA64.test(expectedSha));
  const opened = openProtectedFile(filename);
  try {
    const digest = createHash("sha256");
    const buf = Buffer.allocUnsafe(IO_BLOCK);
    for (let at = 0; at < Number(opened.before.size);) {
      const len = Math.min(IO_BLOCK, Number(opened.before.size) - at);
      const n = readSync(opened.fd, buf, 0, len, at);
      need(n > 0 && n <= len);
      digest.update(buf.subarray(0, n));
      at += n;
    }
    need(digest.digest("hex") === expectedSha);
    closeProtected(opened);
  } catch { try { closeSync(opened.fd); } catch { /* already closed */ } refuse(); }
}

/**
 * Inspect host-owned ORIGINAL backup, verification marker, uncompleted
 * migration guard and predecessor route without changing any object.
 * Caller inputs are only EXPECTATIONS; they never grant authorization.
 * This nonauthorizing inspector deliberately does not sample live database
 * health, actual writer quiescence, independent owner/witness signatures or
 * external floor: a genuine privileged owner-installed entrypoint must do so.
 */
export function inspectProtectedManualPgRollback(request = {}) {
  try {
    requireNativeInstalledPgInspector();
    exact(request, ["productionRoot", "expectedNewSha", "expectedPredecessorSha"]);
    const { productionRoot: root, expectedNewSha, expectedPredecessorSha } = request;
    need(SHA40.test(expectedNewSha) && SHA40.test(expectedPredecessorSha) &&
      expectedNewSha !== expectedPredecessorSha &&
      typeof root === "string" && root !== "/" &&
      path.isAbsolute(root) && path.normalize(root) === root);
    secureDirectory(root);
    secureDirectory(path.join(root, "backups"));
    secureDirectory(path.join(root, "releases"));
    secureDirectory(path.join(root, "releases", expectedPredecessorSha));
    const active = path.join(root, "current");
    const initialRoute = lstatSync(active, { bigint: true });
    need(initialRoute.isSymbolicLink() &&
      readlinkSync(active) === `releases/${expectedPredecessorSha}` &&
      realpathSync.native(active) === path.join(root, "releases", expectedPredecessorSha));
    const predecessor = readFields(
      path.join(root, "releases", expectedPredecessorSha, ".virki-release"),
      ["revision", "archive_sha256"]);
    need(predecessor.revision === expectedPredecessorSha &&
      SHA64.test(predecessor.archive_sha256));

    const maintenance = readFields(path.join(root, ".virki-maintenance"),
      ["revision", "started_at"]);
    need(maintenance.revision === expectedNewSha &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/u.test(maintenance.started_at));
    const guard = readFields(path.join(root, ".virki-migration-integrity-guard"),
      ["phase", "revision", "backup_name", "backup_sha256", "snapshot_identity",
        "snapshot_recovery", "origin_backup_name", "origin_backup_sha256"]);
    need(["PREPARED", "VERIFIED"].includes(guard.phase) &&
      guard.revision === expectedNewSha && BACKUP.test(guard.backup_name) &&
      SHA64.test(guard.backup_sha256) && SNAPSHOT.test(guard.snapshot_identity) &&
      SHA64.test(guard.snapshot_recovery) && BACKUP.test(guard.origin_backup_name) &&
      SHA64.test(guard.origin_backup_sha256));
    const verification = readFields(path.join(root, ".virki-migration-verification"),
      ["revision", "backup_name", "backup_sha256", "verified_at"]);
    need(verification.revision === expectedNewSha &&
      verification.backup_name === guard.backup_name &&
      verification.backup_sha256 === guard.backup_sha256 &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/u.test(verification.verified_at));
    const backupFile = path.join(root, "backups", guard.backup_name);
    const originalFile = path.join(root, "backups", guard.origin_backup_name);
    const backupMeta = lstatSync(backupFile, { bigint: true });
    const originalMeta = lstatSync(originalFile, { bigint: true });
    hashProtectedBackup(backupFile, guard.backup_sha256);
    hashProtectedBackup(originalFile,
      guard.origin_backup_sha256);
    // A concurrent replacement of route/guard/backup during the long backup
    // checks cannot return a successful snapshot. This remains a nonauthorizing
    // preflight: a real executor must independently repeat it under its lock.
    need(same(backupMeta, lstatSync(backupFile, { bigint: true })) &&
      same(originalMeta, lstatSync(originalFile, { bigint: true })) &&
      same(initialRoute, lstatSync(active, { bigint: true })) &&
      readlinkSync(active) === `releases/${expectedPredecessorSha}` &&
      JSON.stringify(readFields(path.join(root, ".virki-maintenance"),
        ["revision", "started_at"])) === JSON.stringify(maintenance) &&
      JSON.stringify(readFields(path.join(root, ".virki-migration-integrity-guard"),
        ["phase", "revision", "backup_name", "backup_sha256", "snapshot_identity",
          "snapshot_recovery", "origin_backup_name", "origin_backup_sha256"])) ===
          JSON.stringify(guard) &&
      JSON.stringify(readFields(path.join(root, ".virki-migration-verification"),
        ["revision", "backup_name", "backup_sha256", "verified_at"])) ===
          JSON.stringify(verification) &&
      JSON.stringify(readFields(path.join(root, "releases", expectedPredecessorSha,
        ".virki-release"), ["revision", "archive_sha256"])) ===
          JSON.stringify(predecessor));

    return Object.freeze({
      status: "PROTECTED_PG_ROLLBACK_EVIDENCE_ONLY", checkpointPhase: guard.phase,
      expectedNewSha, expectedPredecessorSha,
      originalBackupSha256: guard.origin_backup_sha256,
      verificationBackupSha256: guard.backup_sha256,
      rollbackAuthorized: false, deployAuthorized: false,
      writerFenceVerified: false, ownerApprovalVerified: false,
      witnessFloorVerified: false,
    });
  } catch { refuse(); }
}
