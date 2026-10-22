import { createHash } from "node:crypto";
import {
  closeSync, constants, existsSync, fsyncSync, fstatSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, realpathSync, renameSync, statfsSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  AUDITED_VERIFIER_FILES, inspectAuditedVerifierFiles, prepareTrustedVerifierPinSet,
} from "./trusted-host-installer.mjs";

// Test-only proof of Linux atomicity. No CLI, host root destination, activation,
// privilege change, release approval or use of caller-provided uploaded policy.
// Only a root-owned disposable fixture immediately beneath the OS temp folder
// may be written, and only when the caller explicitly enables this rehearsal.
const OPERATOR_FILES = ["ledger.json", "trust-policy.json", "verifier-pins.json"];
const MAX_CODE_BYTES = 2 * 1024 * 1024;
const MAX_JSON_BYTES = 1024 * 1024;
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const DIR_FLAGS = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const WRITE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const CANDIDATE = ".candidate-partial";
const PUBLISHED = "published";

function refuse(reason) {
  throw new Error("Disposable native verifier rehearsal refused: " + reason);
}
function requireIt(condition, reason) {
  if (!condition) refuse(reason);
}
function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function unchanged(before, after) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => before[field] === after[field]);
}
function sameDirectoryIdentity(before, after) {
  // Creating and renaming a child legitimately changes directory nlink,
  // mtime and ctime; its owner, permissions, inode and device must persist.
  return after.isDirectory() && ["dev", "ino", "uid", "gid", "mode"]
    .every((field) => before[field] === after[field]);
}
function onlyNativeFixture() {
  requireIt(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 &&
    constants.O_NOFOLLOW && constants.O_EXCL && constants.O_DIRECTORY,
  "native Linux/amd64 root required");
  requireIt(process.env.VIRKI_DISPOSABLE_STAGE_REHEARSAL === "1",
    "explicit disposable rehearsal opt-in required");
  // Docker Desktop's Linux engine uses a WSL kernel. It may rehearse Linux VFS
  // operations inside its isolated tmpfs, but cannot qualify as a native host.
  requireIt(statfsSync(os.tmpdir()).type === 0x01021994 &&
    (!/wsl|microsoft/iu.test(os.release()) || existsSync("/.dockerenv")),
  "dedicated Linux tmpfs fixture required; WSL outside a container forbidden");
}
function canonicalDirectory(dirname, label) {
  requireIt(typeof dirname === "string" && dirname.length > 1 && dirname.length < 4096 &&
    path.isAbsolute(dirname) && path.normalize(dirname) === dirname &&
    dirname !== path.parse(dirname).root && !dirname.includes("\0"),
  label + " requires a canonical absolute path");
  for (let current = dirname; ; current = path.dirname(current)) {
    const stat = lstatSync(current);
    requireIt(stat.isDirectory() && !stat.isSymbolicLink(),
      label + " contains an alias or non-directory ancestor");
    if (path.dirname(current) === current) break;
  }
  requireIt(realpathSync.native(dirname) === dirname,
    label + " contains a filesystem alias");
}
function privateDirectory(dirname, label) {
  canonicalDirectory(dirname, label);
  const stat = lstatSync(dirname, { bigint: true });
  requireIt(stat.uid === 0n && stat.gid === 0n &&
    (stat.mode & 0o7777n) === 0o700n && stat.isDirectory(),
  label + " must be root:root 0700");
  return stat;
}
function readPrivateRegular(filename, limit, label) {
  const before = lstatSync(filename, { bigint: true });
  requireIt(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
    before.uid === 0n && before.gid === 0n &&
    (before.mode & 0o7777n) === 0o600n &&
    before.size > 0n && before.size <= BigInt(limit),
  label + " must be a private, root-owned, unlinked, bounded regular file");
  const fd = openSync(filename, READ_FLAGS);
  try {
    const opened = fstatSync(fd, { bigint: true });
    requireIt(unchanged(before, opened), label + " changed during opening");
    const bytes = readFileSync(fd);
    requireIt(bytes.length === Number(before.size) &&
      unchanged(opened, fstatSync(fd, { bigint: true })) &&
      unchanged(opened, lstatSync(filename, { bigint: true })),
    label + " changed during reading");
    return bytes;
  } finally {
    closeSync(fd);
  }
}
function protectedOperatorBytes(directory) {
  const stat = privateDirectory(directory, "independent operator directory");
  const fd = openSync(directory, DIR_FLAGS);
  try {
    requireIt(unchanged(stat, fstatSync(fd, { bigint: true })),
      "operator root changed while opening");
    const anchored = `/proc/self/fd/${fd}`;
    requireIt(JSON.stringify(readdirSync(anchored).sort()) === JSON.stringify(OPERATOR_FILES),
      "operator must independently provision exactly three protected files");
    const result = {};
    for (const name of OPERATOR_FILES) {
      result[name] = readPrivateRegular(path.join(anchored, name),
        name === "verifier-pins.json" ? 16384 : MAX_JSON_BYTES,
        "operator " + name);
    }
    requireIt(unchanged(stat, fstatSync(fd, { bigint: true })) &&
      unchanged(stat, lstatSync(directory, { bigint: true })),
    "operator root changed during pin inspection");
    return result;
  } finally {
    closeSync(fd);
  }
}
function sourceFile(sourceDirectory, relativePath) {
  const segments = relativePath.split("/");
  let parent = sourceDirectory;
  for (const segment of segments.slice(0, -1)) {
    parent = path.join(parent, segment);
    privateDirectory(parent, "audited source parent");
  }
  return path.join(parent, segments.at(-1));
}
function sourceBytes(sourceDirectory, files) {
  const output = [];
  for (const entry of files) {
    const bytes = readPrivateRegular(sourceFile(sourceDirectory, entry.path),
      MAX_CODE_BYTES, "audited source " + entry.path);
    requireIt(hash(bytes) === entry.sha256,
      "exact independently pinned verifier SHA-256 mismatch: " + entry.path);
    output.push(bytes);
  }
  return output;
}
function assertExactModuleTree(root, files) {
  const directories = new Map([["", new Set()]]);
  for (const entry of files) {
    const parts = entry.path.split("/");
    let relative = "";
    for (let i = 0; i < parts.length; i++) {
      directories.get(relative).add(parts[i]);
      if (i < parts.length - 1) {
        relative = relative ? path.join(relative, parts[i]) : parts[i];
        if (!directories.has(relative)) directories.set(relative, new Set());
      }
    }
  }
  for (const [relative, children] of directories) {
    const current = path.join(root, relative);
    privateDirectory(current, "exact staged module directory");
    requireIt(JSON.stringify(readdirSync(current).sort()) ===
      JSON.stringify([...children].sort()),
    "staged module tree contains missing, injected or unexpected entries");
  }
}
function fsyncDirectory(dirname) {
  const fd = openSync(dirname, DIR_FLAGS);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function createModule(candidateRoot, relativePath, bytes) {
  const segments = relativePath.split("/");
  let dir = candidateRoot;
  for (const segment of segments.slice(0, -1)) {
    dir = path.join(dir, segment);
    try {
      mkdirSync(dir, { mode: 0o700 });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    privateDirectory(dir, "new staging module parent");
  }
  const filename = path.join(dir, segments.at(-1));
  const fd = openSync(filename, WRITE_FLAGS, 0o600);
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const count = writeSync(fd, bytes, offset, bytes.length - offset, offset);
      requireIt(count > 0, "short write to staged verifier");
      offset += count;
    }
    fsyncSync(fd);
    const stat = fstatSync(fd, { bigint: true });
    requireIt(stat.isFile() && stat.uid === 0n && stat.gid === 0n &&
      (stat.mode & 0o7777n) === 0o600n && stat.nlink === 1n &&
      stat.size === BigInt(bytes.length),
    "unsafe staged module metadata");
  } finally {
    closeSync(fd);
  }
}
function fsyncTree(dirname) {
  const names = readdirSync(dirname, { withFileTypes: true });
  for (const entry of names) {
    if (entry.isDirectory()) fsyncTree(path.join(dirname, entry.name));
  }
  fsyncDirectory(dirname);
}

/**
 * Rehearses one all-or-none publication of eleven independently pinned modules
 * under /tmp/virki-native-stage-fixture-XXXXXX/staging/published only. The
 * protected policy MUST already have been provisioned by the fixture's owner.
 * Caller-controlled pins can never confer deployment or host-install approval.
 * A crash leaves either a non-executable orphan candidate or one complete
 * published directory; an orphan blocks all retries until fixture disposal.
 */
export function rehearseTrustedNativeVerifierStaging(request = {}, { onPhase } = {}) {
  onlyNativeFixture();
  requireIt(request && typeof request === "object" && !Array.isArray(request) &&
    Object.keys(request).length === 5 &&
    ["fixtureRoot", "sourceDirectory", "operatorDirectory", "stagingDirectory",
      "measuredHostIdentitySha256"].every((key) => Object.hasOwn(request, key)),
  "fixed five-field fixture request required");
  const { fixtureRoot, sourceDirectory, operatorDirectory, stagingDirectory,
    measuredHostIdentitySha256 } = request;
  const tempRoot = realpathSync.native(os.tmpdir());
  requireIt(typeof fixtureRoot === "string" &&
    path.dirname(fixtureRoot) === tempRoot &&
    /^virki-native-stage-fixture-[A-Za-z0-9]{6}$/u.test(path.basename(fixtureRoot)),
  "fixture must be a direct disposable temporary directory");
  requireIt(sourceDirectory === path.join(fixtureRoot, "source") &&
    operatorDirectory === path.join(fixtureRoot, "operator") &&
    stagingDirectory === path.join(fixtureRoot, "staging"),
  "source, independently protected operator and staging roots must be disjoint siblings");
  privateDirectory(fixtureRoot, "disposable fixture root");
  privateDirectory(sourceDirectory, "audited source root");
  privateDirectory(operatorDirectory, "operator root");
  const stagingStat = privateDirectory(stagingDirectory, "staging root");
  const operator = protectedOperatorBytes(operatorDirectory);
  const pins = prepareTrustedVerifierPinSet({
    pinsBytes: operator["verifier-pins.json"],
    policyBytes: operator["trust-policy.json"],
    ledgerBytes: operator["ledger.json"],
    measuredHostIdentitySha256,
  });
  requireIt(pins.files.length === AUDITED_VERIFIER_FILES.length,
    "audited exact module inventory is incomplete");
  inspectAuditedVerifierFiles({ sourceDirectory, files: pins.files });
  const bytes = sourceBytes(sourceDirectory, pins.files);
  const stagingFd = openSync(stagingDirectory, DIR_FLAGS);
  try {
    requireIt(unchanged(stagingStat, fstatSync(stagingFd, { bigint: true })),
      "staging root changed during opening");
    const anchored = `/proc/self/fd/${stagingFd}`;
    requireIt(readdirSync(anchored).length === 0,
      "staging contains a prior publication, orphan, link or unrelated entry");
    const candidate = path.join(anchored, CANDIDATE);
    const candidateReal = path.join(stagingDirectory, CANDIDATE);
    const published = path.join(anchored, PUBLISHED);
    // Fixed O_EXCL-equivalent mkdir name doubles as a cross-process lock.
    mkdirSync(candidate, { mode: 0o700 });
    privateDirectory(candidateReal, "staging candidate");
    for (let i = 0; i < pins.files.length; i++) {
      createModule(candidateReal, pins.files[i].path, bytes[i]);
    }
    // Recheck every module before the sole visibility-changing rename.
    const staged = sourceBytes(candidateReal, pins.files);
    for (let i = 0; i < bytes.length; i++) {
      requireIt(staged[i].equals(bytes[i]), "staged verifier differs from inspected source");
    }
    inspectAuditedVerifierFiles({ sourceDirectory, files: pins.files });
    fsyncTree(candidate);
    fsyncSync(stagingFd);
    onPhase?.("beforePublish");
    assertExactModuleTree(candidateReal, pins.files);
    const finalBytes = sourceBytes(candidateReal, pins.files);
    for (let i = 0; i < bytes.length; i++) {
      requireIt(finalBytes[i].equals(bytes[i]), "staged source changed before publication");
    }
    requireIt(readdirSync(anchored).length === 1 &&
      readdirSync(anchored)[0] === CANDIDATE,
    "staging was modified before atomic publication");
    renameSync(candidate, published);
    fsyncSync(stagingFd);
    onPhase?.("afterPublish");
    const publishedReal = path.join(stagingDirectory, PUBLISHED);
    assertExactModuleTree(publishedReal, pins.files);
    sourceBytes(publishedReal, pins.files);
    requireIt(sameDirectoryIdentity(stagingStat, fstatSync(stagingFd, { bigint: true })) &&
      sameDirectoryIdentity(stagingStat, lstatSync(stagingDirectory, { bigint: true })),
    "staging changed during atomic rehearsal");
    return Object.freeze({
      status: "DISPOSABLE_NATIVE_LINUX_STAGING_REHEARSAL_ONLY",
      auditedSourceCount: pins.files.length,
      operatorPinsSha256: pins.operatorPinsSha256,
      stagingPath: path.join(stagingDirectory, PUBLISHED),
    });
  } finally {
    closeSync(stagingFd);
  }
}
