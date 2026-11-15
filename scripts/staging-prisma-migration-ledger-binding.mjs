import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  constants as fsConstants,
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  opendirSync,
  readdirSync,
  readSync,
  realpathSync
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

// The NT SystemRoot alias is resolved by Windows, independently of process
// environment variables or the drive/directory used to install Windows.
function windowsRegistryExecutable() {
  try {
    const executable = realpathSync.native("//?/GLOBALROOT/SystemRoot/System32/reg.exe");
    const stat = lstatSync(executable);
    if (!stat.isFile() || stat.isSymbolicLink() ||
        path.win32.basename(executable).toLowerCase() !== "reg.exe" ||
        path.win32.basename(path.win32.dirname(executable)).toLowerCase() !== "system32") {
      fail("UNTRUSTED_GIT_EXECUTABLE");
    }
    return executable;
  } catch {
    fail("UNTRUSTED_GIT_EXECUTABLE");
  }
}
const WINDOWS_REG_EXECUTABLE = process.platform === "win32" ? windowsRegistryExecutable() : null;
const WINDOWS_GIT_INSTALL_KEYS = [
  "HKLM\\SOFTWARE\\GitForWindows",
  "HKLM\\SOFTWARE\\WOW6432Node\\GitForWindows"
];
const VALID_GIT_TREE_MODES = new Set(["100644", "100755", "120000", "40000", "160000"]);
export const GIT_COMMAND_TIMEOUT_MS = 10_000;
const MAX_LOOSE_OBJECTS_PER_FANOUT = 8_192;
const MAX_LOOSE_OBJECTS_TOTAL = 131_072;
const MAX_OBJECT_STORE_DIRECTORY_ENTRIES = 65_536;
const MAX_LEDGER_BYTES = 1024 * 1024;

function samePath(left, right) {
  const resolvedLeft = path.resolve(left);
  const resolvedRight = path.resolve(right);
  return process.platform === "win32"
    ? resolvedLeft.toLowerCase() === resolvedRight.toLowerCase()
    : resolvedLeft === resolvedRight;
}

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

/** Resolve Git for Windows from the machine-wide installer registration only. */
export function parseWindowsGitInstallPath(registryOutput) {
  if (typeof registryOutput !== "string") fail("UNTRUSTED_GIT_EXECUTABLE");
  const matches = [...registryOutput.matchAll(/^\s*InstallPath\s+REG_SZ\s+(.+?)\s*$/gmu)];
  if (matches.length !== 1) fail("UNTRUSTED_GIT_EXECUTABLE");
  const installPath = matches[0][1];
  if (!path.win32.isAbsolute(installPath) || installPath.startsWith("\\\\") ||
      installPath.includes("\0") || installPath.includes("\n") || installPath.includes("\r") ||
      installPath.includes('"')) {
    fail("UNTRUSTED_GIT_EXECUTABLE");
  }
  return path.win32.join(path.win32.normalize(installPath), "cmd", "git.exe");
}

function resolveWindowsGitExecutable() {
  const windowsRoot = path.win32.dirname(path.win32.dirname(WINDOWS_REG_EXECUTABLE));
  for (const key of WINDOWS_GIT_INSTALL_KEYS) {
    const result = spawnSync(WINDOWS_REG_EXECUTABLE, ["query", key, "/v", "InstallPath"], {
      encoding: "utf8",
      maxBuffer: 16 * 1024,
      timeout: 3_000,
      env: { SystemRoot: windowsRoot, WINDIR: windowsRoot, PATH: path.win32.dirname(WINDOWS_REG_EXECUTABLE) },
      windowsHide: true
    });
    if (result.error || result.status !== 0 || typeof result.stdout !== "string") continue;
    try { return parseWindowsGitInstallPath(result.stdout); } catch { /* Try the 32-bit registry view. */ }
  }
  fail("UNTRUSTED_GIT_EXECUTABLE");
}

export const GIT_EXECUTABLE = process.platform === "win32"
  ? resolveWindowsGitExecutable()
  : "/usr/bin/git";

function isolatedGitEnvironment(source = process.env) {
  const environment = Object.fromEntries(
    Object.entries(source).filter(([name]) => !/^GIT_/iu.test(name))
  );
  // Never allow ambient repository/index/object/config redirection or replace
  // refs to change which approved objects the verifier reads.
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_NO_LAZY_FETCH = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  return environment;
}

function assertGitExecutable() {
  const stat = lstatSync(GIT_EXECUTABLE, { bigint: true });
  // Git for Windows legitimately installs git.exe as a hard link to git-lfs.exe.
  // An extra NTFS hard-link name is not a reparse-point redirect.
  if (!stat.isFile() || stat.isSymbolicLink() ||
      (process.platform !== "win32" && stat.nlink !== 1n)) {
    fail("UNTRUSTED_GIT_EXECUTABLE");
  }
  if (!samePath(realpathSync(GIT_EXECUTABLE), GIT_EXECUTABLE)) {
    fail("UNTRUSTED_GIT_EXECUTABLE");
  }
  if (process.platform === "win32") {
    for (let cursor = path.win32.dirname(GIT_EXECUTABLE);;) {
      const parent = lstatSync(cursor, { bigint: true });
      if (!parent.isDirectory() || parent.isSymbolicLink()) fail("UNTRUSTED_GIT_EXECUTABLE");
      const root = path.win32.parse(cursor).root;
      if (samePath(cursor, root)) break;
      cursor = path.win32.dirname(cursor);
    }
  }
}

export function gitBuffer(args, cwd, input, { timeoutMs = GIT_COMMAND_TIMEOUT_MS, environment = process.env } = {}) {
  assertGitExecutable();
  const result = spawnSync(GIT_EXECUTABLE, args, {
    cwd,
    input,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    timeout: timeoutMs,
    env: isolatedGitEnvironment(environment),
    windowsHide: true
  });
  if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    const error = new Error("MIGRATION_GIT_TREE_UNAVAILABLE", result.error ? { cause: result.error } : undefined);
    error.code = "MIGRATION_GIT_TREE_UNAVAILABLE";
    throw error;
  }
  return result.stdout;
}

function sameFileIdentity(left, right) {
  return ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => left[field] === right[field]);
}

function readRegularFile(filePath, failureCode, expectedBytes, sizeMismatchCode = failureCode, snapshots) {
  let descriptor;
  try {
    if (!Buffer.isBuffer(expectedBytes)) fail(failureCode);
    const before = lstatSync(filePath, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
        before.size !== BigInt(expectedBytes.length)) {
      fail(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n
        ? sizeMismatchCode
        : failureCode);
    }
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(failureCode);
    }

    // POSIX can pin the leaf without following a symlink. Windows Node does
    // not expose O_NOFOLLOW, so retain pre/post lstat plus the pinned FD identity.
    if (process.platform !== "win32" && !Number.isInteger(fsConstants.O_NOFOLLOW)) {
      fail(failureCode);
    }
    descriptor = openSync(filePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
    if (!sameFileIdentity(before, fstatSync(descriptor, { bigint: true }))) fail(failureCode);

    // Read at most one byte beyond the approved blob size. A concurrent
    // writer cannot force an unbounded allocation between lstat and read.
    const bytes = Buffer.alloc(expectedBytes.length + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length !== expectedBytes.length ||
        !sameFileIdentity(before, fstatSync(descriptor, { bigint: true })) ||
        !sameFileIdentity(before, lstatSync(filePath, { bigint: true }))) {
      fail(sizeMismatchCode);
    }
    snapshots?.push({ path: filePath, stat: before });
    return bytes.subarray(0, length);
  } catch (error) {
    if (error?.code === failureCode || error?.code === sizeMismatchCode) throw error;
    fail(failureCode);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function readBoundedObjectStoreFile(filePath, expectedStat, maximumBytes = 64 * 1024) {
  let descriptor;
  try {
    const before = lstatSync(filePath, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
        before.size < 1n || before.size > BigInt(maximumBytes) ||
        !sameFileIdentity(expectedStat, before)) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    if (process.platform !== "win32" && !Number.isInteger(fsConstants.O_NOFOLLOW)) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    descriptor = openSync(filePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
    if (!sameFileIdentity(before, fstatSync(descriptor, { bigint: true }))) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length !== Number(before.size) ||
        !sameFileIdentity(before, fstatSync(descriptor, { bigint: true })) ||
        !sameFileIdentity(before, lstatSync(filePath, { bigint: true }))) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    return bytes.subarray(0, length);
  } catch (error) {
    if (error?.code === "UNTRUSTED_GIT_OBJECT_STORE") throw error;
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function verifyCommitGraphChecksum(filePath, expectedStat, objectFormat, hashBytes, expectedHash) {
  let descriptor;
  try {
    const before = lstatSync(filePath, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
        before.size <= BigInt(hashBytes) || before.size > 1_073_741_824n ||
        before.size > BigInt(Number.MAX_SAFE_INTEGER) ||
        !sameFileIdentity(expectedStat, before)) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    descriptor = openSync(filePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
    if (!sameFileIdentity(before, fstatSync(descriptor, { bigint: true }))) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }

    const contentLength = Number(before.size) - hashBytes;
    const digest = createHash(objectFormat);
    const chunk = Buffer.alloc(1024 * 1024);
    let offset = 0;
    while (offset < contentLength) {
      const length = Math.min(chunk.length, contentLength - offset);
      const count = readSync(descriptor, chunk, 0, length, offset);
      if (count !== length) fail("UNTRUSTED_GIT_OBJECT_STORE");
      digest.update(chunk.subarray(0, count));
      offset += count;
    }
    const trailer = Buffer.alloc(hashBytes);
    if (readSync(descriptor, trailer, 0, hashBytes, contentLength) !== hashBytes) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    const actualHash = digest.digest();
    if (!actualHash.equals(trailer) ||
        (expectedHash !== undefined && actualHash.toString("hex") !== expectedHash) ||
        !sameFileIdentity(before, fstatSync(descriptor, { bigint: true })) ||
        !sameFileIdentity(before, lstatSync(filePath, { bigint: true }))) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
  } catch (error) {
    if (error?.code === "UNTRUSTED_GIT_OBJECT_STORE") throw error;
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function verifyRegularFileSnapshot(snapshot, failureCode = "UNTRUSTED_GIT_OBJECT_STORE") {
  try {
    const current = lstatSync(snapshot.path, { bigint: true });
    if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1n ||
        !sameFileIdentity(snapshot.stat, current)) fail(failureCode);
  } catch (error) {
    if (error?.code === failureCode) throw error;
    fail(failureCode);
  }
}

function gitText(args, cwd) {
  return gitBuffer(args, cwd).toString("utf8").trim();
}

function gitOptionalText(args, cwd) {
  assertGitExecutable();
  const result = spawnSync(GIT_EXECUTABLE, args, {
    cwd,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    timeout: GIT_COMMAND_TIMEOUT_MS,
    env: isolatedGitEnvironment(),
    windowsHide: true
  });
  if (result.error || (result.status !== 0 && result.status !== 1) || !Buffer.isBuffer(result.stdout)) {
    fail("MIGRATION_GIT_TREE_UNAVAILABLE");
  }
  return result.status === 0 ? result.stdout.toString("utf8").trim() : "";
}

function snapshotDirectoryChain(directory, failureCode = "INVALID_MIGRATION_DIRECTORY", stopAt) {
  const chain = [];
  const stopPath = stopAt === undefined ? null : path.resolve(stopAt);
  for (let cursor = path.resolve(directory);;) {
    const stat = lstatSync(cursor, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail(failureCode);
    chain.push({ path: cursor, stat });
    if (stopPath !== null && samePath(cursor, stopPath)) return chain;
    const parent = path.dirname(cursor);
    if (parent === cursor) {
      if (stopPath !== null) fail(failureCode);
      break;
    }
    cursor = parent;
  }
  return chain;
}

function verifyDirectoryChain(chain) {
  for (const { path: directory, stat } of chain) {
    const current = lstatSync(directory, { bigint: true });
    if (!current.isDirectory() || current.isSymbolicLink() || !sameFileIdentity(stat, current)) {
      fail("MIGRATION_DIRECTORY_CHANGED");
    }
  }
}

function readObjectStoreNames(directory, limit = MAX_OBJECT_STORE_DIRECTORY_ENTRIES) {
  let handle;
  try {
    handle = opendirSync(directory);
    const names = [];
    for (;;) {
      const entry = handle.readSync();
      if (entry === null) return names.sort();
      if (names.length >= limit) fail("UNTRUSTED_GIT_OBJECT_STORE");
      names.push(entry.name);
    }
  } catch (error) {
    if (error?.code === "UNTRUSTED_GIT_OBJECT_STORE") throw error;
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  } finally {
    handle?.closeSync();
  }
}

function assertTrustedGitObjectStore(repositoryRoot, approvedSourceSha) {
  const objectFormat = gitText(["rev-parse", "--show-object-format"], repositoryRoot);
  const expectedLength = objectFormat === "sha1" ? 40 : objectFormat === "sha256" ? 64 : 0;
  if (expectedLength === 0 || approvedSourceSha.length !== expectedLength) {
    fail("INVALID_APPROVED_SOURCE_SHA");
  }
  const hashBytes = expectedLength / 2;
  if (gitText(["rev-parse", "--is-shallow-repository"], repositoryRoot) !== "false") {
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  }
  if (gitOptionalText([
    "config", "--get-regexp", "^(extensions\\.partialclone|remote\\..*\\.promisor)"
  ], repositoryRoot) !== "") {
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  }

  const commonDirectory = gitText([
    "rev-parse", "--path-format=absolute", "--git-common-dir"
  ], repositoryRoot);
  if (!samePath(realpathSync(commonDirectory), commonDirectory)) {
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  }
  const gitEntryPath = path.join(repositoryRoot, ".git");
  const gitEntryStat = lstatSync(gitEntryPath, { bigint: true });
  let gitEntrySnapshot;
  if (gitEntryStat.isSymbolicLink()) fail("UNTRUSTED_GIT_OBJECT_STORE");
  if (gitEntryStat.isDirectory()) {
    if (!samePath(realpathSync(gitEntryPath), commonDirectory)) fail("UNTRUSTED_GIT_OBJECT_STORE");
    gitEntrySnapshot = {
      kind: "directory",
      path: gitEntryPath,
      stat: gitEntryStat,
      names: readObjectStoreNames(gitEntryPath)
    };
  } else if (gitEntryStat.isFile() && gitEntryStat.nlink === 1n) {
    const gitEntryText = readBoundedObjectStoreFile(gitEntryPath, gitEntryStat, 4096).toString("utf8");
    const gitDirectoryMatch = /^gitdir: ([^\r\n]+)\r?\n?$/u.exec(gitEntryText);
    if (!gitDirectoryMatch) fail("UNTRUSTED_GIT_OBJECT_STORE");
    const declaredGitDirectory = path.resolve(repositoryRoot, gitDirectoryMatch[1]);
    const actualGitDirectory = gitText(["rev-parse", "--absolute-git-dir"], repositoryRoot);
    const gitDirectoryStat = lstatSync(declaredGitDirectory, { bigint: true });
    if (!gitDirectoryStat.isDirectory() || gitDirectoryStat.isSymbolicLink() ||
        !samePath(realpathSync(declaredGitDirectory), realpathSync(actualGitDirectory)) ||
        !samePath(declaredGitDirectory, actualGitDirectory)) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    gitEntrySnapshot = {
      kind: "file",
      path: gitEntryPath,
      stat: gitEntryStat,
      gitDirectorySnapshot: {
        path: declaredGitDirectory,
        stat: gitDirectoryStat,
        names: readObjectStoreNames(declaredGitDirectory)
      }
    };
  } else {
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  }
  const objectDirectory = path.join(commonDirectory, "objects");
  const objectDirectoryChain = snapshotDirectoryChain(
    objectDirectory, "UNTRUSTED_GIT_OBJECT_STORE", commonDirectory
  );
  const objectDirectoryStat = lstatSync(objectDirectory, { bigint: true });
  if (!objectDirectoryStat.isDirectory() || objectDirectoryStat.isSymbolicLink()) {
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  }

  const objectDirectorySnapshots = [];
  const objectFileSnapshots = [];
  const infoPackNames = [];
  const packArtifacts = new Map();
  let multiPackIndexPresent = false;
  let multiPackIndexSidecarPresent = false;
  let monolithicCommitGraph = null;
  let looseObjectCount = 0;
  if (gitEntrySnapshot.kind === "directory") {
    objectDirectorySnapshots.push(gitEntrySnapshot);
  } else {
    objectFileSnapshots.push(gitEntrySnapshot);
    objectDirectorySnapshots.push(gitEntrySnapshot.gitDirectorySnapshot);
  }
  const rootObjectNames = readObjectStoreNames(objectDirectory, 258);
  objectDirectorySnapshots.push({ path: objectDirectory, stat: objectDirectoryStat, names: rootObjectNames });
  const inspectObjectDirectory = (directory, kind) => {
    const stat = lstatSync(directory, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail("UNTRUSTED_GIT_OBJECT_STORE");
    const names = readObjectStoreNames(directory,
      kind === "loose" ? MAX_LOOSE_OBJECTS_PER_FANOUT : MAX_OBJECT_STORE_DIRECTORY_ENTRIES);
    if (kind === "loose") {
      // An arbitrary number of correctly named but unreferenced objects can
      // otherwise exhaust the scanner before its final snapshot checks.
      looseObjectCount += names.length;
      if (looseObjectCount > MAX_LOOSE_OBJECTS_TOTAL) {
        fail("UNTRUSTED_GIT_OBJECT_STORE");
      }
    }
    objectDirectorySnapshots.push({ path: directory, stat, names });
    for (const name of names) {
      const entryPath = path.join(directory, name);
      const entry = lstatSync(entryPath, { bigint: true });
      if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory())) {
        fail("UNTRUSTED_GIT_OBJECT_STORE");
      }
      if (entry.isDirectory()) {
        if (kind === "info" && name === "commit-graphs") {
          inspectObjectDirectory(entryPath, "commit-graphs");
          continue;
        }
        fail("UNTRUSTED_GIT_OBJECT_STORE");
      }
      if (entry.nlink !== 1n) fail("UNTRUSTED_GIT_OBJECT_STORE");
      if (kind === "loose") {
        if (!new RegExp(`^[a-f0-9]{${expectedLength - 2}}$`, "u").test(name)) {
          fail("UNTRUSTED_GIT_OBJECT_STORE");
        }
      } else if (kind === "info") {
        if (name === "commit-graph") {
          monolithicCommitGraph = { path: entryPath, stat: entry };
        } else if (name === "packs") {
          infoPackNames.push({ path: entryPath, stat: entry });
        } else {
          fail("UNTRUSTED_GIT_OBJECT_STORE");
        }
      } else if (kind === "commit-graphs") {
        if (name !== "commit-graph-chain" &&
            !new RegExp(`^graph-[a-f0-9]{${expectedLength}}\\.graph$`, "u").test(name)) {
          fail("UNTRUSTED_GIT_OBJECT_STORE");
        }
      } else if (kind === "pack") {
        if (/\.promisor$/iu.test(name)) fail("UNTRUSTED_GIT_OBJECT_STORE");
        const packMatch = new RegExp(`^pack-([a-f0-9]{${expectedLength}})\\.(pack|idx|rev|bitmap|mtimes|keep)$`, "u").exec(name);
        const multiPackIndexMatch = new RegExp(`^multi-pack-index(?:-[a-f0-9]{${expectedLength}}\\.(?:bitmap|rev))?$`, "u").exec(name);
        if (!packMatch && !multiPackIndexMatch) fail("UNTRUSTED_GIT_OBJECT_STORE");
        if (name === "multi-pack-index") multiPackIndexPresent = true;
        else if (name.startsWith("multi-pack-index-")) multiPackIndexSidecarPresent = true;
        if (packMatch) {
          const [, packHash, extension] = packMatch;
          const extensions = packArtifacts.get(packHash) ?? new Set();
          if (extensions.has(extension)) fail("UNTRUSTED_GIT_OBJECT_STORE");
          extensions.add(extension);
          packArtifacts.set(packHash, extensions);
        }
      } else {
        fail("UNTRUSTED_GIT_OBJECT_STORE");
      }
      objectFileSnapshots.push({ path: entryPath, stat: entry });
    }
  };

  for (const name of rootObjectNames) {
    const entryPath = path.join(objectDirectory, name);
    const entry = lstatSync(entryPath, { bigint: true });
    if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory())) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    if (entry.isDirectory()) {
      if (name === "info" || name === "pack") {
        inspectObjectDirectory(entryPath, name);
      } else if (/^[a-f0-9]{2}$/u.test(name)) {
        inspectObjectDirectory(entryPath, "loose");
      } else {
        fail("UNTRUSTED_GIT_OBJECT_STORE");
      }
      continue;
    }
    // The canonical Git object directory contains only info/, pack/, and
    // two-hex fanout directories. Temporary/root-level loose objects are not
    // accepted in this immutable staging checkout.
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  }

  for (const extensions of packArtifacts.values()) {
    if (!extensions.has("pack") || !extensions.has("idx")) fail("UNTRUSTED_GIT_OBJECT_STORE");
  }
  if (multiPackIndexSidecarPresent && !multiPackIndexPresent) fail("UNTRUSTED_GIT_OBJECT_STORE");
  for (const packHash of packArtifacts.keys()) {
    gitBuffer(["verify-pack", path.join(objectDirectory, "pack", `pack-${packHash}.idx`)], repositoryRoot);
  }
  const packHashes = new Set(packArtifacts.keys());
  for (const { path: packsPath, stat: packsStat } of infoPackNames) {
    const packsBytes = readBoundedObjectStoreFile(packsPath, packsStat, 1024 * 1024);
    const packsText = packsBytes.toString("ascii");
    if (!Buffer.from(packsText, "ascii").equals(packsBytes)) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    const lines = packsText.split(/\r?\n/u).filter((line) => line.length > 0);
    if (new Set(lines).size !== lines.length ||
        lines.some((line) => !new RegExp(`^P pack-([a-f0-9]{${expectedLength}})\\.pack$`, "u").test(line) ||
        !packHashes.has(line.slice(7, -5)))) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
  }

  const commitGraphDirectory = path.join(objectDirectory, "info", "commit-graphs");
  let commitGraphDirectoryStat;
  try {
    commitGraphDirectoryStat = lstatSync(commitGraphDirectory, { bigint: true });
  } catch (error) {
    if (error?.code !== "ENOENT") fail("UNTRUSTED_GIT_OBJECT_STORE");
  }
  let splitCommitGraphPresent = false;
  if (commitGraphDirectoryStat?.isDirectory()) {
    const graphFiles = new Map();
    let chainFile = null;
    for (const { path: filePath, stat: fileStat } of objectFileSnapshots.filter((entry) =>
      path.dirname(entry.path) === commitGraphDirectory)) {
      const name = path.basename(filePath);
      if (name === "commit-graph-chain") {
        if (chainFile !== null) fail("UNTRUSTED_GIT_OBJECT_STORE");
        chainFile = { path: filePath, stat: fileStat };
      } else {
        const match = new RegExp(`^graph-([a-f0-9]{${expectedLength}})\\.graph$`, "u").exec(name);
        if (!match || graphFiles.has(match[1])) fail("UNTRUSTED_GIT_OBJECT_STORE");
        graphFiles.set(match[1], { path: filePath, stat: fileStat });
      }
    }
    if ((chainFile === null) !== (graphFiles.size === 0)) fail("UNTRUSTED_GIT_OBJECT_STORE");
    if (chainFile !== null) {
      const chainBytes = readBoundedObjectStoreFile(chainFile.path, chainFile.stat);
      const chainText = chainBytes.toString("ascii");
      if (!Buffer.from(chainText, "ascii").equals(chainBytes) || chainText.includes("\r")) {
        fail("UNTRUSTED_GIT_OBJECT_STORE");
      }
      const chainHashes = chainText.split("\n");
      if (chainHashes.at(-1) === "") chainHashes.pop();
      if (chainHashes.length === 0 || new Set(chainHashes).size !== chainHashes.length ||
          chainHashes.length !== graphFiles.size ||
          chainHashes.some((hash) => !new RegExp(`^[a-f0-9]{${expectedLength}}$`, "u").test(hash) ||
            !graphFiles.has(hash))) {
        fail("UNTRUSTED_GIT_OBJECT_STORE");
      }
      for (const hash of chainHashes) {
        const graph = graphFiles.get(hash);
        verifyCommitGraphChecksum(graph.path, graph.stat, objectFormat, hashBytes, hash);
      }
      splitCommitGraphPresent = true;
    }
  } else if (commitGraphDirectoryStat !== undefined) {
    fail("UNTRUSTED_GIT_OBJECT_STORE");
  }

  if (monolithicCommitGraph !== null) {
    verifyCommitGraphChecksum(monolithicCommitGraph.path, monolithicCommitGraph.stat, objectFormat, hashBytes);
  }
  if (splitCommitGraphPresent || monolithicCommitGraph !== null) {
    gitBuffer(["commit-graph", "verify"], repositoryRoot);
  }
  if (multiPackIndexPresent) {
    gitBuffer(["multi-pack-index", "verify"], repositoryRoot);
  }

  for (const name of ["alternates", "http-alternates"]) {
    const alternatePath = gitText([
      "rev-parse", "--path-format=absolute", "--git-path", `objects/info/${name}`
    ], repositoryRoot);
    let alternateExists = false;
    try {
      lstatSync(alternatePath);
      alternateExists = true;
    } catch (error) {
      if (error?.code !== "ENOENT") fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
    if (alternateExists) fail("UNTRUSTED_GIT_OBJECT_STORE");
  }

  return {
    objectFormat,
    hashBytes: expectedLength / 2,
    objectDirectoryChain,
    objectDirectorySnapshots,
    objectFileSnapshots
  };
}

function verifyGitObjectId(type, content, expectedObjectId, objectFormat) {
  const header = Buffer.from(`${type} ${content.length}\0`, "utf8");
  const actualObjectId = createHash(objectFormat).update(header).update(content).digest("hex");
  if (actualObjectId !== expectedObjectId) fail("UNTRUSTED_GIT_OBJECT_STORE");
  return content;
}

function parseGitTree(content, hashBytes) {
  const entries = [];
  let offset = 0;
  while (offset < content.length) {
    const separator = content.indexOf(0x20, offset);
    const terminator = separator < 0 ? -1 : content.indexOf(0, separator + 1);
    if (separator <= offset || terminator <= separator + 1 ||
        content.length < terminator + 1 + hashBytes) {
      fail("INVALID_MIGRATION_GIT_TREE");
    }
    const mode = content.subarray(offset, separator).toString("ascii");
    const name = content.subarray(separator + 1, terminator);
    const objectId = content.subarray(terminator + 1, terminator + 1 + hashBytes).toString("hex");
    if (!VALID_GIT_TREE_MODES.has(mode) ||
        name.length === 0 || name.includes(0x2f) || name.equals(Buffer.from(".")) ||
        name.equals(Buffer.from(".."))) {
      fail("INVALID_MIGRATION_GIT_TREE");
    }
    const entry = { mode, name, objectId };
    const previous = entries.at(-1);
    if (previous && (previous.name.equals(entry.name) || compareGitTreeEntries(previous, entry) >= 0)) {
      fail("INVALID_MIGRATION_GIT_TREE");
    }
    entries.push(entry);
    offset = terminator + 1 + hashBytes;
  }
  return entries;
}

function compareGitTreeEntries(left, right) {
  const commonLength = Math.min(left.name.length, right.name.length);
  for (let index = 0; index < commonLength; index += 1) {
    if (left.name[index] !== right.name[index]) return left.name[index] - right.name[index];
  }
  const leftNext = left.name.length === commonLength
    ? (left.mode === "40000" ? 0x2f : 0)
    : left.name[commonLength];
  const rightNext = right.name.length === commonLength
    ? (right.mode === "40000" ? 0x2f : 0)
    : right.name[commonLength];
  return leftNext - rightNext;
}

export function parseCommitTreeObjectId(content, hashBytes) {
  const headerEnd = content.indexOf(Buffer.from("\n\n"));
  if (headerEnd < 0) fail("INVALID_MIGRATION_GIT_TREE");
  const lines = content.subarray(0, headerEnd).toString("latin1").split("\n");
  const objectIdPattern = new RegExp(`^[a-f0-9]{${hashBytes * 2}}$`, "u");
  const firstTree = /^tree ([a-f0-9]+)$/u.exec(lines[0] ?? "");
  if (!firstTree || !objectIdPattern.test(firstTree[1])) fail("INVALID_MIGRATION_GIT_TREE");
  let previousHeader = null;
  let phase = 0;
  let treeCount = 0;
  let authorCount = 0;
  let committerCount = 0;
  for (const line of lines) {
    if (line.includes("\r") || line.includes("\0")) fail("INVALID_MIGRATION_GIT_TREE");
    if (line.startsWith(" ")) {
      if (!new Set(["gpgsig", "gpgsig-sha256", "mergetag"]).has(previousHeader)) {
        fail("INVALID_MIGRATION_GIT_TREE");
      }
      continue;
    }
    const separator = line.indexOf(" ");
    if (separator <= 0 || !/^[A-Za-z][A-Za-z0-9-]*$/u.test(line.slice(0, separator))) {
      fail("INVALID_MIGRATION_GIT_TREE");
    }
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (key === "tree") {
      treeCount += 1;
      if (phase !== 0 || treeCount !== 1 || !objectIdPattern.test(value) || value !== firstTree[1]) {
        fail("INVALID_MIGRATION_GIT_TREE");
      }
      phase = 1;
    } else if (key === "parent") {
      if (phase > 1 || !objectIdPattern.test(value)) fail("INVALID_MIGRATION_GIT_TREE");
    } else if (key === "author") {
      authorCount += 1;
      if (phase > 2 || authorCount !== 1 || value.length === 0) fail("INVALID_MIGRATION_GIT_TREE");
      phase = 2;
    } else if (key === "committer") {
      committerCount += 1;
      if (phase > 3 || authorCount !== 1 || committerCount !== 1 || value.length === 0) {
        fail("INVALID_MIGRATION_GIT_TREE");
      }
      phase = 3;
    } else if (phase < 3) {
      fail("INVALID_MIGRATION_GIT_TREE");
    }
    previousHeader = key;
  }
  if (treeCount !== 1 || authorCount !== 1 || committerCount !== 1) {
    fail("INVALID_MIGRATION_GIT_TREE");
  }
  return firstTree[1];
}

function readVerifiedTree(repositoryRoot, objectId, objectFormat, hashBytes) {
  const content = gitBuffer(["cat-file", "tree", objectId], repositoryRoot);
  verifyGitObjectId("tree", content, objectId, objectFormat);
  return parseGitTree(content, hashBytes);
}

function findVerifiedTree(repositoryRoot, rootTreeObjectId, segments, objectFormat, hashBytes) {
  let currentTreeObjectId = rootTreeObjectId;
  for (const segment of segments) {
    const entry = readVerifiedTree(repositoryRoot, currentTreeObjectId, objectFormat, hashBytes)
      .find((candidate) => candidate.name.equals(Buffer.from(segment, "utf8")));
    if (!entry || entry.mode !== "40000") fail("INVALID_MIGRATION_GIT_TREE");
    currentTreeObjectId = entry.objectId;
  }
  return currentTreeObjectId;
}

function committedMigrationInventory(migrationDirectory, approvedSourceSha) {
  if (typeof approvedSourceSha !== "string" || !/^[a-f0-9]{40,64}$/u.test(approvedSourceSha)) {
    fail("MISSING_APPROVED_SOURCE_SHA");
  }

  const repositoryRoot = gitText(["rev-parse", "--show-toplevel"], migrationDirectory);
  const canonicalRoot = realpathSync(repositoryRoot);
  const canonicalMigrationDirectory = realpathSync(migrationDirectory);
  if (!samePath(repositoryRoot, canonicalRoot) ||
      !samePath(migrationDirectory, canonicalMigrationDirectory)) {
    fail("INVALID_MIGRATION_DIRECTORY");
  }
  const relativeDirectory = path.relative(canonicalRoot, canonicalMigrationDirectory).split(path.sep).join("/");
  if (relativeDirectory !== "packages/database/prisma/migrations") {
    fail("INVALID_MIGRATION_DIRECTORY");
  }
  const directoryChain = snapshotDirectoryChain(
    canonicalMigrationDirectory, "INVALID_MIGRATION_DIRECTORY", canonicalRoot
  );
  const { objectFormat, hashBytes, objectDirectoryChain, objectDirectorySnapshots, objectFileSnapshots } =
    assertTrustedGitObjectStore(repositoryRoot, approvedSourceSha);
  const resolvedSourceSha = gitText(["rev-parse", "--verify", `${approvedSourceSha}^{commit}`], repositoryRoot);
  const headSha = gitText(["rev-parse", "HEAD"], repositoryRoot);
  if (resolvedSourceSha !== approvedSourceSha || headSha !== approvedSourceSha) {
    fail("APPROVED_SOURCE_SHA_MISMATCH");
  }

  const committedCommit = gitBuffer(["cat-file", "commit", approvedSourceSha], repositoryRoot);
  verifyGitObjectId("commit", committedCommit, approvedSourceSha, objectFormat);
  const rootTreeObjectId = parseCommitTreeObjectId(committedCommit, hashBytes);
  const migrationTreeObjectId = findVerifiedTree(
    repositoryRoot,
    rootTreeObjectId,
    ["packages", "database", "prisma", "migrations"],
    objectFormat,
    hashBytes
  );
  const migrationTreeEntries = readVerifiedTree(
    repositoryRoot, migrationTreeObjectId, objectFormat, hashBytes
  );
  const tracked = new Map();
  let lockObject = null;

  for (const entry of migrationTreeEntries) {
    const name = entry.name.toString("utf8");
    if (!Buffer.from(name, "utf8").equals(entry.name)) fail("INVALID_MIGRATION_GIT_TREE");
    if (name === "migration_lock.toml") {
      if (entry.mode !== "100644") fail("INVALID_MIGRATION_GIT_TREE");
      if (lockObject !== null) fail("INVALID_MIGRATION_GIT_TREE");
      lockObject = entry.objectId;
      continue;
    }
    if (entry.mode !== "40000" || !/^[A-Za-z0-9_]+$/u.test(name) || tracked.has(name)) {
      fail("INVALID_MIGRATION_GIT_TREE");
    }
    const migrationFiles = readVerifiedTree(repositoryRoot, entry.objectId, objectFormat, hashBytes);
    if (migrationFiles.length !== 1 || migrationFiles[0].mode !== "100644" ||
        !migrationFiles[0].name.equals(Buffer.from("migration.sql", "utf8"))) {
      fail("INVALID_MIGRATION_GIT_TREE");
    }
    tracked.set(name, migrationFiles[0].objectId);
  }
  if (lockObject === null || tracked.size === 0) fail("NO_COMMITTED_MIGRATIONS");

  const expectedRootEntries = ["migration_lock.toml", ...tracked.keys()].sort();
  const actualRootEntries = readdirSync(canonicalMigrationDirectory).sort();
  if (actualRootEntries.length !== expectedRootEntries.length ||
      actualRootEntries.some((entry, index) => entry !== expectedRootEntries[index])) {
    fail("UNTRACKED_MIGRATION_ENTRY");
  }

  const committedLock = gitBuffer(["cat-file", "blob", lockObject], repositoryRoot);
  verifyGitObjectId("blob", committedLock, lockObject, objectFormat);
  const lockPath = path.join(canonicalMigrationDirectory, "migration_lock.toml");
  const migrationFileSnapshots = [];
  const workingLock = readRegularFile(lockPath, "INVALID_MIGRATION_LOCK_FILE", committedLock,
    "INVALID_MIGRATION_PROVIDER", migrationFileSnapshots);
  if (!workingLock.equals(committedLock) ||
      !/^provider\s*=\s*"postgresql"\s*$/mu.test(committedLock.toString("utf8"))) {
    fail("INVALID_MIGRATION_PROVIDER");
  }

  const expected = [];
  const migrationDirectoryChains = [];
  for (const [name, objectId] of tracked) {
    const migrationPath = path.join(canonicalMigrationDirectory, name);
    migrationDirectoryChains.push(snapshotDirectoryChain(
      migrationPath, "INVALID_MIGRATION_DIRECTORY", canonicalMigrationDirectory
    ));
    const files = readdirSync(migrationPath, { withFileTypes: true });
    if (files.length !== 1 || files[0].name !== "migration.sql" ||
        !files[0].isFile() || files[0].isSymbolicLink()) {
      fail("UNTRACKED_MIGRATION_ENTRY");
    }
    const sqlPath = path.join(migrationPath, "migration.sql");
    const committedSql = gitBuffer(["cat-file", "blob", objectId], repositoryRoot);
    verifyGitObjectId("blob", committedSql, objectId, objectFormat);
    const workingSql = readRegularFile(sqlPath, "INVALID_MIGRATION_SQL_FILE", committedSql,
      "MIGRATION_SOURCE_TREE_MISMATCH", migrationFileSnapshots);
    if (!workingSql.equals(committedSql)) {
      fail("MIGRATION_SOURCE_TREE_MISMATCH");
    }
    expected.push({ name, checksum: createHash("sha256").update(committedSql).digest("hex") });
  }
  expected.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  for (const chain of migrationDirectoryChains) verifyDirectoryChain(chain);
  verifyDirectoryChain(directoryChain);
  verifyDirectoryChain(objectDirectoryChain);
  for (const snapshot of objectDirectorySnapshots) {
    const current = lstatSync(snapshot.path, { bigint: true });
    const currentNames = readObjectStoreNames(snapshot.path, snapshot.names.length);
    if (!current.isDirectory() || current.isSymbolicLink() ||
        !sameFileIdentity(snapshot.stat, current) ||
        currentNames.length !== snapshot.names.length ||
        currentNames.some((name, index) => name !== snapshot.names[index])) {
      fail("UNTRUSTED_GIT_OBJECT_STORE");
    }
  }
  for (const snapshot of objectFileSnapshots) verifyRegularFileSnapshot(snapshot);
  for (const snapshot of migrationFileSnapshots) {
    verifyRegularFileSnapshot(snapshot, "MIGRATION_SOURCE_TREE_MISMATCH");
  }
  return expected;
}

/**
 * Compares a point-in-time Prisma ledger snapshot against committed migrations
 * and raw checkout bytes. It cannot guarantee that the database rows or SQL
 * files remain unchanged at a later migration/execution step; the operator must
 * maintain the required isolation or revalidate before using them.
 * Input rows are tab-separated: migration_name, checksum, finished, rolled_back.
 * In --hex-fields mode, the first two fields are lowercase hex-encoded UTF-8
 * bytes produced by PostgreSQL encode(convert_to(value, 'UTF8'), 'hex'). This
 * binds one physical SQL row to exactly one line, even for hostile text fields.
 */
export function verifyPrismaMigrationLedger({ migrationDirectory, ledgerText, approvedSourceSha, hexFields = false }) {
  if (typeof migrationDirectory !== "string" || migrationDirectory.length === 0) fail("MISSING_MIGRATION_DIRECTORY");
  if (typeof ledgerText !== "string" || ledgerText.trim().length === 0) fail("EMPTY_MIGRATION_LEDGER");
  if (Buffer.byteLength(ledgerText, "utf8") > MAX_LEDGER_BYTES) fail("INVALID_MIGRATION_LEDGER_ROW");

  const rootStat = lstatSync(migrationDirectory);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("INVALID_MIGRATION_DIRECTORY");
  const expected = committedMigrationInventory(migrationDirectory, approvedSourceSha);

  const actual = [];
  const seen = new Set();
  const lines = hexFields ? ledgerText.split("\n") : ledgerText.replaceAll("\r\n", "\n").split("\n");
  if (hexFields && lines.at(-1) === "") lines.pop(); // psql's single terminal newline
  for (const line of lines) {
    if (hexFields && (line === "" || line.includes("\r"))) fail("INVALID_MIGRATION_LEDGER_ROW");
    if (line === "") continue;
    const fields = line.split("\t");
    if (fields.length !== 4) fail("INVALID_MIGRATION_LEDGER_ROW");
    const [rawName, rawChecksum, finished, rolledBack] = fields;
    const name = hexFields ? decodeLedgerHexField(rawName, 255) : rawName;
    const checksum = hexFields ? decodeLedgerHexField(rawChecksum, 64) : rawChecksum;
    if (!/^[A-Za-z0-9_]+$/u.test(name) || !/^[a-f0-9]{64}$/u.test(checksum) ||
        finished !== "true" || rolledBack !== "false" || seen.has(name)) {
      fail("INVALID_MIGRATION_LEDGER_STATE");
    }
    seen.add(name);
    actual.push({ name, checksum });
  }
  actual.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  if (actual.length !== expected.length) fail("MIGRATION_LEDGER_SET_MISMATCH");
  for (let index = 0; index < expected.length; index += 1) {
    if (actual[index].name !== expected[index].name || actual[index].checksum !== expected[index].checksum) {
      fail("MIGRATION_LEDGER_CHECKSUM_MISMATCH");
    }
  }
  return true;
}

function decodeLedgerHexField(encoded, maximumBytes) {
  if (typeof encoded !== "string" || encoded.length === 0 ||
      encoded.length > maximumBytes * 2 || encoded.length % 2 !== 0 ||
      !/^[a-f0-9]+$/u.test(encoded)) {
    fail("INVALID_MIGRATION_LEDGER_ROW");
  }
  const bytes = Buffer.from(encoded, "hex");
  const decoded = bytes.toString("utf8");
  if (!Buffer.from(decoded, "utf8").equals(bytes) || /[\u0000-\u001f\u007f]/u.test(decoded)) {
    fail("INVALID_MIGRATION_LEDGER_ROW");
  }
  return decoded;
}

function readCliLedger() {
  const bytes = Buffer.alloc(MAX_LEDGER_BYTES + 1);
  let length = 0;
  while (length < bytes.length) {
    const count = readSync(0, bytes, length, bytes.length - length, null);
    if (count === 0) break;
    length += count;
  }
  if (length > MAX_LEDGER_BYTES) fail("INVALID_MIGRATION_LEDGER_ROW");
  const contents = bytes.subarray(0, length);
  const text = contents.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(contents)) fail("INVALID_MIGRATION_LEDGER_ROW");
  return text;
}

function runCli() {
  try {
    const argumentsList = process.argv.slice(2);
    if (argumentsList.length > 1 ||
        (argumentsList.length === 1 && argumentsList[0] !== "--hex-fields")) {
      fail("INVALID_MIGRATION_LEDGER_ROW");
    }
    verifyPrismaMigrationLedger({
      migrationDirectory: path.resolve(process.cwd(), "packages/database/prisma/migrations"),
      ledgerText: readCliLedger(),
      approvedSourceSha: process.env.VIRKI_STAGING_APPROVED_SOURCE_SHA,
      hexFields: argumentsList.length === 1
    });
    process.stdout.write("STAGING_PRISMA_MIGRATION_LEDGER=PASS\n");
    return 0;
  } catch {
    process.stderr.write("BLOCK:STAGING_PRISMA_MIGRATION_LEDGER\n");
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = runCli();
}
