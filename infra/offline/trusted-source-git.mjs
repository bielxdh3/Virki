import { execFileSync } from "node:child_process";
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync,
  readdirSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifySourceTarAgainstGit } from "../../scripts/lib/offline-source-tar-verifier.mjs";
import { inspectUntrustedOfflineCandidate } from "./trusted-host-entry.mjs";

// These locations are independently installed by the host administrator.
// Never load them from the candidate, its manifest, environment or CLI.
// This root-owned 0700 bare store must stay outside the ledger-only directory.
const FIXED_TRUSTED_GIT = "/var/lib/virki/offline-source/trusted.git";
const FIXED_HOST_PIN = "/etc/virki/offline-source-commit.sha";
const REVISION = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const MAX_ARCHIVE = 8 * 1024 * 1024 * 1024;
const MAX_ENTRIES = 100000;
const PREVIEW_KEYS = Object.freeze([
  "sourceArchivePath", "candidateSourceSha", "candidateArchiveSha256",
  "candidateArchiveSizeBytes", "trustedGitDirectory", "trustedShaPinPath",
]);
const GIT_ENV = Object.freeze({
  PATH: "/usr/bin:/bin", HOME: "/nonexistent", XDG_CONFIG_HOME: "/nonexistent",
  LC_ALL: "C", TZ: "UTC", GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_COUNT: "0", GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0", GIT_NO_LAZY_FETCH: "1",
  GIT_ALLOW_PROTOCOL: "", GIT_TERMINAL_PROMPT: "0", GIT_PAGER: "cat",
});

function refuse(reason) { throw new Error(`Trusted offline source Git refused: ${reason}`); }
function requireIt(ok, reason) { if (!ok) refuse(reason); }
function exact(value, fields) {
  requireIt(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((key) => Object.hasOwn(value, key)), "missing or untrusted request fields");
}
function same(a, b) {
  return ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function canonical(raw, label) {
  requireIt(typeof raw === "string" && raw.length > 1 && raw.length <= 4096 &&
    !raw.includes("\0") && path.isAbsolute(raw) && path.normalize(raw) === raw &&
    raw !== path.parse(raw).root, `${label} is not an absolute canonical path`);
  return raw;
}
function outsideTree(target, root) {
  const relative = path.relative(root, target);
  return relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
}
function assertRootAncestors(location) {
  let cursor = location;
  while (true) {
    const info = lstatSync(cursor, { bigint: true });
    requireIt(info.isDirectory() && !info.isSymbolicLink() && info.uid === 0n &&
      (info.mode & 0o022n) === 0n, "untrusted owner, writable ancestor or directory alias");
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  requireIt(realpathSync.native(location) === location, "directory path uses an alias");
}
function requirePrivateDirectory(location, label) {
  canonical(location, label);
  assertRootAncestors(location);
  const info = lstatSync(location, { bigint: true });
  requireIt(info.isDirectory() && (info.mode & 0o7777n) === 0o700n,
    `${label} must be root-owned private directory (0700)`);
  return info;
}
function readRootPin(filename) {
  canonical(filename, "host SHA pin");
  assertRootAncestors(path.dirname(filename));
  const before = optionalStat(filename);
  requireIt(before?.isFile() && !before.isSymbolicLink() && before.uid === 0n &&
    before.nlink === 1n && [0o400n, 0o600n].includes(before.mode & 0o7777n) &&
    before.size === 41n, "independent SHA pin must be root-owned, private and regular");
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    requireIt(same(before, fstatSync(fd, { bigint: true })), "SHA pin changed during open");
    const bytes = readFileSync(fd);
    requireIt(same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(filename, { bigint: true })), "SHA pin changed during read");
    const value = bytes.toString("ascii");
    requireIt(REVISION.test(value.slice(0, -1)) && value.endsWith("\n"),
      "invalid independent SHA pin syntax");
    return Object.freeze({ sha: value.slice(0, -1), info: before });
  } finally { closeSync(fd); }
}
function optionalStat(filename) {
  try { return lstatSync(filename, { bigint: true }); }
  catch (error) { if (error?.code === "ENOENT") return null; throw error; }
}
function requireNoGitAliases(gitDirectory) {
  // Only an isolated bare Git store is accepted. Alternate, grafted, shallow,
  // linked, or substituted repositories do not establish independent trust.
  for (const rel of ["commondir", "shallow", "info/grafts", "objects/info/alternates",
    "objects/info/http-alternates", "objects/replace", ".git"]) {
    requireIt(!optionalStat(path.join(gitDirectory, rel)), `unsafe Git ${rel} file or alias`);
  }
  let count = 0;
  function inspectTree(folder) {
    for (const item of readdirSync(folder, { withFileTypes: true })) {
      count++;
      requireIt(count <= 1000000 && item.name !== "." && item.name !== "..",
        "unbounded Git object store");
      const filename = path.join(folder, item.name);
      const stat = lstatSync(filename, { bigint: true });
      requireIt(stat.uid === 0n && (stat.mode & 0o022n) === 0n &&
        !stat.isSymbolicLink() &&
        (stat.isDirectory() || stat.isFile() && stat.nlink === 1n),
      "Git objects or refs have an untrusted owner, link or writable mode");
      requireIt(!item.name.endsWith(".promisor"),
        "Git partial-clone promisor objects are forbidden");
      if (stat.isDirectory()) inspectTree(filename);
    }
  }
  for (const relative of ["objects", "refs"]) {
    const directory = path.join(gitDirectory, relative);
    const stat = lstatSync(directory, { bigint: true });
    requireIt(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0n &&
      (stat.mode & 0o022n) === 0n, `Git ${relative} must be an owned real directory`);
    inspectTree(directory);
  }
  for (const relative of ["HEAD", "config", "packed-refs"]) {
    const stat = optionalStat(path.join(gitDirectory, relative));
    if (stat) requireIt(stat.isFile() && stat.uid === 0n && stat.nlink === 1n &&
      (stat.mode & 0o022n) === 0n, `unsafe Git ${relative}`);
  }
  const replace = path.join(gitDirectory, "refs", "replace");
  requireIt(!optionalStat(replace), "Git replacement refs are forbidden");
}
function git(repo, ...args) {
  // No shell, user environment, network, hooks, optional locks or candidate argv.
  try {
    const output = execFileSync("/usr/bin/git", ["--no-pager", `--git-dir=${repo}`, ...args], {
      env: GIT_ENV, encoding: "buffer", timeout: 30000, maxBuffer: 32 * 1024 * 1024,
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    return Buffer.from(output);
  } catch {
    refuse("trusted local Git object read or integrity check failed");
  }
}
function gitText(repo, ...args) {
  return new TextDecoder("utf-8", { fatal: true }).decode(git(repo, ...args)).trim();
}
function treePathSafe(value) {
  return value.length > 0 && value.length <= 4096 && !value.includes("\\") &&
    !Array.from(value).some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127) &&
    value.split("/").every((entry) => entry && entry !== "." && entry !== "..") &&
    !/^[A-Za-z]:/u.test(value);
}
function authenticatedGitTree(repo, revision) {
  const configKeys = gitText(repo, "config", "--local", "--name-only", "--list").split("\n");
  requireIt(configKeys.every((key) => !/^(?:remote\.|url\.|include\.|includeif\.|extensions\.partialclone$|core\.sshcommand$|core\.alternaterefscommand$|core\.fsmonitor$)/iu.test(key)),
    "trusted Git cannot use remote, include, partial clone or executable configuration");
  requireIt(gitText(repo, "rev-parse", "--is-bare-repository") === "true",
    "trusted Git must be a bare repository");
  requireIt(gitText(repo, "rev-parse", "--is-shallow-repository") === "false",
    "shallow Git object store is not independently complete");
  requireIt(gitText(repo, "rev-parse", "--show-object-format=storage") === "sha1",
    "unsupported trusted Git object format");
  requireIt(gitText(repo, "symbolic-ref", "HEAD") === "refs/heads/main" &&
    gitText(repo, "show-ref", "--verify", "--hash", "refs/heads/main") === revision,
  "host's independently maintained main must equal pinned commit");
  requireIt(gitText(repo, "cat-file", "-t", revision) === "commit",
    "pinned object is not a Git commit");
  // fsck validates the stored commit, tree and blob object identities, not just
  // their object IDs reported by ls-tree. This never fetches absent objects.
  git(repo, "fsck", "--strict", "--no-reflogs", "--no-progress", "--no-dangling", revision);
  const timestamp = gitText(repo, "show", "-s", "--format=%ct", revision);
  requireIt(/^(0|[1-9][0-9]*)$/u.test(timestamp) &&
    Number.isSafeInteger(Number(timestamp)), "pinned commit has invalid timestamp");
  const bytes = git(repo, "ls-tree", "-r", "-t", "-z", "--full-tree", revision);
  requireIt(bytes.length > 0 && bytes.at(-1) === 0, "invalid Git tree records");
  const records = new TextDecoder("utf-8", { fatal: true }).decode(bytes).split("\0");
  records.pop();
  requireIt(records.length > 0 && records.length <= MAX_ENTRIES, "Git tree is empty or excessive");
  const objects = new Map();
  const normalized = new Set();
  for (const record of records) {
    const match = /^(040000|100644|100755) (tree|blob) ([0-9a-f]{40})\t(.+)$/u.exec(record);
    requireIt(match && (match[1] === "040000") === (match[2] === "tree") &&
      treePathSafe(match[4]) && !normalized.has(match[4].toLowerCase()),
    "invalid Git file modes, ambiguous filename or unsupported entry");
    normalized.add(match[4].toLowerCase());
    objects.set(match[4], { mode: match[1], type: match[2], id: match[3] });
  }
  return Object.freeze({ objects, timestamp: Number(timestamp) });
}

async function inspectSource(request) {
  exact(request, PREVIEW_KEYS);
  requireIt(process.platform === "linux" && typeof process.getuid === "function" &&
    process.getuid() === 0 && constants.O_NOFOLLOW && constants.O_NONBLOCK,
  "Linux root with no-follow file handling is required");
  const { sourceArchivePath, candidateSourceSha, candidateArchiveSha256,
    candidateArchiveSizeBytes, trustedGitDirectory, trustedShaPinPath } = request;
  requireIt(REVISION.test(candidateSourceSha ?? "") &&
    DIGEST.test(candidateArchiveSha256 ?? "") &&
    Number.isSafeInteger(candidateArchiveSizeBytes) &&
    candidateArchiveSizeBytes >= 1024 && candidateArchiveSizeBytes <= MAX_ARCHIVE &&
    candidateArchiveSizeBytes % 512 === 0, "candidate SHA or archive claims malformed");
  canonical(sourceArchivePath, "candidate source archive");
  canonical(trustedGitDirectory, "trusted Git directory");
  canonical(trustedShaPinPath, "trusted SHA pin");
  requireIt(path.basename(sourceArchivePath) === "source.tar", "expected source.tar archive only");
  const candidateRoot = path.dirname(sourceArchivePath);
  requireIt(outsideTree(trustedGitDirectory, candidateRoot) &&
    outsideTree(candidateRoot, trustedGitDirectory) &&
    outsideTree(trustedShaPinPath, candidateRoot) &&
    outsideTree(trustedShaPinPath, trustedGitDirectory),
  "candidate, Git object store and host SHA pin must remain independent");
  const candidateBefore = requirePrivateDirectory(candidateRoot, "candidate directory");
  const tarBefore = lstatSync(sourceArchivePath, { bigint: true });
  requireIt(tarBefore.isFile() && !tarBefore.isSymbolicLink() &&
    tarBefore.uid === 0n && tarBefore.nlink === 1n &&
    (tarBefore.mode & 0o7777n) === 0o600n &&
    tarBefore.size === BigInt(candidateArchiveSizeBytes),
  "candidate source archive must be root-owned 0600, single-link regular file");
  const pin = readRootPin(trustedShaPinPath);
  requireIt(pin.sha === candidateSourceSha, "candidate SHA differs from independent host pin");
  const rootBefore = requirePrivateDirectory(trustedGitDirectory, "independent bare Git directory");
  requireNoGitAliases(trustedGitDirectory);
  const source = authenticatedGitTree(trustedGitDirectory, pin.sha);
  // Existing streaming parser hashes actual TAR member contents as Git blobs,
  // and independently compares file modes, directory entries and timestamp.
  const verified = verifySourceTarAgainstGit(sourceArchivePath, pin.sha, source.objects, source.timestamp);
  requireIt(verified.sha256 === candidateArchiveSha256 &&
    verified.sizeBytes === candidateArchiveSizeBytes,
  "source archive differs from candidate's declared digest or size");
  requireNoGitAliases(trustedGitDirectory);
  requireIt(same(tarBefore, lstatSync(sourceArchivePath, { bigint: true })) &&
    same(candidateBefore, lstatSync(candidateRoot, { bigint: true })) &&
    same(rootBefore, lstatSync(trustedGitDirectory, { bigint: true })) &&
    same(pin.info, lstatSync(trustedShaPinPath, { bigint: true })),
  "trusted pin, Git repository or candidate changed during inspection");
  return Object.freeze({ status: "INDEPENDENT_GIT_SOURCE_PREVIEW_ONLY",
    deployAuthorized: false, sourceSha: pin.sha, archiveSha256: verified.sha256,
    archiveSizeBytes: verified.sizeBytes, treeEntries: source.objects.size });
}

/** Caller-provided trust locations are useful only for adversarial preview tests.
 * This is NEVER an authorization channel. Real operators must use the fixed
 * host-provisioned verifier below, with its independent immutable trust roots.
 */
export async function inspectUntrustedSourceGitForPreview(request = {}) {
  return inspectSource(request);
}

/** Native installed-host READ-ONLY source inspection. No trusted path, SHA or
 * expected digest is accepted from the caller; there is no activation API.
 * Candidate manifest/signature acceptance remains a separate blocked gate.
 */
export async function verifyInstalledTrustedSourceGit(request = {}) {
  requireIt(process.platform === "linux" && process.arch === "x64" &&
    typeof process.getuid === "function" && process.getuid() === 0 &&
    !/microsoft|wsl/iu.test(os.release()),
  "native Linux/amd64 root required; WSL and Docker Desktop kernels forbidden");
  exact(request, ["candidateDirectory"]);
  const inspected = await inspectUntrustedOfflineCandidate(request);
  const source = await inspectSource({
    sourceArchivePath: inspected.archivePaths.source,
    candidateSourceSha: inspected.expected.sourceSha,
    candidateArchiveSha256: inspected.expected.sourceArchiveSha256,
    candidateArchiveSizeBytes: inspected.expected.sourceArchiveSizeBytes,
    trustedGitDirectory: FIXED_TRUSTED_GIT,
    trustedShaPinPath: FIXED_HOST_PIN,
  });
  return Object.freeze({ ...source, status: "INDEPENDENT_GIT_SOURCE_INSPECTED_RELEASE_BLOCKED",
    deployAuthorized: false });
}
