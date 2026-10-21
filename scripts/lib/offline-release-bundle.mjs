import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants, chmodSync, closeSync, fstatSync, lstatSync, mkdirSync, openSync,
  readFileSync, realpathSync, readdirSync, rmdirSync, statfsSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { inventoryOfflineArtifacts } from "./offline-artifact-inventory.mjs";
import { validateOfflineCiEvidence } from "./offline-ci-evidence.mjs";

const SOURCE = "https://github.com/bielxdh3/Virki.git";
const OCI_SOURCE = "https://github.com/bielxdh3/Virki";
const SHA = /^[0-9a-f]{40}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const FILENAMES = new Set(["ci.json", "source.tar", "runtime.tar", "migrator.tar"]);
const RESERVED = new Set([".env", ".npmrc", ".dev.vars", ".ghcr-read-token", ".production.operator.json",
  ".virki-release", ".virki-production-host", "backups", "backup", "dumps", "releases",
  "current", "google takeout", "takeout", "gmail", "attachments", "secrets"]);
const DANGEROUS_SUFFIX = /\.(?:pem|key|p12|pfx|der|jks|keystore|zip|tar|tgz|mbox|log|sqlite3?|db|dump|bak|backup)(?:\.(?:gz|gzip|bz2|xz|zst|lz4))*$/iu;

function reject(reason) { throw new Error(`Offline bundle preparation rejected: ${reason}`); }

async function defaultRunner(program, args, { cwd, env, input } = {}) {
  // All paths and arguments are individual argv entries. No shell or command substitution.
  return new Promise((resolve, rejectPromise) => {
    const child = spawn(program, args, { cwd, env, shell: false, windowsHide: true,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    const chunks = [];
    let length = 0;
    let aborted = false;
    const collect = (chunk) => {
      length += chunk.length;
      if (length > 8 * 1024 * 1024) {
        aborted = true;
        child.kill();
      } else chunks.push(chunk);
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", (chunk) => {
      length += chunk.length;
      if (length > 8 * 1024 * 1024) { aborted = true; child.kill(); }
    });
    child.once("error", rejectPromise);
    if (input !== undefined) child.stdin.end(input);
    child.once("close", (code, signal) => {
      if (aborted || code !== 0 || signal) rejectPromise(new Error(`${program} failed`));
      else resolve(Buffer.concat(chunks).toString("utf8"));
    });
  });
}

function safeAbsolute(raw, label) {
  if (typeof raw !== "string" || raw.includes("\0") || raw.length > 4096 ||
      !path.isAbsolute(raw) || path.normalize(raw) !== raw) reject(`${label} must be a canonical absolute path`);
  return raw;
}

function assertNoAliases(raw, directory = false) {
  let cursor = raw;
  while (true) {
    const stat = lstatSync(cursor, { bigint: true });
    if (stat.isSymbolicLink() || (cursor !== raw && !stat.isDirectory()) ||
        (cursor === raw && directory && !stat.isDirectory())) reject("symlink or unsafe directory alias");
    const parent = path.dirname(cursor);
    if (parent === cursor) return;
    cursor = parent;
  }
}

function sameStat(a, b) {
  return ["dev", "ino", "size", "nlink", "mtimeNs", "ctimeNs", "mode"].every((key) => a[key] === b[key]);
}

function sameDirectory(a, b) {
  // Directory mtime, ctime, and size change normally while staging files.
  return a.isDirectory() && b.isDirectory() &&
    ["dev", "ino", "mode"].every((key) => a[key] === b[key]);
}

function readPinnedCi(ciManifestPath) {
  assertNoAliases(ciManifestPath);
  const before = lstatSync(ciManifestPath, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > 65536n) reject("invalid CI evidence file");
  const fd = openSync(ciManifestPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!sameStat(before, fstatSync(fd, { bigint: true }))) reject("CI evidence changed before reading");
    const bytes = readFileSync(fd);
    if (!sameStat(before, fstatSync(fd, { bigint: true })) ||
        !sameStat(before, lstatSync(ciManifestPath, { bigint: true }))) reject("CI evidence changed during reading");
    return bytes;
  } finally { closeSync(fd); }
}

function sensitivePath(entry) {
  const name = entry.toLowerCase().replaceAll("\\", "/").replace(/\/+$/u, "");
  const segments = name.split("/");
  if (name === "infra/backups" || name === "infra/backups/.gitkeep") return false;
  return segments.some((segment) => RESERVED.has(segment) || segment.startsWith(".dev.vars.") ||
    (segment.startsWith(".env.") && segment !== ".env.example") ||
    /^mail-attachments?$/u.test(segment) || /^takeout(?:[-_.]|$)/u.test(segment)) ||
    (segments[0] === "infra" && segments[1] === "cloudflare" && name.endsWith(".json")) ||
    /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)$/iu.test(name) ||
    (DANGEROUS_SUFFIX.test(name) && !/^packages\/database\/prisma\/migrations\/[^/]+\/migration\.sql$/iu.test(name)) ||
    (/\.(?:sql|sqlite|db)(?:\.|$)/iu.test(name) &&
     !/^packages\/database\/prisma\/migrations\/[^/]+\/migration\.sql$/iu.test(name));
}

function safeTreePath(entry) {
  return typeof entry === "string" && entry.length > 0 && entry.length < 4096 &&
    !entry.includes("\\") && !entry.includes("\r") && !entry.includes("\n") &&
    !entry.includes("\0") && entry.split("/").every((s) => s && s !== "." && s !== "..") &&
    !/^[a-zA-Z]:/u.test(entry) && !sensitivePath(entry);
}

async function gitSourceGate(repositoryRoot, revision, runner) {
  const env = { ...process.env, GIT_NO_REPLACE_OBJECTS: "1", GIT_TERMINAL_PROMPT: "0" };
  const git = async (...args) => (await runner("git", args, { cwd: repositoryRoot, env })).trim();
  const gitRaw = (...args) => runner("git", args, { cwd: repositoryRoot, env });
  if (path.resolve(await git("rev-parse", "--show-toplevel")) !== repositoryRoot ||
      realpathSync(repositoryRoot) !== repositoryRoot) reject("Git repository root is unexpected");
  if (await git("branch", "--show-current") !== "main") reject("source branch must be main");
  if (await git("remote", "get-url", "origin") !== SOURCE) reject("foreign origin repository");
  if (await git("rev-parse", "--verify", "HEAD") !== revision ||
      await git("rev-parse", "--verify", "refs/remotes/origin/main") !== revision) {
    reject("HEAD differs from exact SHA or local origin/main");
  }
  if (await gitRaw("status", "--porcelain=v1", "-z", "--untracked-files=all")) {
    reject("source contains staged, tracked or untracked changes");
  }
  const raw = await gitRaw("ls-tree", "-r", "-t", "-z", "--full-tree", revision);
  const paths = [];
  const unique = new Set();
  for (const record of raw.split("\0")) {
    if (!record) continue;
    const match = /^(040000|100644|100755) (tree|blob) ([0-9a-f]{40,64})\t([^\0]+)$/u.exec(record);
    if (!match || (match[1] === "040000") !== (match[2] === "tree") ||
        !safeTreePath(match[4]) || unique.has(match[4].toLowerCase())) reject("unsafe source tree entry");
    unique.add(match[4].toLowerCase());
    paths.push(match[4]);
  }
  if (!paths.length) reject("empty source tree");
  const attrs = await runner("git", ["check-attr", "--cached", "-z", "export-ignore", "export-subst", "--stdin"],
    { cwd: repositoryRoot, env, input: paths.join("\0") + "\0" });
  const cells = attrs.split("\0").filter(Boolean);
  if (cells.length !== paths.length * 6) reject("ambiguous archive attributes");
  for (let i = 0; i < cells.length; i += 3) {
    if (!paths.includes(cells[i]) || !["export-ignore", "export-subst"].includes(cells[i + 1]) ||
        !["unspecified", "unset", "false"].includes(cells[i + 2])) reject("Git archive attributes could alter source");
  }
  return { env, git, paths };
}

async function readDockerImage(imageId, role, revision, runner) {
  const raw = await runner("docker", ["image", "inspect", imageId]);
  if (typeof raw !== "string" || raw.length > 1024 * 1024) reject("invalid Docker inspect output");
  let image;
  try { const images = JSON.parse(raw); if (images?.length !== 1) reject("unexpected image count"); [image] = images; }
  catch { reject("malformed Docker inspect output"); }
  if (image?.Id !== imageId || !Number.isSafeInteger(image.Size) || image.Size <= 0 ||
      image.Os !== "linux" || image.Architecture !== "amd64" ||
      image.Config?.Labels?.["org.opencontainers.image.revision"] !== revision ||
      image.Config?.Labels?.["org.opencontainers.image.source"] !== OCI_SOURCE ||
      !["node", "node:node", "1000", "1000:1000"].includes(image.Config?.User)) {
    reject(`${role} image identity, source, platform or non-root user differs`);
  }
  return { role, imageId, sizeBytes: image.Size, os: image.Os,
    architecture: image.Architecture, labels: {
      "org.opencontainers.image.revision": revision,
      "org.opencontainers.image.source": OCI_SOURCE,
    } };
}

function requireTarEntries(list, role) {
  const entries = list.split(/\r?\n/u).filter(Boolean);
  if (entries.length === 0 || entries.length > 100000 || entries.some((entry) => !safeTreePath(entry.replace(/\/$/u, "")))) {
    reject(`${role} tar archive listing is unsafe`);
  }
  return entries.map((entry) => entry.replace(/\/$/u, ""));
}

function reserveArchive(filename) {
  const fd = openSync(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
    constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
  try { return fstatSync(fd, { bigint: true }); }
  finally { closeSync(fd); }
}

function assertSameArchive(filename, expected) {
  const stat = lstatSync(filename, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n ||
      stat.dev !== expected.dev || stat.ino !== expected.ino || stat.size <= 0n) {
    reject("archive output was replaced or is incomplete");
  }
}

function removeOwnedStaging(directory, identity) {
  // Never recursively follow an unexpected replacement of the newly created tree.
  if (!sameDirectory(lstatSync(directory, { bigint: true }), identity)) reject("staging was replaced; manual cleanup required");
  for (const name of readdirSync(directory)) {
    if (!FILENAMES.has(name)) reject("foreign staging entry; manual cleanup required");
    const filename = path.join(directory, name);
    const meta = lstatSync(filename, { bigint: true });
    if (!meta.isFile() || meta.isSymbolicLink() || meta.nlink !== 1n) reject("unsafe staging entry; manual cleanup required");
    unlinkSync(filename);
  }
  rmdirSync(directory);
}

/** Prepare only a local unsigned offline bundle from a clean, locally fetched main.
 * No Docker build/pull/tag, Git fetch, registry lookup, SSH or production actions.
 * Returned evidence is a local claim; a separate trusted signer and native host
 * verifier must independently authenticate and check the entire bundle.
 */
export async function prepareOfflineReleaseBundle({
  repositoryRoot, revision, stagingParent, ciManifestPath, images, runner = defaultRunner,
} = {}) {
  if (!SHA.test(revision ?? "") || !images ||
      !IMAGE_ID.test(images.runtime ?? "") || !IMAGE_ID.test(images.migrator ?? "") ||
      images.runtime === images.migrator || typeof runner !== "function") reject("invalid release inputs");
  const repo = safeAbsolute(repositoryRoot, "repository root");
  const parent = safeAbsolute(stagingParent, "staging parent");
  const ciPath = safeAbsolute(ciManifestPath, "CI evidence");
  assertNoAliases(repo, true);
  assertNoAliases(parent, true);
  const rel = path.relative(repo, parent);
  if (rel === "" || (!rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel))) {
    reject("staging parent must be outside the source tree");
  }
  const beforeParent = lstatSync(parent, { bigint: true });
  const bytes = readPinnedCi(ciPath);
  const ciEvidence = validateOfflineCiEvidence(bytes, revision, "main");
  const git = await gitSourceGate(repo, revision, runner);
  const imageMetadata = {
    runtime: await readDockerImage(images.runtime, "runtime", revision, runner),
    migrator: await readDockerImage(images.migrator, "migrator", revision, runner),
  };
  const available = statfsSync(parent, { bigint: true });
  const remaining = available.bavail * available.bsize;
  const estimate = (BigInt(imageMetadata.runtime.sizeBytes) + BigInt(imageMetadata.migrator.sizeBytes)) * 2n +
    512n * 1024n * 1024n;
  if (remaining < estimate) reject("insufficient local staging disk budget");
  if (!sameStat(beforeParent, lstatSync(parent, { bigint: true }))) reject("staging parent was replaced");
  const directory = path.join(parent, `virki-offline-${revision.slice(0, 12)}-${randomBytes(12).toString("hex")}`);
  mkdirSync(directory, { mode: 0o700 });
  if (process.platform !== "win32") chmodSync(directory, 0o700);
  const identity = lstatSync(directory, { bigint: true });
  const sourceArchivePath = path.join(directory, "source.tar");
  const runtimeArchivePath = path.join(directory, "runtime.tar");
  const migratorArchivePath = path.join(directory, "migrator.tar");
  try {
    // Preallocate all three names exclusively in the private directory so a
    // producer cannot accidentally open a caller-provided symlink or hardlink.
    const pinned = new Map([[sourceArchivePath, reserveArchive(sourceArchivePath)],
      [runtimeArchivePath, reserveArchive(runtimeArchivePath)],
      [migratorArchivePath, reserveArchive(migratorArchivePath)]]);
    // Both archive producers receive immutable content identities (SHA or image ID).
    await runner("git", ["archive", "--format=tar", `--output=${sourceArchivePath}`, revision],
      { cwd: repo, env: git.env });
    assertSameArchive(sourceArchivePath, pinned.get(sourceArchivePath));
    const sourceEntries = requireTarEntries(await runner("tar", ["-tf", sourceArchivePath]), "source");
    if (sourceEntries.length !== git.paths.length ||
        new Set(sourceEntries).size !== sourceEntries.length ||
        sourceEntries.some((entry) => !git.paths.includes(entry))) reject("source archive does not match Git tree listing");
    for (const [role, target] of [["runtime", runtimeArchivePath], ["migrator", migratorArchivePath]]) {
      await runner("docker", ["save", "--output", target, imageMetadata[role].imageId]);
      assertSameArchive(target, pinned.get(target));
      requireTarEntries(await runner("tar", ["-tf", target]), role);
    }
    // Recheck live Docker IDs and source after writes before measuring content.
    for (const role of ["runtime", "migrator"]) {
      const checked = await readDockerImage(images[role], role, revision, runner);
      if (JSON.stringify(checked) !== JSON.stringify(imageMetadata[role])) reject("image metadata shifted during archive creation");
    }
    await gitSourceGate(repo, revision, runner);
    writeFileSync(path.join(directory, "ci.json"), bytes, { flag: "wx", mode: 0o600 });
    const inventory = await inventoryOfflineArtifacts({ artifactRoot: directory, sourceArchivePath,
      runtimeArchivePath, migratorArchivePath, expectedRevision: revision, images: imageMetadata });
    if (!sameDirectory(identity, lstatSync(directory, { bigint: true })) ||
        !sameDirectory(beforeParent, lstatSync(parent, { bigint: true }))) reject("staging identity changed");
    return Object.freeze({ directory, sourceArchivePath, runtimeArchivePath, migratorArchivePath,
      ciEvidence, imageMetadata: Object.freeze(imageMetadata), inventory });
  } catch (error) {
    try { removeOwnedStaging(directory, identity); }
    catch (cleanupError) {
      throw new AggregateError([error, cleanupError],
        "Offline preparation failed and staging needs manual inspection", { cause: error });
    }
    throw error;
  }
}
