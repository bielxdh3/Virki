import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync, closeSync, constants, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, realpathSync, readdirSync,
  renameSync, rmSync, readSync, writeSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AUDITED_VERIFIER_FILES } from "../infra/offline/trusted-host-installer.mjs";
import { pinnedWindowsPathToWsl } from "./offline-manual-image-build.mjs";

// Review and handoff of exact bytes only. The independently installed owner
// bootstrap remains the ONLY authority to install or activate those bytes.
const NATIVE_FILES = Object.freeze([
  "infra/offline/native-supervisor/native-docker-fd-transport.c",
  "infra/offline/native-supervisor/native-docker-fd-transport.h",
  "infra/offline/isolated-docker-daemon-identity.mjs",
  "infra/offline/manual-native-image-receipt.mjs",
]);
export const NATIVE_HOST_REVIEW_FILES = Object.freeze([...AUDITED_VERIFIER_FILES, ...NATIVE_FILES]);
const HEX40 = /^[a-f0-9]{40}$/u;
const HEX64 = /^[a-f0-9]{64}$/u;
const ID = /^sha256:[a-f0-9]{64}$/u;
const BLOCK = 64 * 1024;
const FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const CREATE = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;

function need(ok, message = "review package invariant") {
  if (!ok) throw new Error(`Native manual host review package refused: ${message}`);
}
function exact(value, keys) {
  need(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key, i) => Object.keys(value)[i] === key), "unexpected inventory fields");
}
function canonical(p) {
  need(typeof p === "string" && p.length > 1 && p.length <= 4096 &&
    path.isAbsolute(p) && path.normalize(p) === p &&
    p !== path.parse(p).root && !p.includes("\0"), "unsafe path");
  return p;
}
function noAlias(p) {
  need(realpathSync.native(p) === p, "path alias");
  for (let cursor = p;; cursor = path.dirname(cursor)) {
    const st = lstatSync(cursor, { bigint: true });
    need(st.isDirectory() && !st.isSymbolicLink(), "symlinked ancestor");
    if (cursor === path.dirname(cursor)) break;
  }
}
function same(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
const hash = (b) => createHash("sha256").update(b).digest("hex");
function privateDir(dir) {
  noAlias(canonical(dir));
  const st = lstatSync(dir, { bigint: true });
  need(st.uid === BigInt(process.getuid()) && (st.mode & 0o7777n) === 0o700n,
    "staging parent must be owner private 0700");
}
function receiptFilename(directory, filename) {
  if (typeof directory === "string" && directory.startsWith("E:\\")) {
    const converted = pinnedWindowsPathToWsl(directory);
    return { expected: path.posix.join(converted, filename),
      normalize: pinnedWindowsPathToWsl };
  }
  const root = canonical(directory);
  return { expected: path.join(root, filename), normalize: canonical };
}
function fsyncDir(dir) {
  const fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

/** Read-only checks of an UNSIGNED developer image-build receipt (no signing keys). */
export function verifyManualNativeImageReceiptForReview(receipt) {
  exact(receipt, ["status", "sourceSha", "directory", "sourceArchive",
    "sourceArchiveSha256", "images", "npmCacheLockSha256", "npmCachePackagesVerified",
    "prismaEngineCommit", "prismaEngineTarget", "hostedCi", "codeql", "ghcr",
    "ownerSignatureVerified", "deployAuthorized", "transferAuthorized"]);
  need(receipt.status === "LOCAL_SOURCE_AND_IMAGES_VERIFIED_ONLY" &&
    HEX40.test(receipt.sourceSha) && !/^0+$/u.test(receipt.sourceSha) &&
    HEX64.test(receipt.sourceArchiveSha256) &&
    HEX64.test(receipt.npmCacheLockSha256) &&
    receipt.npmCachePackagesVerified === 339 &&
    HEX40.test(receipt.prismaEngineCommit) &&
    typeof receipt.prismaEngineTarget === "string" &&
    receipt.prismaEngineTarget.length > 0 && receipt.prismaEngineTarget.length <= 128 &&
    receipt.hostedCi === "NOT_RUN" && receipt.codeql === "NOT_RUN" &&
    receipt.ghcr === "NOT_USED" && receipt.ownerSignatureVerified === false &&
    receipt.deployAuthorized === false && receipt.transferAuthorized === false,
  "unsigned builder provenance malformed");
  const source = receiptFilename(receipt.directory, "source.tar");
  need(source.normalize(receipt.sourceArchive) === source.expected,
    "source archive outside receipt root");
  exact(receipt.images, ["runtime", "migrator"]);
  const images = ["runtime", "migrator"].map((role) => {
    const image = receipt.images[role];
    need(image && typeof image === "object" && !Array.isArray(image) &&
      image.role === role && ID.test(image.imageId) &&
      HEX64.test(image.archiveSha256) &&
      Number.isSafeInteger(image.archiveSizeBytes) &&
      image.archiveSizeBytes > 0 && image.archiveSizeBytes <= 8 * 1024 ** 3 &&
      image.archiveSizeBytes % 512 === 0 &&
      receiptFilename(receipt.directory, `${role}.tar`).normalize(image.archivePath) ===
        receiptFilename(receipt.directory, `${role}.tar`).expected,
    "image role, digest, size or location malformed");
    return Object.freeze({ role, imageId: image.imageId,
      archiveSha256: image.archiveSha256, archiveSizeBytes: image.archiveSizeBytes });
  });
  need(images[0].imageId !== images[1].imageId &&
    images[0].archiveSha256 !== images[1].archiveSha256,
  "duplicate native runtime/migrator identities");
  return Object.freeze({ sourceSha: receipt.sourceSha, images: Object.freeze(images) });
}

function stageFile(source, destination) {
  const before = lstatSync(source, { bigint: true });
  need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
    before.size > 0n && before.size <= 2n * 1024n * 1024n,
  "review source must be bounded regular single-link file");
  const fd = openSync(source, FLAGS);
  try {
    need(same(before, fstatSync(fd, { bigint: true })), "source replaced at open");
    const writer = openSync(destination, CREATE, 0o600);
    const digest = createHash("sha256");
    try {
      const block = Buffer.allocUnsafe(BLOCK);
      for (let position = 0; position < Number(before.size);) {
        const amount = Math.min(block.length, Number(before.size) - position);
        const n = readSync(fd, block, 0, amount, position);
        need(n > 0, "source short read");
        digest.update(block.subarray(0, n));
        for (let written = 0; written < n;) {
          const count = writeSync(writer, block, written, n - written);
          need(count > 0, "staging short write");
          written += count;
        }
        position += n;
      }
      fsyncSync(writer);
      need(fstatSync(writer, { bigint: true }).size === before.size,
        "staged file length changed");
    } finally { closeSync(writer); }
    need(same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(source, { bigint: true })), "review source mutated");
    const sha = digest.digest("hex");
    const dst = lstatSync(destination, { bigint: true });
    need(dst.isFile() && dst.nlink === 1n && dst.uid === BigInt(process.getuid()) &&
      (dst.mode & 0o7777n) === 0o600n &&
      hash(readFileSync(destination)) === sha, "staged file readback mismatch");
    return sha;
  } finally { closeSync(fd); }
}

// Copies only from the same pinned descriptor; no source pathname reopen.
function stageTree(repositoryRoot, packageRoot, files, group) {
  const result = [];
  for (const name of files) {
    const source = path.join(repositoryRoot, ...name.split("/"));
    noAlias(path.dirname(source));
    const destination = path.join(packageRoot, group, ...name.split("/"));
    const segments = path.dirname(destination).slice(packageRoot.length + 1).split(path.sep);
    let parent = packageRoot;
    for (const segment of segments) {
      parent = path.join(parent, segment);
      if (!readdirSync(path.dirname(parent)).includes(segment)) mkdirSync(parent, { mode: 0o700 });
      chmodSync(parent, 0o700);
    }
    const sha256 = stageFile(source, destination);
    fsyncDir(path.dirname(destination));
    result.push(Object.freeze({ group, path: name, sha256 }));
  }
  return result;
}

/** Creates an unsigned, no-permission review package without invoking Docker. */
export async function createManualNativeHostReviewPackage(request = {}) {
  exact(request, ["repositoryRoot", "stagingParent", "imageReceipt", "builderRevision"]);
  need(process.platform === "linux" && process.arch === "x64" &&
    typeof process.getuid === "function" && constants.O_NOFOLLOW && constants.O_DIRECTORY,
  "Linux filesystem protections required");
  const root = canonical(request.repositoryRoot);
  const parent = canonical(request.stagingParent);
  noAlias(root);
  privateDir(parent);
  need(root !== parent && !root.startsWith(parent + path.sep) &&
    !parent.startsWith(root + path.sep), "source and staging roots must be disjoint");
  const verified = verifyManualNativeImageReceiptForReview(request.imageReceipt);
  need(HEX40.test(request.builderRevision) && !/^0+$/u.test(request.builderRevision),
    "builder revision invalid");
  const candidate = path.join(parent, ".review-pending-" + randomBytes(16).toString("hex"));
  const published = path.join(parent, "native-host-review-" + randomBytes(16).toString("hex"));
  mkdirSync(candidate, { mode: 0o700 });
  chmodSync(candidate, 0o700);
  let safeToCleanup = true;
  try {
    mkdirSync(path.join(candidate, "verifier"), { mode: 0o700 });
    mkdirSync(path.join(candidate, "native"), { mode: 0o700 });
    const modules = stageTree(root, candidate, AUDITED_VERIFIER_FILES, "verifier");
    const native = stageTree(root, candidate, NATIVE_FILES, "native");
    const inventory = Object.freeze({
      version: 1, status: "NATIVE_HOST_OWNER_REVIEW_PACKAGE_UNSIGNED",
      sourceSha: verified.sourceSha, builderRevision: request.builderRevision,
      images: verified.images, modules, native,
      ownerSignatureVerified: false, hostInstallAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false,
    });
    const filename = path.join(candidate, "inventory.json");
    const f = openSync(filename, CREATE, 0o600);
    try {
      const buf = Buffer.from(JSON.stringify(inventory) + "\n");
      need(writeSync(f, buf) === buf.length, "inventory short write");
      fsyncSync(f);
    } finally { closeSync(f); }
    fsyncDir(candidate);
    renameSync(candidate, published);
    safeToCleanup = false; // published or sync-uncertain package must be retained
    fsyncDir(parent);
    return Object.freeze({ status: inventory.status, directory: published,
      sourceSha: inventory.sourceSha, builderRevision: inventory.builderRevision,
      ownerSignatureVerified: false, hostInstallAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false });
  } finally {
    if (safeToCleanup) rmSync(candidate, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    need(process.argv.length === 10 && process.argv[2] === "--repository" &&
      process.argv[4] === "--image-receipt" &&
      process.argv[6] === "--stage-parent" &&
      process.argv[8] === "--builder-revision", "exact CLI arguments required");
    const receiptPath = canonical(process.argv[5]);
    const st = lstatSync(receiptPath, { bigint: true });
    need(st.isFile() && st.nlink === 1n && st.size > 0n && st.size <= 16384n,
      "unsafe local unsigned image receipt");
    const fd = openSync(receiptPath, FLAGS);
    let raw;
    try {
      need(same(st, fstatSync(fd, { bigint: true })), "receipt substituted");
      raw = readFileSync(fd);
      need(same(st, fstatSync(fd, { bigint: true })) &&
        same(st, lstatSync(receiptPath, { bigint: true })), "receipt modified");
    } finally { closeSync(fd); }
    const result = await createManualNativeHostReviewPackage({
      repositoryRoot: process.argv[3], imageReceipt: JSON.parse(raw.toString("utf8")),
      stagingParent: process.argv[7], builderRevision: process.argv[9],
    });
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exitCode = 2; // deliberately no owner installation authorization
  } catch {
    process.stderr.write("Native manual host package BLOCKED; independently provisioned owner install required.\n");
    process.exitCode = 2;
  }
}
