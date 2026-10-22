import { createHash } from "node:crypto";
import { constants, lstatSync } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";

// This module inventories caller-supplied artifacts. It does not parse tar,
// attest the provenance of Docker metadata, sign anything, or permit deploys.
const GIT_REMOTE = "https://github.com/bielxdh3/Virki.git";
// Dockerfile OCI labels deliberately omit `.git` from the canonical Git
// remote. These are distinct identities: never rewrite a claimed OCI label.
const OCI_SOURCE = "https://github.com/bielxdh3/Virki";
const FULL_SHA = /^[0-9a-f]{40}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024;
const READ_BLOCK_BYTES = 64 * 1024;
const IMAGE_ROLES = ["runtime", "migrator"];

function refuse(reason) {
  throw new Error(`Offline artifact inventory rejected: ${reason}`);
}

function regularMetadata(stat, label) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n ||
      stat.size < 1n || stat.size > BigInt(MAX_ARCHIVE_BYTES)) {
    refuse(`${label} must be a single-link, nonempty, bounded regular file`);
  }
}

function identicalMetadata(first, second, label) {
  for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) {
    if (first[field] !== second[field]) refuse(`${label} metadata changed during inspection`);
  }
}

function validateInputPath(raw, label) {
  if (typeof raw !== "string" || raw.includes("\0") || raw.length > 4096 ||
      !path.isAbsolute(raw) || path.normalize(raw) !== raw) {
    refuse(`${label} path is not an absolute canonical path`);
  }
  return raw;
}

function rejectSymlinkAncestors(root) {
  // Verify each ancestor explicitly, including those above artifactRoot.
  // Opening the root with O_NOFOLLOW alone would not reject parent aliases.
  let current = root;
  while (true) {
    const metadata = lstatSync(current, { bigint: true });
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      refuse("artifact root or an ancestor is an unsafe directory alias");
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function checkRoot(root, expectedStat) {
  rejectSymlinkAncestors(root);
  const observed = lstatSync(root, { bigint: true });
  if (!observed.isDirectory() || observed.isSymbolicLink()) refuse("artifact root is not a real directory");
  identicalMetadata(expectedStat, observed, "artifact root");
}

function assertArtifactLocation(archivePath, root, name) {
  const candidate = validateInputPath(archivePath, name);
  // Require all three artifacts directly inside one pinned directory. This
  // avoids traversing attacker-controlled intermediate directories or links.
  if (path.dirname(candidate) !== root || !path.basename(candidate).endsWith(".tar")) {
    refuse(`${name} path must identify a direct .tar child of artifact root`);
  }
  return candidate;
}

function verifyDockerMetadata(metadata, role, revision) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata) ||
      metadata.role !== role || typeof metadata.imageId !== "string" ||
      !IMAGE_ID.test(metadata.imageId) || !Number.isSafeInteger(metadata.sizeBytes) ||
      metadata.sizeBytes <= 0 || metadata.os !== "linux" || metadata.architecture !== "amd64" ||
      !metadata.labels || typeof metadata.labels !== "object" || Array.isArray(metadata.labels) ||
      metadata.labels["org.opencontainers.image.revision"] !== revision ||
      metadata.labels["org.opencontainers.image.source"] !== OCI_SOURCE) {
    refuse(`${role} Docker metadata does not match exact image role, revision, source or platform`);
  }
  return metadata.imageId;
}

async function hashPass(handle, expectedSize) {
  const sha = createHash("sha256");
  const buffer = Buffer.allocUnsafe(READ_BLOCK_BYTES);
  let offset = 0;
  while (offset < expectedSize) {
    const remaining = expectedSize - offset;
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, remaining), offset);
    if (!Number.isSafeInteger(bytesRead) || bytesRead <= 0 || bytesRead > remaining) {
      refuse("archive changed length while being read");
    }
    sha.update(buffer.subarray(0, bytesRead));
    offset += bytesRead;
  }
  return sha.digest("hex");
}

async function inventoryFile(archivePath, label, root, rootHandle, initialRoot) {
  checkRoot(root, initialRoot);
  const beforePath = lstatSync(archivePath, { bigint: true });
  regularMetadata(beforePath, label);

  // O_NOFOLLOW protects the opened leaf; O_NONBLOCK prevents hanging on an
  // unexpected FIFO. Metadata of the opened FD is the hashing authority.
  const handle = await open(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const beforeFd = await handle.stat({ bigint: true });
    regularMetadata(beforeFd, label);
    identicalMetadata(beforePath, beforeFd, label);
    const size = Number(beforeFd.size);
    const firstHash = await hashPass(handle, size);
    const afterFirst = await handle.stat({ bigint: true });
    identicalMetadata(beforeFd, afterFirst, label);
    identicalMetadata(beforeFd, lstatSync(archivePath, { bigint: true }), label);

    // One full reread detects changes to bytes even when metadata was restored.
    // The caller must independently reverify the artifact on its destination.
    const secondHash = await hashPass(handle, size);
    if (firstHash !== secondHash) refuse(`${label} content changed between hash passes`);
    identicalMetadata(beforeFd, await handle.stat({ bigint: true }), label);
    identicalMetadata(beforeFd, lstatSync(archivePath, { bigint: true }), label);
    identicalMetadata(initialRoot, await rootHandle.stat({ bigint: true }), "artifact root");
    checkRoot(root, initialRoot);
    return Object.freeze({ sha256: firstHash, sizeBytes: size });
  } finally {
    await handle.close();
  }
}

/**
 * Read-only inventory of three already-created tar files and supplied Docker
 * inspect metadata. Files must be direct children of the same canonical root.
 * The Docker fields are checked as *claims*, not independently obtained here;
 * a native host gate must validate tar payload/config, SHA and labels again.
 */
export async function inventoryOfflineArtifacts({
  artifactRoot,
  sourceArchivePath,
  runtimeArchivePath,
  migratorArchivePath,
  expectedRevision,
  images,
} = {}) {
  if (!Number.isInteger(constants.O_NOFOLLOW) || !Number.isInteger(constants.O_DIRECTORY) ||
      !Number.isInteger(constants.O_NONBLOCK)) {
    refuse("required no-follow filesystem capabilities are unavailable");
  }
  const root = validateInputPath(artifactRoot, "artifact root");
  if (!FULL_SHA.test(expectedRevision ?? "")) refuse("expected revision must be a full lowercase SHA");
  if (!images || typeof images !== "object" || Array.isArray(images)) refuse("Docker image metadata is missing");
  const imageIds = IMAGE_ROLES.map((role) => verifyDockerMetadata(images[role], role, expectedRevision));
  if (imageIds[0] === imageIds[1]) refuse("runtime and migrator must have distinct image IDs");

  const sourcePath = assertArtifactLocation(sourceArchivePath, root, "source archive");
  const runtimePath = assertArtifactLocation(runtimeArchivePath, root, "runtime archive");
  const migratorPath = assertArtifactLocation(migratorArchivePath, root, "migrator archive");
  if (new Set([sourcePath, runtimePath, migratorPath]).size !== 3) refuse("archive paths must be distinct");

  const beforeRoot = lstatSync(root, { bigint: true });
  if (!beforeRoot.isDirectory() || beforeRoot.isSymbolicLink()) refuse("artifact root must be a real directory");
  rejectSymlinkAncestors(root);
  const rootHandle = await open(root, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try {
    identicalMetadata(beforeRoot, await rootHandle.stat({ bigint: true }), "artifact root");
    const source = await inventoryFile(sourcePath, "source", root, rootHandle, beforeRoot);
    const runtime = await inventoryFile(runtimePath, "runtime", root, rootHandle, beforeRoot);
    const migrator = await inventoryFile(migratorPath, "migrator", root, rootHandle, beforeRoot);
    identicalMetadata(beforeRoot, await rootHandle.stat({ bigint: true }), "artifact root");
    checkRoot(root, beforeRoot);

    return Object.freeze({
      source_sha: expectedRevision,
      repository: GIT_REMOTE,
      platform: "linux/amd64",
      source_archive_sha256: source.sha256,
      source_archive_size_bytes: source.sizeBytes,
      runtime_image: Object.freeze({ archive_sha256: runtime.sha256, archive_size_bytes: runtime.sizeBytes, image_id: imageIds[0] }),
      migrator_image: Object.freeze({ archive_sha256: migrator.sha256, archive_size_bytes: migrator.sizeBytes, image_id: imageIds[1] }),
    });
  } finally {
    await rootHandle.close();
  }
}
