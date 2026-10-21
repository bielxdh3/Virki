import { createHash } from "node:crypto";
import { constants, lstatSync, realpathSync } from "node:fs";
import { open } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { verifyOfflineDockerSaveTar } from "../../scripts/lib/offline-docker-tar-verifier.mjs";
import { verifyTrustedHostOfflineCandidate } from "./trusted-host-entry.mjs";

// Installed host policy and ledger currently provide only INSPECTED_ONLY /
// deployAuthorized:false; they do not mint an unforgeable admission capability.
// Accordingly this module exports NO active docker-load/tag function. Never
// accept a caller's claimed authorization, token or injected Docker command.
// The safe future transfer is a root-pinned, verified regular-file FD passed as
// child stdin (stdio[0]=fd) to docker load. No import uses an archive pathname.
const FIXED_STAGING = "/var/lib/virki/offline-release/staging";
const MAX_ARCHIVE = 8 * 1024 * 1024 * 1024;
const READ_BLOCK = 64 * 1024;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const REVISION = /^[a-f0-9]{40}$/u;
const OCI_SOURCE = "https://github.com/bielxdh3/Virki";
const PREVIEW_FIELDS = Object.freeze([
  "archivePath", "role", "expectedImageId", "expectedRevision",
  "expectedArchiveSha256", "expectedArchiveSizeBytes",
]);

function refuse(reason) {
  throw new Error("Trusted offline image loader refused: " + reason);
}
function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(value, field))) {
    refuse(label + " contains missing or unexpected fields");
  }
}
function same(a, b) {
  return ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
function requireNoAliases(directory) {
  let current = directory;
  while (true) {
    const meta = lstatSync(current, { bigint: true });
    if (!meta.isDirectory() || meta.isSymbolicLink()) {
      refuse("directory or ancestor is a symbolic alias");
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
function requireRegular(meta, expectedSize) {
  if (!meta.isFile() || meta.isSymbolicLink() || meta.nlink !== 1n ||
      meta.size !== BigInt(expectedSize) ||
      (meta.mode & 0o7777n) !== 0o400n && (meta.mode & 0o7777n) !== 0o600n ||
      (process.platform === "linux" &&
       (typeof process.getuid !== "function" || meta.uid !== BigInt(process.getuid())))) {
    refuse("archive must be an owned, single-link, bounded private regular file");
  }
}
function validatePreviewInput(request) {
  const keys = Object.keys(request ?? {});
  const withTestHook = keys.includes("afterPinnedOpen");
  exact(request, withTestHook ? [...PREVIEW_FIELDS, "afterPinnedOpen"] : PREVIEW_FIELDS,
    "untrusted read-only preview request");
  if (withTestHook && typeof request.afterPinnedOpen !== "function") {
    refuse("test-only preview callback is invalid");
  }
  if (!["runtime", "migrator"].includes(request.role) ||
      !IMAGE_ID.test(request.expectedImageId) ||
      !REVISION.test(request.expectedRevision) ||
      !DIGEST.test(request.expectedArchiveSha256) ||
      !Number.isSafeInteger(request.expectedArchiveSizeBytes) ||
      request.expectedArchiveSizeBytes < 1024 ||
      request.expectedArchiveSizeBytes > MAX_ARCHIVE ||
      request.expectedArchiveSizeBytes % 512 !== 0 ||
      typeof request.archivePath !== "string" ||
      request.archivePath.includes("\0") || request.archivePath.length > 4096 ||
      !path.isAbsolute(request.archivePath) ||
      path.normalize(request.archivePath) !== request.archivePath ||
      path.basename(request.archivePath) !== `${request.role}.tar` ||
      !Number.isInteger(constants.O_NOFOLLOW) ||
      !Number.isInteger(constants.O_NONBLOCK)) {
    refuse("image role, archive path or expected identity is invalid");
  }
}
function requireNativeRoot() {
  if (process.platform !== "linux" || process.arch !== "x64" ||
      typeof process.getuid !== "function" || process.getuid() !== 0 ||
      /microsoft|wsl/iu.test(os.release()) ||
      !constants.O_NOFOLLOW || !constants.O_DIRECTORY) {
    refuse("native Linux/amd64 root required; WSL and Docker Desktop kernels forbidden");
  }
}

async function hashPinned(handle, size) {
  const hasher = createHash("sha256");
  const buffer = Buffer.allocUnsafe(READ_BLOCK);
  let at = 0;
  while (at < size) {
    const count = Math.min(size - at, buffer.length);
    const { bytesRead } = await handle.read(buffer, 0, count, at);
    if (!Number.isSafeInteger(bytesRead) || bytesRead <= 0 || bytesRead > count) {
      refuse("pinned archive read incomplete");
    }
    hasher.update(buffer.subarray(0, bytesRead));
    at += bytesRead;
  }
  return hasher.digest("hex");
}

/**
 * Pure NON-AUTHORIZING filesystem and format preview. It accepts caller
 * expected metadata only so tests can exercise a pinned-FD/filename-swap
 * threat without a real Docker daemon or owner trust. Never treat the result
 * as a permission to import, tag or deploy anything.
 *
 * afterPinnedOpen is an optional read-only PREVIEW test hook. It can simulate a
 * pathname replacement; the opened fd remains tied to the original inode.
 * The guarded native production API below never accepts such a hook.
 */
export async function inspectUntrustedPinnedImageForPreview(request = {}) {
  validatePreviewInput(request);
  const {
    archivePath, role, expectedImageId, expectedRevision,
    expectedArchiveSha256, expectedArchiveSizeBytes, afterPinnedOpen,
  } = request;
  requireNoAliases(path.dirname(archivePath));
  const directoryBefore = lstatSync(path.dirname(archivePath), { bigint: true });
  const before = lstatSync(archivePath, { bigint: true });
  requireRegular(before, expectedArchiveSizeBytes);
  const handle = await open(archivePath,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const pinned = await handle.stat({ bigint: true });
    requireRegular(pinned, expectedArchiveSizeBytes);
    if (!same(pinned, before)) refuse("archive identity changed while opening");
    if (afterPinnedOpen) await afterPinnedOpen(Object.freeze({ pinnedFd: handle.fd }));
    // Path equality is checked again even before parsing, so a rename followed
    // by a valid replacement cannot make the parser validate a different inode.
    if (!same(pinned, lstatSync(archivePath, { bigint: true }))) {
      refuse("archive filename was replaced after FD pinning");
    }
    const first = await hashPinned(handle, expectedArchiveSizeBytes);
    if (first !== expectedArchiveSha256) refuse("pinned archive differs from claimed SHA-256");
    if (!same(pinned, await handle.stat({ bigint: true })) ||
        !same(pinned, lstatSync(archivePath, { bigint: true }))) {
      refuse("archive changed after hashing");
    }
    // Existing rigorous TAR parser checks config, every layer's uncompressed
    // diff_id, tags, OCI graph, owner metadata, and entire archive SHA-256.
    // It currently accepts a PATH, not an already opened FD; this is safe for
    // non-authorizing preview only. An active loader needs an FD-bound verifier.
    const proof = await verifyOfflineDockerSaveTar({
      archivePath, role, expectedImageId, expectedRevision,
      expectedArchiveSha256, expectedArchiveSizeBytes,
    });
    const second = await hashPinned(handle, expectedArchiveSizeBytes);
    if (second !== first || !same(pinned, await handle.stat({ bigint: true })) ||
        !same(pinned, lstatSync(archivePath, { bigint: true })) ||
        !same(directoryBefore, lstatSync(path.dirname(archivePath), { bigint: true }))) {
      refuse("archive or staging directory changed while inspecting");
    }
    requireNoAliases(path.dirname(archivePath));
    return Object.freeze({
      status: "UNTRUSTED_PINNED_ARCHIVE_PREVIEW_ONLY",
      deployAuthorized: false,
      dockerLoadAuthorized: false,
      role: proof.role,
      imageId: proof.imageId,
      archiveSha256: proof.archiveSha256,
      archiveSizeBytes: proof.archiveSizeBytes,
      platform: proof.platform,
      user: proof.user,
      stdinDesign: "inherit pinned verified regular-file FD as child stdin; never reopen archive filename",
    });
  } finally {
    await handle.close();
  }
}

/**
 * Pure post-load comparison for future admission integration, not authorization.
 * Accepts Docker's single image-inspect JSON output; must run BEFORE any alias
 * tag. No Docker command is launched here, and caller objects are UNTRUSTED.
 */
export function compareUntrustedLoadedImageForPreview({ imageInspect, verifiedImage } = {}) {
  if (!verifiedImage || typeof verifiedImage !== "object" ||
      !IMAGE_ID.test(verifiedImage.imageId) ||
      !REVISION.test(verifiedImage.revision) ||
      verifiedImage.source !== OCI_SOURCE ||
      verifiedImage.platform !== "linux/amd64" ||
      verifiedImage.user !== "node:node" ||
      !Array.isArray(imageInspect) || imageInspect.length !== 1) {
    refuse("post-load expected identity or Docker inspect records invalid");
  }
  const image = imageInspect[0];
  if (!image || typeof image !== "object" || Array.isArray(image) ||
      image.Id !== verifiedImage.imageId ||
      image.Os !== "linux" || image.Architecture !== "amd64" ||
      !image.Config || typeof image.Config !== "object" ||
      image.Config.User !== "node:node" ||
      !image.Config.Labels || typeof image.Config.Labels !== "object" ||
      image.Config.Labels["org.opencontainers.image.revision"] !== verifiedImage.revision ||
      image.Config.Labels["org.opencontainers.image.source"] !== OCI_SOURCE ||
      !(image.RepoTags === null ||
        (Array.isArray(image.RepoTags) && image.RepoTags.length === 0)) ||
      !(image.RepoDigests === null || image.RepoDigests === undefined ||
        (Array.isArray(image.RepoDigests) && image.RepoDigests.length === 0))) {
    refuse("post-load image identity, labels, platform, user or pristine alias state mismatch");
  }
  return Object.freeze({
    status: "UNTRUSTED_POSTLOAD_COMPARISON_ONLY",
    dockerTagAuthorized: false,
    deployAuthorized: false,
    imageId: verifiedImage.imageId,
  });
}

/**
 * Installed host-only inspection. The staging path and role are constrained;
 * policy + ledger pins must come from the installed native verifier. Even a
 * successful owner signature currently yields deployAuthorized:false.
 */
export async function previewTrustedOfflineImageLoad(request = {}) {
  requireNativeRoot();
  exact(request, ["candidateDirectory", "role"], "trusted preview request");
  if (request.candidateDirectory !== FIXED_STAGING ||
      !["runtime", "migrator"].includes(request.role) ||
      realpathSync.native(FIXED_STAGING) !== FIXED_STAGING) {
    refuse("expected the fixed owner-protected staging directory");
  }
  const checked = await verifyTrustedHostOfflineCandidate({
    candidateDirectory: FIXED_STAGING,
  });
  if (checked.deployAuthorized !== false ||
      checked.status !== "INSPECTED_ONLY_RELEASE_BLOCKED") {
    refuse("unexpected host admission state");
  }
  return Object.freeze({
    status: "TRUSTED_INSPECTION_ONLY_LOAD_BLOCKED",
    deployAuthorized: false,
    dockerLoadAuthorized: false,
    role: request.role,
    verifiedManifestSha256: checked.verifiedManifestSha256,
    reason: "No approved, non-forgeable release admission token/ledger activation exists",
  });
}

/**
 * The absence of an independently minted one-shot host-admission capability
 * is a hard security boundary, not a feature flag. Reject every invocation,
 * including strings or objects claiming to be tokens.
 */
export async function loadTrustedOfflineImage(request = {}) {
  requireNativeRoot();
  exact(request, ["candidateDirectory", "role"], "trusted loader request");
  if (request.candidateDirectory !== FIXED_STAGING ||
      !["runtime", "migrator"].includes(request.role)) {
    refuse("untrusted candidate location or image role");
  }
  refuse("Docker load is blocked: no trusted admission token issuer or FD-bound verifier");
}
