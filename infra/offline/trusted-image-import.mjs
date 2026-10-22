import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  constants, closeSync, fstatSync, fsyncSync, lstatSync, openSync,
  readFileSync, readSync, realpathSync, unlinkSync, writeSync,
} from "node:fs";
import { open } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyOfflineDockerSaveTarFromHandle } from "../../scripts/lib/offline-docker-tar-verifier.mjs";
import { inspectUntrustedOfflineCandidate } from "./trusted-host-entry.mjs";
import { coordinateTrustedOfflineRelease } from "./trusted-release-coordinator.mjs";
import { compareUntrustedLoadedImageForPreview } from "./trusted-image-loader.mjs";

// Deliberately separate from production deploy. This installed-only entrypoint
// imports ONE untagged image into a dedicated isolated daemon, and never
// starts, tags, publishes, activates or accepts a release. Its signed approval
// is checked by the independently installed coordinator, not by this caller.
const INSTALLED_ENTRY = "/usr/local/lib/virki/offline-release/infra/offline/trusted-image-import.mjs";
const QUARANTINE = "/var/lib/virki/offline-import-quarantine";
const DOCKER_SOCKET = "/run/virki-offline-import/docker.sock";
const DOCKER_HOST = "unix://" + DOCKER_SOCKET;
// This root-provisioned CLI is deliberately NOT the host's default docker
// executable. An operator must separately pin the binary, and an isolated
// Docker daemon must independently own the adjacent private socket.
const DOCKER_EXE = "/run/virki-offline-import/docker";
const DOCKER_EXE_PIN = "/etc/virki/offline-import-cli.sha256";
const MAX_DOCKER_EXE = 64 * 1024 * 1024;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024 * 1024;
const BLOCK = 64 * 1024;
const SOURCE = "https://github.com/bielxdh3/Virki";
const BLOCKED = Object.freeze({ status: "blocked", dockerLoadAuthorized: false, deployAuthorized: false });

function ensure(ok) {
  if (!ok) throw new Error("Trusted offline image import refused");
}
function same(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function rootDirectory(directory, mode) {
  ensure(realpathSync.native(directory) === directory);
  let current = directory;
  while (true) {
    const stat = lstatSync(current, { bigint: true });
    ensure(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0n &&
      (stat.mode & 0o022n) === 0n &&
      (current !== directory || (stat.mode & 0o7777n) === BigInt(mode)));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}
function nativeInstalledOnly() {
  ensure(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && !/microsoft|wsl/iu.test(os.release()));
  ensure(fileURLToPath(import.meta.url) === INSTALLED_ENTRY &&
    realpathSync.native(INSTALLED_ENTRY) === INSTALLED_ENTRY);
  const stat = lstatSync(INSTALLED_ENTRY, { bigint: true });
  ensure(stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0n &&
    stat.nlink === 1n && stat.size > 0n && stat.size <= 2n * 1024n * 1024n &&
    (stat.mode & 0o022n) === 0n);
  rootDirectory(path.dirname(INSTALLED_ENTRY), 0o700);
}
function isolatedDockerOnly() {
  rootDirectory(path.dirname(DOCKER_SOCKET), 0o700);
  const socket = lstatSync(DOCKER_SOCKET, { bigint: true });
  ensure(socket.isSocket() && socket.uid === 0n && (socket.mode & 0o7777n) === 0o600n);
  // The CLI digest file must be independently controlled, never writable by
  // an uploader via a swapped directory or an untrusted ancestor.
  rootDirectory(path.dirname(DOCKER_EXE_PIN), 0o755);
  ensure(realpathSync.native(DOCKER_EXE_PIN) === DOCKER_EXE_PIN);
  const pinStat = lstatSync(DOCKER_EXE_PIN, { bigint: true });
  ensure(pinStat.isFile() && !pinStat.isSymbolicLink() && pinStat.uid === 0n &&
    pinStat.nlink === 1n && (pinStat.mode & 0o7777n) === 0o600n &&
    pinStat.size === 65n);
  const pinFd = openSync(DOCKER_EXE_PIN, constants.O_RDONLY | constants.O_NOFOLLOW);
  let pin;
  try {
    ensure(same(pinStat, fstatSync(pinFd, { bigint: true })));
    pin = readFileSync(pinFd).toString("ascii");
    ensure(same(pinStat, fstatSync(pinFd, { bigint: true })));
  } finally {
    closeSync(pinFd);
  }
  ensure(/^[a-f0-9]{64}\n$/u.test(pin));
  const exe = lstatSync(DOCKER_EXE, { bigint: true });
  ensure(exe.isFile() && !exe.isSymbolicLink() && exe.uid === 0n &&
    exe.nlink === 1n && exe.size > 0n && exe.size <= BigInt(MAX_DOCKER_EXE) &&
    (exe.mode & 0o7777n) === 0o700n);
  const fd = openSync(DOCKER_EXE, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    ensure(same(exe, fstatSync(fd, { bigint: true })));
    const hasher = createHash("sha256");
    const buffer = Buffer.allocUnsafe(BLOCK);
    for (let offset = 0; offset < Number(exe.size);) {
      const count = readSync(fd, buffer, 0, Math.min(BLOCK, Number(exe.size) - offset), offset);
      ensure(count > 0);
      hasher.update(buffer.subarray(0, count));
      offset += count;
    }
    ensure(hasher.digest("hex") === pin.slice(0, 64) &&
      same(exe, fstatSync(fd, { bigint: true })) &&
      same(exe, lstatSync(DOCKER_EXE, { bigint: true })));
  } finally {
    closeSync(fd);
  }
}
function docker(args, stdinFd = "ignore") {
  isolatedDockerOnly();
  const result = spawnSync(DOCKER_EXE, ["--host", DOCKER_HOST, ...args], {
    stdio: [stdinFd, "pipe", "pipe"],
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent", DOCKER_CONFIG: "/nonexistent" },
    shell: false,
    windowsHide: true,
    timeout: 300000,
    maxBuffer: 65536,
  });
  ensure(!result.error && !result.signal && Number.isInteger(result.status));
  return result;
}
function requireSource(file, size) {
  const stat = lstatSync(file, { bigint: true });
  ensure(stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0n &&
    stat.nlink === 1n && (stat.mode & 0o7777n) === 0o600n &&
    stat.size === BigInt(size));
  return stat;
}
async function detachedAuthenticatedCopy(filename, expected) {
  rootDirectory(QUARANTINE, 0o700);
  const dir = openSync(QUARANTINE, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let writer;
  let source;
  let pinned;
  let pathname;
  try {
    const directory = fstatSync(dir, { bigint: true });
    const before = requireSource(filename, expected.expectedArchiveSizeBytes);
    source = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    ensure(same(before, await source.stat({ bigint: true })));
    pathname = path.join(QUARANTINE, ".import-" + randomBytes(16).toString("hex"));
    writer = openSync(pathname,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(BLOCK);
    let offset = 0;
    while (offset < expected.expectedArchiveSizeBytes) {
      const amount = Math.min(BLOCK, expected.expectedArchiveSizeBytes - offset);
      const { bytesRead } = await source.read(buffer, 0, amount, offset);
      ensure(bytesRead > 0 && bytesRead <= amount);
      let wrote = 0;
      while (wrote < bytesRead) {
        // Never reopen the uploaded pathname and never follow a temporary alias.
        const n = writeSync(writer, buffer, wrote, bytesRead - wrote);
        ensure(n > 0);
        wrote += n;
      }
      digest.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    ensure(digest.digest("hex") === expected.expectedArchiveSha256 &&
      same(before, await source.stat({ bigint: true })) &&
      same(before, requireSource(filename, expected.expectedArchiveSizeBytes)));
    fsyncSync(writer);
    closeSync(writer);
    writer = undefined;
    pinned = await open(pathname, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await pinned.stat({ bigint: true });
    ensure(stat.isFile() && stat.uid === 0n && stat.nlink === 1n &&
      stat.size === BigInt(expected.expectedArchiveSizeBytes) &&
      (stat.mode & 0o7777n) === 0o600n);
    const proof = await verifyOfflineDockerSaveTarFromHandle({
      fileHandle: pinned, ...expected,
    });
    ensure(proof.imageId === expected.expectedImageId &&
      proof.archiveSha256 === expected.expectedArchiveSha256 &&
      same(stat, await pinned.stat({ bigint: true })) &&
      directory.dev === fstatSync(dir, { bigint: true }).dev &&
      directory.ino === fstatSync(dir, { bigint: true }).ino);
    // Detach BEFORE exposing the read-only descriptor to the daemon; source
    // replacement or in-place mutation can no longer change the consumed inode.
    unlinkSync(pathname);
    pathname = undefined;
    fsyncSync(dir);
    await source.close();
    source = undefined;
    return pinned;
  } catch (error) {
    if (pinned) await pinned.close();
    throw error;
  } finally {
    if (writer !== undefined) closeSync(writer);
    if (source) await source.close();
    if (pathname) unlinkSync(pathname);
    closeSync(dir);
  }
}

/**
 * Performs one audited, atomic-admission two-image import, never deployment.
 * The caller selects only a private candidate directory. The coordinator obtains
 * all trusted signature, Git and ledger identities from protected host state.
 * Every failed/partial import leaves the coordinator's attempted latch intact.
 */
export async function importApprovedOfflineImages(request = {}) {
  try {
    nativeInstalledOnly();
    ensure(request && typeof request === "object" && !Array.isArray(request) &&
      Object.keys(request).length === 1 && Object.hasOwn(request, "candidateDirectory"));
    ensure(typeof request.candidateDirectory === "string" &&
      path.isAbsolute(request.candidateDirectory) &&
      path.normalize(request.candidateDirectory) === request.candidateDirectory &&
      request.candidateDirectory.startsWith("/var/lib/virki/offline-staging/"));
    isolatedDockerOnly();
    rootDirectory(QUARANTINE, 0o700);
    // A failed or disconnected daemon must not burn the one-shot owner
    // approval. Check the root-pinned dedicated endpoint before reserving
    // the durable attempt; repeat checks remain mandatory after admission.
    const daemon = docker(["version", "--format", "{{.Server.Version}}"]);
    ensure(daemon.status === 0 && /^\d+\.\d+\.\d+\n?$/u.test(daemon.stdout));
    const accepted = await coordinateTrustedOfflineRelease({
      candidateDirectory: request.candidateDirectory,
    });
    ensure(accepted.status === "staged" && accepted.deployAuthorized === false);
    const candidate = await inspectUntrustedOfflineCandidate({
      candidateDirectory: request.candidateDirectory,
    });
    ensure(candidate.manifestDigest === accepted.verifiedManifestSha256 &&
      candidate.expected.sourceSha === accepted.sourceSha);
    const imagePlan = ["runtime", "migrator"].map((role) => {
      const identity = role === "runtime" ? candidate.expected.runtimeImage : candidate.expected.migratorImage;
      ensure(identity.archiveSizeBytes <= MAX_IMAGE_BYTES);
      return {
        role, identity, expected: {
          role, expectedImageId: identity.imageId,
          expectedRevision: accepted.sourceSha,
          expectedArchiveSha256: identity.archiveSha256,
          expectedArchiveSizeBytes: identity.archiveSizeBytes,
        },
      };
    });
    ensure(imagePlan[0].identity.imageId !== imagePlan[1].identity.imageId);
    // Check both preconditions BEFORE mutating the isolated daemon. The two
    // archives may happen to encode one identical image ID in a test fixture;
    // an existing object is still never reused as implicit authorization.
    for (const { identity } of imagePlan) {
      const prior = docker(["image", "inspect", "--type", "image", identity.imageId]);
      ensure(prior.status === 1 && prior.stdout.length === 0 &&
        prior.stderr.trim() === `Error: No such image: ${identity.imageId}`);
    }
    const pinned = [];
    try {
      // Authenticate BOTH complete archives before the FIRST image load.
      // Neither upload pathname is accessed once import begins.
      for (const { role, expected } of imagePlan) {
        pinned.push(await detachedAuthenticatedCopy(candidate.archivePaths[role], expected));
      }
      for (const handle of pinned) {
        ensure(docker(["image", "load", "--quiet"], handle.fd).status === 0);
      }
    } finally {
      for (const handle of pinned) await handle.close();
    }
    for (const { identity } of imagePlan) {
      const after = docker(["image", "inspect", "--type", "image", identity.imageId]);
      ensure(after.status === 0 && after.stdout.length <= 65536);
      const checked = compareUntrustedLoadedImageForPreview({
        imageInspect: JSON.parse(after.stdout),
        verifiedImage: {
          imageId: identity.imageId, revision: accepted.sourceSha,
          source: SOURCE, platform: "linux/amd64", user: "node:node",
        },
      });
      ensure(checked.dockerTagAuthorized === false && checked.deployAuthorized === false);
    }
    return Object.freeze({
      status: "IMPORTED_BOTH_UNTAGGED_ATTEMPT_LOCKED",
      imageIds: Object.freeze(imagePlan.map(({ identity }) => identity.imageId)),
      dockerTagAuthorized: false, deployAuthorized: false,
    });
  } catch {
    return BLOCKED;
  }
}

// Refuse legacy callers trying to admit one role at a time: the attempted
// release latch is one-shot and must cover BOTH signed images in one process.
export async function importApprovedOfflineImage() {
  return BLOCKED;
}
