import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectUntrustedOfflineCandidate, verifyTrustedHostOfflineCandidate } from "./trusted-host-entry.mjs";
import { verifyInstalledTrustedSourceGit } from "./trusted-source-git.mjs";
import { recordOfflineReleaseAcceptance } from "../../scripts/lib/offline-release-ledger.mjs";

// Native installed-host composition only. This file and its transitive modules
// must be independently audited and installed under root ownership before use.
// It is NOT an install, image load, activation or production deployment entry.
// The uploader controls only the location of UNTRUSTED candidate bytes.
const FIXED_LEDGER_DIRECTORY = "/var/lib/virki/offline-release";
const INSTALLED_ENTRY = "/usr/local/lib/virki/offline-release/infra/offline/trusted-release-coordinator.mjs";
const FILES = Object.freeze([
  "manifest.json", "signatures.json", "source.tar", "runtime.tar", "migrator.tar",
  "ci-report.json", "scanner-report.json", "finding-review.json",
  "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json",
]);
const METADATA = Object.freeze([
  "dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs",
]);
const BLOCKED = Object.freeze({ status: "blocked", deployAuthorized: false });

function check(ok) {
  if (!ok) throw new Error("Trusted offline coordinator blocked");
}

function requireNativeRoot() {
  check(process.platform === "linux" && process.arch === "x64" &&
    typeof process.getuid === "function" && process.getuid() === 0 &&
    !/microsoft|wsl/iu.test(os.release()));
  // An arbitrary checkout or uploaded candidate cannot act as this root
  // coordinator. Installation and audit pinning remain independently owned.
  check(fileURLToPath(import.meta.url) === INSTALLED_ENTRY &&
    realpathSync.native(INSTALLED_ENTRY) === INSTALLED_ENTRY);
  let location = INSTALLED_ENTRY;
  while (true) {
    const stat = lstatSync(location, { bigint: true });
    check(stat.uid === 0n && !stat.isSymbolicLink() &&
      (stat.mode & 0o022n) === 0n && (stat.mode & 0o6000n) === 0n &&
      (location === INSTALLED_ENTRY
        ? stat.isFile() && stat.nlink === 1n &&
          stat.size > 0n && stat.size <= 2n * 1024n * 1024n
        : stat.isDirectory()));
    const parent = path.dirname(location);
    if (parent === location) break;
    location = parent;
  }
}

// The two verifiers open and reread the same candidate at different points.
// Protect against a replaced byte/inode during their composition, even when
// an attacker swaps in a file with identical signed SHA-256 contents.
function snapshot(directory) {
  const paths = [directory, ...FILES.map((name) => path.join(directory, name))];
  return paths.map((pathname, index) => {
    const stat = lstatSync(pathname, { bigint: true });
    check(stat.uid === 0n && !stat.isSymbolicLink() &&
      (index === 0
        ? stat.isDirectory() && (stat.mode & 0o7777n) === 0o700n
        : stat.isFile() && stat.nlink === 1n && (stat.mode & 0o7777n) === 0o600n));
    return METADATA.map((name) => stat[name].toString()).join(":");
  });
}

function sameInspection(first, second) {
  check(first.manifestDigest === second.manifestDigest &&
    first.manifestBytes.equals(second.manifestBytes) &&
    first.signatures.owner === second.signatures.owner &&
    first.signatures.builder === second.signatures.builder &&
    JSON.stringify(first.expected) === JSON.stringify(second.expected));
}

/**
 * Compose host-pinned signature + image inspection, independently pinned Git
 * source verification and an exclusive, durable attempted ledger reservation.
 *
 * Only the candidate directory can be supplied. Both signing keys, trusted
 * host identity, Git store/pin and ledger head always come from independent
 * protected host state. A failed or interrupted ledger write retains its lock.
 *
 * Every outcome is NON-AUTHORIZING. A staged attempt requires subsequent
 * independent host review and a different, separately approved operator path.
 */
export async function coordinateTrustedOfflineRelease(request = {}) {
  try {
    requireNativeRoot();
    check(request !== null && typeof request === "object" && !Array.isArray(request) &&
      Object.keys(request).length === 1 && Object.hasOwn(request, "candidateDirectory"));
    const { candidateDirectory } = request;
    check(typeof candidateDirectory === "string" && path.isAbsolute(candidateDirectory) &&
      path.normalize(candidateDirectory) === candidateDirectory);

    const before = snapshot(candidateDirectory);
    const first = await inspectUntrustedOfflineCandidate({ candidateDirectory });
    const signed = await verifyTrustedHostOfflineCandidate({ candidateDirectory });
    check(signed.status === "INSPECTED_ONLY_RELEASE_BLOCKED" &&
      signed.deployAuthorized === false &&
      signed.sourceSha === first.expected.sourceSha &&
      signed.verifiedManifestSha256 === first.manifestDigest &&
      Array.isArray(signed.checkedImageRoles) &&
      signed.checkedImageRoles.length === 2 &&
      signed.checkedImageRoles.includes("runtime") &&
      signed.checkedImageRoles.includes("migrator"));

    const source = await verifyInstalledTrustedSourceGit({ candidateDirectory });
    check(source.status === "INDEPENDENT_GIT_SOURCE_INSPECTED_RELEASE_BLOCKED" &&
      source.deployAuthorized === false &&
      source.sourceSha === signed.sourceSha &&
      source.archiveSha256 === first.expected.sourceArchiveSha256 &&
      source.archiveSizeBytes === first.expected.sourceArchiveSizeBytes);

    const last = await inspectUntrustedOfflineCandidate({ candidateDirectory });
    sameInspection(first, last);
    const after = snapshot(candidateDirectory);
    check(before.every((entry, index) => entry === after[index]));
    const manifest = JSON.parse(last.manifestBytes.toString("utf8"));
    const nowSeconds = Math.floor(Date.now() / 1000);
    check(Number.isSafeInteger(manifest.issued_at) && Number.isSafeInteger(manifest.expires_at) &&
      nowSeconds >= manifest.issued_at && nowSeconds < manifest.expires_at &&
      manifest.source_sha === signed.sourceSha &&
      manifest.predecessor_sha === last.expected.predecessorSha &&
      manifest.sequence === last.expected.lastSequence + 1);

    // Persist the digest of the ACTUAL independently checked owner signature,
    // domain separated from any caller-provided approval or untrusted metadata.
    const approvalDigest = createHash("sha256")
      .update("VIRKI_OFFLINE_COORDINATOR_OWNER_APPROVAL_V1\0")
      .update(Buffer.from(last.manifestDigest, "hex"))
      .update(Buffer.from(last.signatures.owner, "base64"))
      .digest("hex");
    const attempt = recordOfflineReleaseAcceptance({
      directory: FIXED_LEDGER_DIRECTORY,
      manifestSha256: signed.verifiedManifestSha256,
      priorSha: manifest.predecessor_sha,
      nextSha: signed.sourceSha,
      nonce: manifest.nonce,
      sequence: manifest.sequence,
      approvalDigest,
    });
    check(attempt.status === "attempted" &&
      attempt.pendingSha === signed.sourceSha &&
      attempt.sequence === manifest.sequence);
    return Object.freeze({
      status: "staged", deployAuthorized: false,
      sourceSha: signed.sourceSha,
      verifiedManifestSha256: signed.verifiedManifestSha256,
      sequence: attempt.sequence,
    });
  } catch {
    // Never disclose a verifier's failure as a usable admission token.
    return BLOCKED;
  }
}
