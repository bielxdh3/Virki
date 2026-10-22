import { lstatSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { inventoryOfflineArtifacts } from "./offline-artifact-inventory.mjs";
import { verifyOfflineReleaseAttestation } from "./offline-release-attestation.mjs";

// Library foundation only: no file-based trust-root discovery, key reading,
// ledger write, Docker load, SSH, database, deployment or host policy change.
// These public keys / state / report hashes MUST be independently provisioned
// by trusted host code, never selected from the uploaded release bundle.
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const EVIDENCE_FIELDS = Object.freeze([
  "ciReportSha256", "scannerReportSha256", "scannerRulesCommit",
  "findingReviewSha256", "runtimeSmokeSha256", "migratorSmokeSha256",
  "backupRestoreSha256",
]);
const HOST_FIELDS = Object.freeze([
  "sourceSha", "hostIdentitySha256", "predecessorSha", "lastSequence", "evidence",
]);

function refuse(message) {
  throw new Error(`Offline host verifier refused: ${message}`);
}

function exactFields(object, fields, label) {
  if (!object || typeof object !== "object" || Array.isArray(object) ||
      Object.keys(object).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(object, field))) {
    refuse(`${label} must have exactly the required fields`);
  }
}

function requireMatch(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) refuse(`${label} is invalid`);
  return value;
}

function requireKey(key, label) {
  exactFields(key, ["publicKeyPem", "pinSha256"], label);
  if (typeof key.publicKeyPem !== "string" || key.publicKeyPem.length === 0 ||
      key.publicKeyPem.length > 2048) refuse(`${label} public key is invalid`);
  return Object.freeze({
    publicKeyPem: key.publicKeyPem,
    pinSha256: requireMatch(key.pinSha256, DIGEST, `${label} key pin`),
  });
}

/**
 * Validate and take immutable snapshots of the host's trusted inputs BEFORE
 * any asynchronous archive hashing. This helper is pure, so Windows and WSL
 * tests may check validation without bypassing the native-kernel guard.
 *
 * The values must originate outside the untrusted bundle. Shape validation
 * alone does not establish that the operator supplied trustworthy values.
 */
export function prepareOfflineHostVerificationContext({ trustAnchor, hostState } = {}) {
  exactFields(trustAnchor, ["builder", "owner"], "trust anchor");
  exactFields(hostState, HOST_FIELDS, "protected host state");
  exactFields(hostState.evidence, EVIDENCE_FIELDS, "independently checked evidence");

  const builder = requireKey(trustAnchor.builder, "builder");
  const owner = requireKey(trustAnchor.owner, "owner");
  if (builder.pinSha256 === owner.pinSha256) refuse("builder and owner must have distinct pins");

  const evidence = {};
  for (const field of EVIDENCE_FIELDS) {
    evidence[field] = requireMatch(
      hostState.evidence[field], field === "scannerRulesCommit" ? SHA : DIGEST, field,
    );
  }
  const lastSequence = hostState.lastSequence;
  if (!Number.isSafeInteger(lastSequence) || lastSequence < 0) {
    refuse("protected last accepted sequence is invalid");
  }
  return Object.freeze({
    trustedKeys: Object.freeze({ builder, owner }),
    hostState: Object.freeze({
      sourceSha: requireMatch(hostState.sourceSha, SHA, "source SHA"),
      hostIdentitySha256: requireMatch(hostState.hostIdentitySha256, DIGEST, "host identity"),
      predecessorSha: requireMatch(hostState.predecessorSha, SHA, "predecessor SHA"),
      lastSequence,
      evidence: Object.freeze(evidence),
    }),
  });
}

function requireNativeHost() {
  // No production bypass or injectable kernel value: mocks belong only in
  // isolated test processes. Docker Desktop's WSL kernel must fail closed.
  if (process.platform !== "linux" || process.arch !== "x64" ||
      /microsoft|wsl/iu.test(os.release()) || typeof process.getuid !== "function") {
    refuse("native Linux/amd64 kernel required; WSL/Microsoft kernels are forbidden");
  }
}

function requireTrustedRoot(root) {
  if (typeof root !== "string" || !path.isAbsolute(root) ||
      path.normalize(root) !== root || root === path.parse(root).root) {
    refuse("trusted artifact directory path is invalid");
  }
  const stat = lstatSync(root, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o7777n) !== 0o700n) {
    refuse("trusted artifact directory must be an owner-only 0700 real directory");
  }
  return Object.freeze({ dev: stat.dev, ino: stat.ino, uid: stat.uid, mode: stat.mode });
}

function verifyTrustedRootUnchanged(root, previous) {
  const stat = requireTrustedRoot(root);
  if (stat.dev !== previous.dev || stat.ino !== previous.ino ||
      stat.uid !== previous.uid || stat.mode !== previous.mode) {
    refuse("trusted artifact directory changed during verification");
  }
}

function snapshotArtifacts(artifacts) {
  exactFields(artifacts, [
    "artifactRoot", "sourceArchivePath", "runtimeArchivePath", "migratorArchivePath", "images",
  ], "artifact inputs");
  exactFields(artifacts.images, ["runtime", "migrator"], "image metadata");
  const images = {};
  for (const role of ["runtime", "migrator"]) {
    const image = artifacts.images[role];
    exactFields(image, ["role", "imageId", "sizeBytes", "os", "architecture", "labels"],
      `${role} image metadata`);
    exactFields(image.labels,
      ["org.opencontainers.image.revision", "org.opencontainers.image.source"],
      `${role} image labels`);
    images[role] = Object.freeze({
      role: image.role, imageId: image.imageId, sizeBytes: image.sizeBytes,
      os: image.os, architecture: image.architecture,
      labels: Object.freeze({
        "org.opencontainers.image.revision": image.labels["org.opencontainers.image.revision"],
        "org.opencontainers.image.source": image.labels["org.opencontainers.image.source"],
      }),
    });
  }
  return Object.freeze({
    artifactRoot: artifacts.artifactRoot,
    sourceArchivePath: artifacts.sourceArchivePath,
    runtimeArchivePath: artifacts.runtimeArchivePath,
    migratorArchivePath: artifacts.migratorArchivePath,
    images: Object.freeze(images),
  });
}

/**
 * Read-only verifier foundation. All supplied trust material is snapshotted,
 * three archive bytes/lengths are independently read through no-follow file
 * handles, then the two Ed25519 signatures and host/release/evidence identity
 * are checked against those measurements.
 *
 * The result IS NOT a deployment authorization: image metadata and evidence
 * claims still need native independent verification, revocation/host policy,
 * a durable exclusive anti-replay ledger and full production preflight.
 * Callers must reverify the same artifacts at their eventual use point.
 */
export async function verifyOfflineHostRelease({
  manifestBytes, signatures, trustAnchor, hostState, artifacts, nowSeconds,
} = {}) {
  requireNativeHost();
  const prepared = prepareOfflineHostVerificationContext({ trustAnchor, hostState });
  if (!Buffer.isBuffer(manifestBytes)) refuse("manifest must be supplied as exact bytes");
  exactFields(signatures, ["builder", "owner"], "release signatures");
  const manifestSnapshot = Buffer.from(manifestBytes);
  const signatureSnapshot = Object.freeze({
    builder: signatures.builder,
    owner: signatures.owner,
  });
  const artifactSnapshot = snapshotArtifacts(artifacts);
  const trustedRoot = requireTrustedRoot(artifactSnapshot.artifactRoot);

  const inventory = await inventoryOfflineArtifacts({
    ...artifactSnapshot,
    expectedRevision: prepared.hostState.sourceSha,
  });
  verifyTrustedRootUnchanged(artifactSnapshot.artifactRoot, trustedRoot);
  const { hostState: host } = prepared;
  const checked = verifyOfflineReleaseAttestation({
    manifestBytes: manifestSnapshot,
    signatures: signatureSnapshot,
    trustedKeys: prepared.trustedKeys,
    expected: {
      sourceSha: host.sourceSha,
      sourceArchiveSha256: inventory.source_archive_sha256,
      sourceArchiveSizeBytes: inventory.source_archive_size_bytes,
      platform: "linux/amd64",
      hostIdentitySha256: host.hostIdentitySha256,
      predecessorSha: host.predecessorSha,
      runtimeImage: {
        archiveSha256: inventory.runtime_image.archive_sha256,
        archiveSizeBytes: inventory.runtime_image.archive_size_bytes,
        imageId: inventory.runtime_image.image_id,
      },
      migratorImage: {
        archiveSha256: inventory.migrator_image.archive_sha256,
        archiveSizeBytes: inventory.migrator_image.archive_size_bytes,
        imageId: inventory.migrator_image.image_id,
      },
      ...host.evidence,
      lastSequence: host.lastSequence,
    },
    ...(nowSeconds === undefined ? {} : { nowSeconds }),
  });
  verifyTrustedRootUnchanged(artifactSnapshot.artifactRoot, trustedRoot);
  return Object.freeze({ ...checked, artifacts: inventory });
}
