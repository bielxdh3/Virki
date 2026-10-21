import { createHash, createPublicKey, verify } from "node:crypto";

// This library only validates a supplied attestation. It deliberately does not
// enable an offline production gate or read keys from the release itself.
const RELEASE_GATE = "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1";
const CANONICAL_REPOSITORY = "https://github.com/bielxdh3/Virki.git";
const MAX_MANIFEST_BYTES = 8192;
const MAX_IMAGE_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024;
const MAX_VALIDITY_SECONDS = 24 * 60 * 60;
const BUILDER_DOMAIN = Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0", "utf8");
const OWNER_DOMAIN = Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0", "utf8");
const HASH = /^[0-9a-f]{64}$/u;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const NONCE = /^[0-9a-f]{32}$/u;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;

function fail(message) {
  throw new Error(`Offline release attestation rejected: ${message}`);
}

function requireObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length ||
      fields.some((key) => !Object.hasOwn(value, key))) {
    fail(`${label} schema is invalid`);
  }
}

function requireMatch(value, expression, label) {
  if (typeof value !== "string" || !expression.test(value)) fail(`${label} is invalid`);
  return value;
}

function requireSafeInteger(value, min, max, label) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`${label} is invalid`);
  return value;
}

function canonicalImage(image, name) {
  requireObject(image, ["archive_sha256", "archive_size_bytes", "image_id"], name);
  return {
    archive_sha256: requireMatch(image.archive_sha256, HASH, `${name} archive hash`),
    archive_size_bytes: requireSafeInteger(image.archive_size_bytes, 1, MAX_IMAGE_ARCHIVE_BYTES, `${name} archive size`),
    image_id: requireMatch(image.image_id, IMAGE_ID, `${name} image ID`),
  };
}

function canonicalManifest(value) {
  requireObject(value, [
    "version", "release_gate", "repository", "source_sha", "source_archive_sha256", "source_archive_size_bytes",
    "platform", "host_identity_sha256", "predecessor_sha", "runtime_image", "migrator_image",
    "evidence", "issued_at", "expires_at", "nonce", "sequence",
  ], "manifest");
  if (value.version !== 1 || value.release_gate !== RELEASE_GATE ||
      value.repository !== CANONICAL_REPOSITORY || value.platform !== "linux/amd64") {
    fail("manifest release policy is unsupported");
  }
  requireObject(value.evidence, [
    "ci_report_sha256", "scanner_report_sha256", "scanner_rules_commit", "finding_review_sha256",
    "runtime_smoke_sha256", "migrator_smoke_sha256", "backup_restore_sha256",
  ], "evidence");
  const issuedAt = requireSafeInteger(value.issued_at, 1, Number.MAX_SAFE_INTEGER, "issue time");
  const expiresAt = requireSafeInteger(value.expires_at, 1, Number.MAX_SAFE_INTEGER, "expiry time");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_VALIDITY_SECONDS) fail("validity window is invalid");
  return {
    version: 1,
    release_gate: RELEASE_GATE,
    repository: CANONICAL_REPOSITORY,
    source_sha: requireMatch(value.source_sha, FULL_SHA, "source SHA"),
    source_archive_sha256: requireMatch(value.source_archive_sha256, HASH, "source archive hash"),
    source_archive_size_bytes: requireSafeInteger(value.source_archive_size_bytes, 1, MAX_IMAGE_ARCHIVE_BYTES, "source archive size"),
    platform: "linux/amd64",
    host_identity_sha256: requireMatch(value.host_identity_sha256, HASH, "host identity hash"),
    predecessor_sha: requireMatch(value.predecessor_sha, FULL_SHA, "predecessor SHA"),
    runtime_image: canonicalImage(value.runtime_image, "runtime image"),
    migrator_image: canonicalImage(value.migrator_image, "migrator image"),
    evidence: {
      ci_report_sha256: requireMatch(value.evidence.ci_report_sha256, HASH, "CI report hash"),
      scanner_report_sha256: requireMatch(value.evidence.scanner_report_sha256, HASH, "scanner report hash"),
      scanner_rules_commit: requireMatch(value.evidence.scanner_rules_commit, FULL_SHA, "scanner rules revision"),
      finding_review_sha256: requireMatch(value.evidence.finding_review_sha256, HASH, "reviewed findings hash"),
      runtime_smoke_sha256: requireMatch(value.evidence.runtime_smoke_sha256, HASH, "runtime smoke report hash"),
      migrator_smoke_sha256: requireMatch(value.evidence.migrator_smoke_sha256, HASH, "migrator smoke report hash"),
      backup_restore_sha256: requireMatch(value.evidence.backup_restore_sha256, HASH, "backup-restore report hash"),
    },
    issued_at: issuedAt,
    expires_at: expiresAt,
    nonce: requireMatch(value.nonce, NONCE, "nonce"),
    sequence: requireSafeInteger(value.sequence, 1, Number.MAX_SAFE_INTEGER, "sequence"),
  };
}

export function encodeCanonicalOfflineReleaseManifest(value) {
  const bytes = Buffer.from(`${JSON.stringify(canonicalManifest(value))}\n`, "utf8");
  if (bytes.length > MAX_MANIFEST_BYTES) fail("manifest is oversized");
  return bytes;
}

function decodeCanonicalManifest(manifestBytes) {
  if (!Buffer.isBuffer(manifestBytes) || manifestBytes.length === 0 ||
      manifestBytes.length > MAX_MANIFEST_BYTES) fail("manifest bytes are missing or oversized");
  // Own the bytes during verification, so a caller cannot mutate the signed
  // buffer between hashing, parsing, and signature checking.
  const bytes = Buffer.from(manifestBytes);
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("manifest is not JSON");
  }
  const canonical = canonicalManifest(parsed);
  if (!encodeCanonicalOfflineReleaseManifest(canonical).equals(bytes)) {
    fail("manifest bytes are not canonical");
  }
  return { canonical, bytes };
}

function pinnedPublicKey(entry, label) {
  if (!entry || typeof entry !== "object" ||
      typeof entry.publicKeyPem !== "string" || entry.publicKeyPem.length > 2048 ||
      !HASH.test(entry.pinSha256 ?? "")) fail(`${label} public-key pin is missing`);
  let key;
  try {
    key = createPublicKey(entry.publicKeyPem);
  } catch {
    fail(`${label} public key cannot be decoded`);
  }
  if (key.asymmetricKeyType !== "ed25519") fail(`${label} must use Ed25519`);
  const der = key.export({ type: "spki", format: "der" });
  const observed = createHash("sha256").update(der).digest("hex");
  if (observed !== entry.pinSha256) fail(`${label} public key does not match trusted pin`);
  return { key, der };
}

function signatureBytes(encoded, label) {
  if (typeof encoded !== "string" || !SIGNATURE.test(encoded)) fail(`${label} signature has invalid encoding`);
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== encoded) fail(`${label} signature encoding is not canonical`);
  return bytes;
}

function requireMatchingImage(actual, expected, label) {
  if (!expected || actual.archive_sha256 !== expected.archiveSha256 ||
      actual.archive_size_bytes !== expected.archiveSizeBytes || actual.image_id !== expected.imageId) {
    fail(`${label} differs from independently measured image evidence`);
  }
}

/**
 * Verify an already-staged manifest against independently measured evidence.
 * trustedKeys and expected MUST come from a trusted operator/host context,
 * never from the manifest or an untrusted bundle. This does not persist the
 * sequence, prove a scan ran, or authorize production. A future host gate must
 * atomically persist sequence/nonce under a lock before any mutation.
 */
export function verifyOfflineReleaseAttestation({
  manifestBytes,
  signatures,
  trustedKeys,
  expected,
  nowSeconds = Math.floor(Date.now() / 1000),
} = {}) {
  const { canonical: manifest, bytes } = decodeCanonicalManifest(manifestBytes);
  if (!trustedKeys || !expected || !signatures) fail("trusted verification inputs are missing");
  const builder = pinnedPublicKey(trustedKeys.builder, "builder");
  const owner = pinnedPublicKey(trustedKeys.owner, "owner");
  if (builder.der.equals(owner.der)) fail("builder and owner must have distinct signing keys");

  const digest = createHash("sha256").update(bytes).digest();
  const builderSignature = signatureBytes(signatures.builder, "builder");
  const ownerSignature = signatureBytes(signatures.owner, "owner");
  if (!verify(null, Buffer.concat([BUILDER_DOMAIN, bytes]), builder.key, builderSignature)) {
    fail("builder signature verification failed");
  }
  if (!verify(null, Buffer.concat([OWNER_DOMAIN, digest]), owner.key, ownerSignature)) {
    fail("owner approval signature verification failed");
  }

  requireSafeInteger(nowSeconds, 1, Number.MAX_SAFE_INTEGER, "verification time");
  if (manifest.issued_at > nowSeconds || manifest.expires_at <= nowSeconds) {
    fail("release approval is not currently valid");
  }
  if (manifest.source_sha !== expected.sourceSha ||
      manifest.source_archive_sha256 !== expected.sourceArchiveSha256 ||
      manifest.source_archive_size_bytes !== expected.sourceArchiveSizeBytes ||
      manifest.host_identity_sha256 !== expected.hostIdentitySha256 ||
      manifest.predecessor_sha !== expected.predecessorSha ||
      manifest.platform !== expected.platform) {
    fail("release identity differs from trusted target or source evidence");
  }
  requireMatchingImage(manifest.runtime_image, expected.runtimeImage, "runtime image");
  requireMatchingImage(manifest.migrator_image, expected.migratorImage, "migrator image");
  if (manifest.evidence.ci_report_sha256 !== expected.ciReportSha256 ||
      manifest.evidence.scanner_report_sha256 !== expected.scannerReportSha256 ||
      manifest.evidence.scanner_rules_commit !== expected.scannerRulesCommit ||
      manifest.evidence.finding_review_sha256 !== expected.findingReviewSha256 ||
      manifest.evidence.runtime_smoke_sha256 !== expected.runtimeSmokeSha256 ||
      manifest.evidence.migrator_smoke_sha256 !== expected.migratorSmokeSha256 ||
      manifest.evidence.backup_restore_sha256 !== expected.backupRestoreSha256) {
    fail("test and scanner evidence hashes do not match");
  }
  const lastSequence = requireSafeInteger(expected.lastSequence, 0, Number.MAX_SAFE_INTEGER, "last accepted sequence");
  if (manifest.sequence <= lastSequence) fail("release sequence was already accepted or downgraded");

  return Object.freeze({
    releaseGate: RELEASE_GATE,
    sourceSha: manifest.source_sha,
    predecessorSha: manifest.predecessor_sha,
    manifestSha256: digest.toString("hex"),
    sequence: manifest.sequence,
    nonce: manifest.nonce,
    expiresAt: manifest.expires_at,
  });
}
