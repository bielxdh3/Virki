import { createHash, createPublicKey, KeyObject, verify } from "node:crypto";
import { encodeCanonicalOfflineReleaseManifest, verifyOfflineReleaseAttestation } from "./offline-release-attestation.mjs";
import { signOfflineOwnerApproval } from "./offline-release-signing.mjs";

// Manual owner-signing library only. The caller supplies a protected independent
// key policy, trusted measured evidence and an ephemeral private KeyObject.
// None of these inputs may be loaded from the candidate bundle. No environment,
// keyfile, CI status, production connection, or automatic approval is consulted.
const BUILDER_DOMAIN = Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0", "utf8");
const SHA256 = /^[0-9a-f]{64}$/u;
const SHA = /^[0-9a-f]{40}$/u;
const KEY_ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/u;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const EXPECTED_FIELDS = Object.freeze([
  "sourceSha", "sourceArchiveSha256", "sourceArchiveSizeBytes", "platform",
  "hostIdentitySha256", "predecessorSha", "runtimeImage", "migratorImage",
  "ciReportSha256", "scannerReportSha256", "scannerRulesCommit",
  "findingReviewSha256", "runtimeSmokeSha256", "migratorSmokeSha256",
  "backupRestoreSha256", "lastSequence",
]);
const POLICY_FIELDS = Object.freeze([
  "version", "mode", "enabled", "builderKeyId", "ownerKeyId", "notBeforeSeconds",
  "notAfterSeconds", "revokedKeyIds", "revokedPinsSha256",
]);
const ACK_FIELDS = Object.freeze([
  "manifestSha256", "codeql", "hostedCi", "localEvidence", "sast", "reducedAssuranceAcceptance",
]);

function reject(message) {
  throw new Error(`Offline manual owner approval refused: ${message}`);
}

function exactFields(value, fields, name) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(value, field))) {
    reject(`${name} must contain exactly the required fields`);
  }
}

function requirePattern(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) reject(`${label} is invalid`);
  return value;
}

function requireSafeInteger(value, min, label) {
  if (!Number.isSafeInteger(value) || value < min) reject(`${label} is invalid`);
  return value;
}

function pinnedKey(entry, label) {
  exactFields(entry, ["keyId", "publicKeyPem", "pinSha256"], `${label} signing identity`);
  requirePattern(entry.keyId, KEY_ID, `${label} key identifier`);
  requirePattern(entry.pinSha256, SHA256, `${label} key pin`);
  if (typeof entry.publicKeyPem !== "string" || entry.publicKeyPem.length > 2048 ||
      entry.publicKeyPem.length < 1) reject(`${label} public key is invalid`);
  let key;
  try {
    key = createPublicKey(entry.publicKeyPem);
  } catch {
    reject(`${label} public key cannot be decoded`);
  }
  if (key.asymmetricKeyType !== "ed25519") reject(`${label} signing key must be Ed25519`);
  const der = key.export({ type: "spki", format: "der" });
  if (createHash("sha256").update(der).digest("hex") !== entry.pinSha256) {
    reject(`${label} public key does not match independently trusted pin`);
  }
  return { key, der, keyId: entry.keyId, pinSha256: entry.pinSha256 };
}

function validateTrustedPolicy(policy, builder, owner, nowSeconds) {
  exactFields(policy, POLICY_FIELDS, "independent manual release policy");
  if (policy.version !== 1 || policy.mode !== "EXPLICIT_OWNER_MANUAL_OFFLINE_V1" || policy.enabled !== true) {
    reject("independent owner policy has not explicitly enabled manual offline signing");
  }
  if (policy.builderKeyId !== builder.keyId || policy.ownerKeyId !== owner.keyId ||
      builder.keyId === owner.keyId || builder.der.equals(owner.der)) {
    reject("builder and owner must have distinct, policy-pinned signing identities");
  }
  const validFrom = requireSafeInteger(policy.notBeforeSeconds, 1, "policy start time");
  const validUntil = requireSafeInteger(policy.notAfterSeconds, 1, "policy end time");
  if (validUntil <= validFrom || nowSeconds < validFrom || nowSeconds >= validUntil) {
    reject("manual offline signing policy is not currently valid");
  }
  const revocations = [
    [policy.revokedKeyIds, KEY_ID, "key ID"],
    [policy.revokedPinsSha256, SHA256, "public-key pin"],
  ];
  for (const [entries, pattern, label] of revocations) {
    if (!Array.isArray(entries) || entries.length > 128 ||
        entries.some((entry) => typeof entry !== "string" || !pattern.test(entry)) ||
        new Set(entries).size !== entries.length) reject(`revoked ${label} list is invalid`);
  }
  if (policy.revokedKeyIds.includes(builder.keyId) || policy.revokedKeyIds.includes(owner.keyId) ||
      policy.revokedPinsSha256.includes(builder.pinSha256) ||
      policy.revokedPinsSha256.includes(owner.pinSha256)) {
    reject("one of the signing identities has been revoked");
  }
}

function canonicalManifestSnapshot(manifestBytes) {
  if (!Buffer.isBuffer(manifestBytes) || manifestBytes.length === 0 || manifestBytes.length > 8192) {
    reject("manifest must be supplied as canonical, bounded bytes");
  }
  const bytes = Buffer.from(manifestBytes);
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    reject("manifest bytes are invalid UTF-8 or JSON");
  }
  if (!encodeCanonicalOfflineReleaseManifest(parsed).equals(bytes)) {
    reject("manifest bytes are not canonical");
  }
  return { bytes, manifest: parsed, manifestSha256: createHash("sha256").update(bytes).digest("hex") };
}

function verifyExpectedIdentity(manifest, expected) {
  exactFields(expected, EXPECTED_FIELDS, "independently measured release evidence");
  const pairs = [
    [manifest.source_sha, expected.sourceSha],
    [manifest.source_archive_sha256, expected.sourceArchiveSha256],
    [manifest.source_archive_size_bytes, expected.sourceArchiveSizeBytes],
    [manifest.platform, expected.platform],
    [manifest.host_identity_sha256, expected.hostIdentitySha256],
    [manifest.predecessor_sha, expected.predecessorSha],
    [manifest.evidence.ci_report_sha256, expected.ciReportSha256],
    [manifest.evidence.scanner_report_sha256, expected.scannerReportSha256],
    [manifest.evidence.scanner_rules_commit, expected.scannerRulesCommit],
    [manifest.evidence.finding_review_sha256, expected.findingReviewSha256],
    [manifest.evidence.runtime_smoke_sha256, expected.runtimeSmokeSha256],
    [manifest.evidence.migrator_smoke_sha256, expected.migratorSmokeSha256],
    [manifest.evidence.backup_restore_sha256, expected.backupRestoreSha256],
  ];
  if (pairs.some(([signed, observed]) => signed !== observed)) {
    reject("manifest identity differs from independently reviewed source, host, images or evidence");
  }
  for (const [signed, observed] of [
    [manifest.runtime_image, expected.runtimeImage],
    [manifest.migrator_image, expected.migratorImage],
  ]) {
    exactFields(observed, ["archiveSha256", "archiveSizeBytes", "imageId"], "measured image");
    if (signed.archive_sha256 !== observed.archiveSha256 ||
        signed.archive_size_bytes !== observed.archiveSizeBytes || signed.image_id !== observed.imageId) {
      reject("manifest image differs from independently measured artifact");
    }
  }
  if (!SHA.test(expected.sourceSha) || !SHA.test(expected.predecessorSha) ||
      expected.platform !== "linux/amd64" ||
      manifest.sequence <= requireSafeInteger(expected.lastSequence, 0, "last release sequence")) {
    reject("source, platform or monotonic release sequence is not acceptable");
  }
}

function validateAcknowledgement(acknowledgement, reviewedManifestSha256) {
  exactFields(acknowledgement, ACK_FIELDS, "explicit owner assurance acknowledgement");
  if (acknowledgement.manifestSha256 !== reviewedManifestSha256 ||
      acknowledgement.codeql !== "NOT_RUN" || acknowledgement.hostedCi !== "NOT_RUN" ||
      acknowledgement.localEvidence !== "LOCAL_ONLY" ||
      acknowledgement.sast !== "SEMGREP_OSS_IS_NOT_CODEQL" ||
      acknowledgement.reducedAssuranceAcceptance !== "I_EXPLICITLY_ACCEPT_REDUCED_OFFLINE_ASSURANCE") {
    reject("owner must explicitly acknowledge local-only evidence and missing CodeQL/hosted CI");
  }
}

/**
 * Sign only after independently validating canonical builder evidence, trusted
 * identities/policy, reviewed target identity, unexpired sequence and the owner's
 * explicit reduced-assurance acknowledgement. This is a CLI-level signing
 * primitive; it neither enables production nor proves local CI actually ran.
 * The caller must acquire `expected` and `trustedPolicy` outside the bundle.
 */
export function approveOfflineReleaseManually({
  manifestBytes, builderSignatureBase64, trustedKeys, ownerPrivateKey,
  reviewedManifestSha256, expected, nowSeconds, trustedPolicy, ownerAcknowledgement,
} = {}) {
  requireSafeInteger(nowSeconds, 1, "trusted current time");
  exactFields(trustedKeys, ["builder", "owner"], "trusted public keys");
  const builder = pinnedKey(trustedKeys.builder, "builder");
  const owner = pinnedKey(trustedKeys.owner, "owner");
  validateTrustedPolicy(trustedPolicy, builder, owner, nowSeconds);

  const snapshot = canonicalManifestSnapshot(manifestBytes);
  if (requirePattern(reviewedManifestSha256, SHA256, "reviewed manifest SHA-256") !== snapshot.manifestSha256) {
    reject("owner has not supplied the exact reviewed manifest SHA-256");
  }
  validateAcknowledgement(ownerAcknowledgement, snapshot.manifestSha256);
  if (snapshot.manifest.issued_at > nowSeconds || snapshot.manifest.expires_at <= nowSeconds) {
    reject("release manifest is expired or not yet valid");
  }
  verifyExpectedIdentity(snapshot.manifest, expected);

  requirePattern(builderSignatureBase64, SIGNATURE, "builder signature");
  const builderSignature = Buffer.from(builderSignatureBase64, "base64");
  if (builderSignature.length !== 64 || builderSignature.toString("base64") !== builderSignatureBase64 ||
      !verify(null, Buffer.concat([BUILDER_DOMAIN, snapshot.bytes]), builder.key, builderSignature)) {
    reject("pinned builder signature does not authenticate reviewed manifest bytes");
  }
  // Derive only the public half. Never serialize, log, export or persist the
  // owner's private key. Reject a different or reused signer before signing.
  if (!(ownerPrivateKey instanceof KeyObject) || ownerPrivateKey.type !== "private" ||
      ownerPrivateKey.asymmetricKeyType !== "ed25519" ||
      !createPublicKey(ownerPrivateKey).export({ type: "spki", format: "der" }).equals(owner.der)) {
    reject("transient Ed25519 owner private key does not match independently pinned owner identity");
  }
  const ownerSignatureBase64 = signOfflineOwnerApproval({
    manifestBytes: snapshot.bytes,
    reviewedManifestSha256: snapshot.manifestSha256,
    ownerPrivateKey,
  }).ownerSignatureBase64;
  const signatures = Object.freeze({ builder: builderSignatureBase64, owner: ownerSignatureBase64 });
  // Verify the final assembled artifact with the same verifier used by the host.
  verifyOfflineReleaseAttestation({
    manifestBytes: snapshot.bytes,
    signatures,
    trustedKeys,
    expected,
    nowSeconds,
  });
  return Object.freeze({
    manifestSha256: snapshot.manifestSha256,
    builderKeyId: builder.keyId,
    ownerKeyId: owner.keyId,
    ownerSignatureBase64,
    signatures,
    assurance: "LOCAL_ONLY_CODEQL_NOT_RUN_REDUCED_ASSURANCE",
  });
}
