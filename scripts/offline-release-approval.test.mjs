import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { approveOfflineReleaseManually } from "./lib/offline-release-approval.mjs";
import { encodeCanonicalOfflineReleaseManifest, verifyOfflineReleaseAttestation } from "./lib/offline-release-attestation.mjs";
import { signOfflineBuilderManifest } from "./lib/offline-release-signing.mjs";

const NOW = 1_800_000_000;
const hex = (digit, length = 64) => digit.repeat(length);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

function manifest() {
  return {
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git",
    source_sha: hex("a", 40), source_archive_sha256: hex("1"), source_archive_size_bytes: 600,
    platform: "linux/amd64", host_identity_sha256: hex("2"), predecessor_sha: hex("b", 40),
    runtime_image: { archive_sha256: hex("3"), archive_size_bytes: 800, image_id: `sha256:${hex("4")}` },
    migrator_image: { archive_sha256: hex("5"), archive_size_bytes: 900, image_id: `sha256:${hex("6")}` },
    evidence: {
      ci_report_sha256: hex("7"), scanner_report_sha256: hex("8"), scanner_rules_commit: hex("c", 40),
      finding_review_sha256: hex("9"), runtime_smoke_sha256: hex("0"),
      migrator_smoke_sha256: hex("d"), backup_restore_sha256: hex("e"),
    },
    issued_at: NOW - 60, expires_at: NOW + 600, nonce: hex("f", 32), sequence: 4,
  };
}

function expected(m) {
  const image = (i) => ({ archiveSha256: i.archive_sha256, archiveSizeBytes: i.archive_size_bytes, imageId: i.image_id });
  return {
    sourceSha: m.source_sha, sourceArchiveSha256: m.source_archive_sha256,
    sourceArchiveSizeBytes: m.source_archive_size_bytes, platform: m.platform,
    hostIdentitySha256: m.host_identity_sha256, predecessorSha: m.predecessor_sha,
    runtimeImage: image(m.runtime_image), migratorImage: image(m.migrator_image),
    ciReportSha256: m.evidence.ci_report_sha256, scannerReportSha256: m.evidence.scanner_report_sha256,
    scannerRulesCommit: m.evidence.scanner_rules_commit,
    findingReviewSha256: m.evidence.finding_review_sha256, runtimeSmokeSha256: m.evidence.runtime_smoke_sha256,
    migratorSmokeSha256: m.evidence.migrator_smoke_sha256, backupRestoreSha256: m.evidence.backup_restore_sha256,
    lastSequence: 3,
  };
}

function keyEntry(publicKey, keyId) {
  return {
    keyId,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    pinSha256: digest(publicKey.export({ type: "spki", format: "der" })),
  };
}

function fixture() {
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const data = manifest();
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(data);
  return {
    manifestBytes,
    builderSignatureBase64: signOfflineBuilderManifest({ manifestBytes, builderPrivateKey: builder.privateKey }).builderSignatureBase64,
    trustedKeys: { builder: keyEntry(builder.publicKey, "builder-key-1"), owner: keyEntry(owner.publicKey, "owner-key-2") },
    ownerPrivateKey: owner.privateKey,
    reviewedManifestSha256: digest(manifestBytes),
    expected: expected(data),
    nowSeconds: NOW,
    trustedPolicy: {
      version: 1, mode: "EXPLICIT_OWNER_MANUAL_OFFLINE_V1", enabled: true,
      builderKeyId: "builder-key-1", ownerKeyId: "owner-key-2",
      notBeforeSeconds: NOW - 3600, notAfterSeconds: NOW + 3600,
      revokedKeyIds: [], revokedPinsSha256: [],
    },
    ownerAcknowledgement: {
      manifestSha256: digest(manifestBytes), codeql: "NOT_RUN", hostedCi: "NOT_RUN",
      localEvidence: "LOCAL_ONLY", sast: "SEMGREP_OSS_IS_NOT_CODEQL",
      reducedAssuranceAcceptance: "I_EXPLICITLY_ACCEPT_REDUCED_OFFLINE_ASSURANCE",
    },
  };
}

test("manual owner approval requires verified builder and trusted measured evidence, then returns verifiable immutable signatures", () => {
  const f = fixture();
  const approved = approveOfflineReleaseManually(f);
  assert.equal(approved.manifestSha256, digest(f.manifestBytes));
  assert.equal(approved.ownerSignatureBase64.length, 88);
  assert.equal(approved.assurance, "LOCAL_ONLY_CODEQL_NOT_RUN_REDUCED_ASSURANCE");
  assert.equal(approved.builderKeyId, "builder-key-1");
  assert.equal(approved.ownerKeyId, "owner-key-2");
  assert.equal(Object.isFrozen(approved), true);
  assert.equal(Object.isFrozen(approved.signatures), true);
  assert.equal(approved.signatures.builder, f.builderSignatureBase64);
  assert.equal(approved.signatures.owner, approved.ownerSignatureBase64);
  const { builder, owner } = f.trustedKeys;
  const accepted = verifyOfflineReleaseAttestation({
    manifestBytes: f.manifestBytes, signatures: approved.signatures,
    trustedKeys: { builder, owner }, expected: f.expected, nowSeconds: f.nowSeconds,
  });
  assert.equal(accepted.sequence, 4);
  assert.equal(accepted.sourceSha, hex("a", 40));
});

test("rejects invalid builder signature, foreign builder key, and unpinned or revoked trust", () => {
  const f = fixture();
  const other = fixture();
  for (const changed of [
    { builderSignatureBase64: undefined },
    { builderSignatureBase64: other.builderSignatureBase64 },
    { builderSignatureBase64: "!" },
    { trustedKeys: { ...f.trustedKeys, builder: other.trustedKeys.builder } },
    { trustedKeys: { ...f.trustedKeys, builder: { ...f.trustedKeys.builder, pinSha256: hex("0") } } },
    { trustedPolicy: { ...f.trustedPolicy, revokedKeyIds: ["builder-key-1"] } },
    { trustedPolicy: { ...f.trustedPolicy, revokedPinsSha256: [f.trustedKeys.builder.pinSha256] } },
    { trustedPolicy: { ...f.trustedPolicy, revokedKeyIds: ["owner-key-2"] } },
    { trustedPolicy: { ...f.trustedPolicy, revokedPinsSha256: [f.trustedKeys.owner.pinSha256] } },
  ]) {
    assert.throws(() => approveOfflineReleaseManually({ ...f, ...changed }));
  }
});

test("rejects signer identity collision, wrong or unsuitable private owner key", () => {
  const f = fixture();
  const other = fixture();
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  for (const changed of [
    { ownerPrivateKey: other.ownerPrivateKey },
    { ownerPrivateKey: rsa.privateKey },
    { ownerPrivateKey: undefined },
    { ownerPrivateKey: f.trustedKeys.owner.publicKeyPem },
    { trustedKeys: { ...f.trustedKeys, owner: { ...f.trustedKeys.builder } } },
    { trustedKeys: { ...f.trustedKeys, owner: { ...f.trustedKeys.owner, keyId: "builder-key-1" } } },
    { trustedPolicy: { ...f.trustedPolicy, ownerKeyId: "owner-not-pinned" } },
    { trustedPolicy: { ...f.trustedPolicy, builderKeyId: "builder-not-pinned" } },
  ]) {
    assert.throws(() => approveOfflineReleaseManually({ ...f, ...changed }));
  }
});

test("refuses absent or misleading CodeQL/hosted CI disclosure and unreviewed manifest digest", () => {
  const f = fixture();
  for (const changed of [
    { ownerAcknowledgement: undefined },
    { ownerAcknowledgement: { ...f.ownerAcknowledgement, codeql: "SUCCESS" } },
    { ownerAcknowledgement: { ...f.ownerAcknowledgement, hostedCi: "SUCCESS" } },
    { ownerAcknowledgement: { ...f.ownerAcknowledgement, sast: "SEMGREP_EQUALS_CODEQL" } },
    { ownerAcknowledgement: { ...f.ownerAcknowledgement, localEvidence: "HOSTED" } },
    { ownerAcknowledgement: { ...f.ownerAcknowledgement, reducedAssuranceAcceptance: true } },
    { ownerAcknowledgement: { ...f.ownerAcknowledgement, manifestSha256: hex("0") } },
    { reviewedManifestSha256: undefined },
    { reviewedManifestSha256: hex("0") },
    { ownerAcknowledgement: { ...f.ownerAcknowledgement, extra: true } },
  ]) {
    assert.throws(() => approveOfflineReleaseManually({ ...f, ...changed }));
  }
});

test("refuses missing, disabled, expired, or externally substituted approval policy", () => {
  const f = fixture();
  for (const changed of [
    { trustedPolicy: undefined },
    { trustedPolicy: { ...f.trustedPolicy, enabled: false } },
    { trustedPolicy: { ...f.trustedPolicy, version: 2 } },
    { trustedPolicy: { ...f.trustedPolicy, mode: "AUTO_FALLBACK" } },
    { trustedPolicy: { ...f.trustedPolicy, notBeforeSeconds: NOW + 1 } },
    { trustedPolicy: { ...f.trustedPolicy, notAfterSeconds: NOW } },
    { trustedPolicy: { ...f.trustedPolicy, revokedKeyIds: "none" } },
    { trustedPolicy: { ...f.trustedPolicy, unexpected: true } },
    { trustedKeys: { ...f.trustedKeys, owner: { ...f.trustedKeys.owner, extra: "from bundle" } } },
  ]) {
    assert.throws(() => approveOfflineReleaseManually({ ...f, ...changed }));
  }
});

test("rejects wrong independent SHA/host/predecessor/platform, artifacts, evidence, and sequence", () => {
  const f = fixture();
  for (const expected of [
    { sourceSha: hex("b", 40) }, { sourceArchiveSha256: hex("0") }, { sourceArchiveSizeBytes: 601 },
    { hostIdentitySha256: hex("0") }, { predecessorSha: hex("a", 40) }, { platform: "linux/arm64" },
    { runtimeImage: { ...f.expected.runtimeImage, imageId: `sha256:${hex("0")}` } },
    { runtimeImage: { ...f.expected.runtimeImage, archiveSha256: hex("0") } },
    { migratorImage: { ...f.expected.migratorImage, archiveSizeBytes: 901 } },
    { ciReportSha256: hex("0") }, { scannerReportSha256: hex("0") },
    { scannerRulesCommit: hex("0", 40) }, { findingReviewSha256: hex("0") },
    { runtimeSmokeSha256: hex("1") }, { migratorSmokeSha256: hex("0") },
    { backupRestoreSha256: hex("0") }, { lastSequence: 4 }, { lastSequence: undefined },
  ]) {
    assert.throws(() => approveOfflineReleaseManually({ ...f, expected: { ...f.expected, ...expected } }), undefined, JSON.stringify(expected));
  }
});

test("rejects stale/future release, noncanonical/duplicate JSON, and builder-signed replacement manifest", () => {
  const f = fixture();
  const signedOther = fixture();
  const changed = encodeCanonicalOfflineReleaseManifest({ ...manifest(), sequence: 5 });
  for (const altered of [
    { nowSeconds: NOW + 601 }, { nowSeconds: NOW - 61 },
    { manifestBytes: changed }, { builderSignatureBase64: signedOther.builderSignatureBase64 },
    { manifestBytes: Buffer.concat([f.manifestBytes, Buffer.from("\n")]) },
    { manifestBytes: Buffer.from(f.manifestBytes.toString().replace('"version":1', '"version":1,"version":1')) },
    { manifestBytes: Buffer.from(f.manifestBytes.toString().replace('"version":1', '"extra":true,"version":1')) },
    { manifestBytes: Buffer.alloc(8193, 0x20) },
  ]) {
    assert.throws(() => approveOfflineReleaseManually({ ...f, ...altered }), undefined, Object.keys(altered).join(","));
  }
});
