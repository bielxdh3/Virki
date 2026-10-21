import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { encodeCanonicalOfflineReleaseManifest, verifyOfflineReleaseAttestation } from "./lib/offline-release-attestation.mjs";
import { signOfflineBuilderManifest, signOfflineOwnerApproval } from "./lib/offline-release-signing.mjs";

const sha = (v, n = 64) => v.repeat(n);
const NOW = 1_800_000_000;
const SOURCE = sha("a", 40);
function manifest() {
  return {
    version: 1,
    release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git",
    source_sha: SOURCE,
    source_archive_sha256: sha("1"),
    source_archive_size_bytes: 1234,
    platform: "linux/amd64",
    host_identity_sha256: sha("2"),
    predecessor_sha: sha("b", 40),
    runtime_image: { archive_sha256: sha("3"), archive_size_bytes: 3344, image_id: `sha256:${sha("4")}` },
    migrator_image: { archive_sha256: sha("5"), archive_size_bytes: 5566, image_id: `sha256:${sha("6")}` },
    evidence: {
      ci_report_sha256: sha("7"), scanner_report_sha256: sha("8"), scanner_rules_commit: sha("c", 40),
      finding_review_sha256: sha("9"), runtime_smoke_sha256: sha("0"),
      migrator_smoke_sha256: sha("d"), backup_restore_sha256: sha("e"),
    },
    issued_at: NOW - 60, expires_at: NOW + 600,
    nonce: sha("f", 32), sequence: 1,
  };
}

function pin(publicKey) {
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const pinSha256 = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  return { publicKeyPem, pinSha256 };
}

function expected(m) {
  const image = (v) => ({ archiveSha256: v.archive_sha256, archiveSizeBytes: v.archive_size_bytes, imageId: v.image_id });
  return {
    sourceSha: m.source_sha, sourceArchiveSha256: m.source_archive_sha256,
    sourceArchiveSizeBytes: m.source_archive_size_bytes, platform: m.platform,
    hostIdentitySha256: m.host_identity_sha256, predecessorSha: m.predecessor_sha,
    runtimeImage: image(m.runtime_image), migratorImage: image(m.migrator_image),
    ciReportSha256: m.evidence.ci_report_sha256, scannerReportSha256: m.evidence.scanner_report_sha256,
    scannerRulesCommit: m.evidence.scanner_rules_commit,
    findingReviewSha256: m.evidence.finding_review_sha256,
    runtimeSmokeSha256: m.evidence.runtime_smoke_sha256,
    migratorSmokeSha256: m.evidence.migrator_smoke_sha256,
    backupRestoreSha256: m.evidence.backup_restore_sha256, lastSequence: 0,
  };
}

test("two distinct manual signing roles produce signatures accepted by independent verifier", () => {
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const m = manifest();
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(m);
  const built = signOfflineBuilderManifest({ manifestBytes, builderPrivateKey: builder.privateKey });
  const approved = signOfflineOwnerApproval({
    manifestBytes, reviewedManifestSha256: built.manifestSha256, ownerPrivateKey: owner.privateKey,
  });
  assert.equal(built.manifestSha256, approved.manifestSha256);
  assert.equal(approved.ownerSignatureBase64.length, 88);
  const verified = verifyOfflineReleaseAttestation({
    manifestBytes,
    signatures: { builder: built.builderSignatureBase64, owner: approved.ownerSignatureBase64 },
    trustedKeys: { builder: pin(builder.publicKey), owner: pin(owner.publicKey) },
    expected: expected(m), nowSeconds: NOW,
  });
  assert.equal(verified.sourceSha, SOURCE);
  assert.equal(verified.sequence, 1);
});

test("owner refusal for unreviewed digest, foreign digest, malformed manifest or wrong keys", () => {
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const m = manifest();
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(m);
  const correct = createHash("sha256").update(manifestBytes).digest("hex");
  for (const reviewedManifestSha256 of [undefined, "A".repeat(64), "0".repeat(64), "0", ""]) {
    assert.throws(() => signOfflineOwnerApproval({ manifestBytes, reviewedManifestSha256, ownerPrivateKey: owner.privateKey }));
  }
  assert.throws(() => signOfflineOwnerApproval({ manifestBytes, reviewedManifestSha256: correct, ownerPrivateKey: owner.publicKey }));
  assert.throws(() => signOfflineBuilderManifest({ manifestBytes, builderPrivateKey: owner.publicKey }));
  const wrongAlgorithm = generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.throws(() => signOfflineBuilderManifest({ manifestBytes, builderPrivateKey: wrongAlgorithm.privateKey }));
  for (const bad of [Buffer.alloc(9000, 0), Buffer.from("{}"), Buffer.concat([manifestBytes, Buffer.from("\n")])]) {
    assert.throws(() => signOfflineBuilderManifest({ manifestBytes: bad, builderPrivateKey: builder.privateKey }));
    assert.throws(() => signOfflineOwnerApproval({ manifestBytes: bad, reviewedManifestSha256: correct, ownerPrivateKey: owner.privateKey }));
  }
});

test("signing a different manifest invalidates old review and signatures", () => {
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const original = encodeCanonicalOfflineReleaseManifest(manifest());
  const changed = encodeCanonicalOfflineReleaseManifest({ ...manifest(), sequence: 2 });
  const digest = signOfflineBuilderManifest({ manifestBytes: original, builderPrivateKey: builder.privateKey }).manifestSha256;
  assert.throws(() => signOfflineOwnerApproval({ manifestBytes: changed, reviewedManifestSha256: digest, ownerPrivateKey: owner.privateKey }));
});
