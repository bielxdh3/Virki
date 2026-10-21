import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  encodeCanonicalOfflineReleaseManifest,
  verifyOfflineReleaseAttestation,
} from "./lib/offline-release-attestation.mjs";

const sha = (letter) => letter.repeat(64);
const revision = "0123456789abcdef0123456789abcdef01234567";
const predecessor = "fedcba9876543210fedcba9876543210fedcba98";
const NOW = 1_800_000_000;
const builderDomain = Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0", "utf8");
const ownerDomain = Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0", "utf8");

function testKeys() {
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const publicEntry = (key) => {
    const publicKeyPem = key.export({ type: "spki", format: "pem" });
    const pinSha256 = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
    return { publicKeyPem, pinSha256 };
  };
  return {
    builder,
    owner,
    trustedKeys: { builder: publicEntry(builder.publicKey), owner: publicEntry(owner.publicKey) },
  };
}

function testManifest() {
  return {
    version: 1,
    release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git",
    source_sha: revision,
    source_archive_sha256: sha("a"),
    source_archive_size_bytes: 12345,
    platform: "linux/amd64",
    host_identity_sha256: sha("b"),
    predecessor_sha: predecessor,
    runtime_image: { archive_sha256: sha("c"), archive_size_bytes: 123456, image_id: `sha256:${sha("d")}` },
    migrator_image: { archive_sha256: sha("e"), archive_size_bytes: 654321, image_id: `sha256:${sha("f")}` },
    evidence: {
      ci_report_sha256: sha("1"),
      scanner_report_sha256: sha("2"),
      scanner_rules_commit: "17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9",
      finding_review_sha256: sha("3"),
      runtime_smoke_sha256: sha("4"),
      migrator_smoke_sha256: sha("5"),
      backup_restore_sha256: sha("6"),
    },
    issued_at: NOW - 60,
    expires_at: NOW + 900,
    nonce: "0123456789abcdef0123456789abcdef",
    sequence: 42,
  };
}

function expectedFor(manifest) {
  return {
    sourceSha: manifest.source_sha,
    sourceArchiveSha256: manifest.source_archive_sha256,
    sourceArchiveSizeBytes: manifest.source_archive_size_bytes,
    platform: manifest.platform,
    hostIdentitySha256: manifest.host_identity_sha256,
    predecessorSha: manifest.predecessor_sha,
    runtimeImage: {
      archiveSha256: manifest.runtime_image.archive_sha256,
      archiveSizeBytes: manifest.runtime_image.archive_size_bytes,
      imageId: manifest.runtime_image.image_id,
    },
    migratorImage: {
      archiveSha256: manifest.migrator_image.archive_sha256,
      archiveSizeBytes: manifest.migrator_image.archive_size_bytes,
      imageId: manifest.migrator_image.image_id,
    },
    ciReportSha256: manifest.evidence.ci_report_sha256,
    scannerReportSha256: manifest.evidence.scanner_report_sha256,
    scannerRulesCommit: manifest.evidence.scanner_rules_commit,
    findingReviewSha256: manifest.evidence.finding_review_sha256,
    runtimeSmokeSha256: manifest.evidence.runtime_smoke_sha256,
    migratorSmokeSha256: manifest.evidence.migrator_smoke_sha256,
    backupRestoreSha256: manifest.evidence.backup_restore_sha256,
    lastSequence: 41,
  };
}

function signedFixture(manifest = testManifest(), keys = testKeys()) {
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(manifest);
  const digest = createHash("sha256").update(manifestBytes).digest();
  const signatures = {
    builder: sign(null, Buffer.concat([builderDomain, manifestBytes]), keys.builder.privateKey).toString("base64"),
    owner: sign(null, Buffer.concat([ownerDomain, digest]), keys.owner.privateKey).toString("base64"),
  };
  return {
    manifestBytes,
    signatures,
    trustedKeys: keys.trustedKeys,
    expected: expectedFor(manifest),
    nowSeconds: NOW,
  };
}

test("accepts exact canonical manifest with independent pinned Ed25519 builder and owner signatures", () => {
  const sample = signedFixture();
  const result = verifyOfflineReleaseAttestation(sample);
  assert.equal(result.sourceSha, revision);
  assert.equal(result.sequence, 42);
  assert.equal(result.manifestSha256, createHash("sha256").update(sample.manifestBytes).digest("hex"));
  assert.equal(result.releaseGate, "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1");
});

test("rejects tampering, noncanonical whitespace, duplicate or additional fields", () => {
  const fixture = signedFixture();
  const tampered = Buffer.from(fixture.manifestBytes);
  tampered[tampered.indexOf(Buffer.from(sha("a")))] = 0x62;
  for (const manifestBytes of [
    tampered,
    Buffer.concat([fixture.manifestBytes, Buffer.from("\n")]),
    Buffer.from(fixture.manifestBytes.toString().replace('"version":1', '"version":1,"version":1')),
    Buffer.from(fixture.manifestBytes.toString().replace('"version":1', '"unexpected":true,"version":1')),
    Buffer.from(fixture.manifestBytes.toString().replace('"version":1', '"version": 1')),
  ]) {
    assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, manifestBytes }));
  }
});

test("rejects stale, future-dated, excessively long-lived and invalid timestamps", () => {
  for (const update of [
    { expires_at: NOW - 1 },
    { issued_at: NOW + 1 },
  ]) {
    const fixture = signedFixture({ ...testManifest(), ...update });
    assert.throws(() => verifyOfflineReleaseAttestation(fixture));
  }
  for (const update of [
    { issued_at: NOW - 86400, expires_at: NOW + 2 },
    { issued_at: NOW, expires_at: NOW },
    { expires_at: "tomorrow" },
  ]) {
    assert.throws(() => signedFixture({ ...testManifest(), ...update }));
  }
});

test("rejects wrong target host, source SHA, archive hash, predecessor or architecture", () => {
  const fixture = signedFixture();
  const mismatches = [
    { sourceSha: predecessor },
    { sourceArchiveSha256: sha("0") },
    { sourceArchiveSizeBytes: 12346 },
    { hostIdentitySha256: sha("0") },
    { predecessorSha: revision },
    { platform: "linux/arm64" },
  ];
  for (const update of mismatches) {
    assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, expected: { ...fixture.expected, ...update } }));
  }
});

test("rejects changed image archive hash, image ID, image size and report hashes", () => {
  const fixture = signedFixture();
  const expected = fixture.expected;
  for (const changed of [
    { runtimeImage: { ...expected.runtimeImage, archiveSha256: sha("0") } },
    { runtimeImage: { ...expected.runtimeImage, archiveSizeBytes: 123457 } },
    { runtimeImage: { ...expected.runtimeImage, imageId: `sha256:${sha("0")}` } },
    { migratorImage: { ...expected.migratorImage, archiveSha256: sha("0") } },
    { migratorImage: { ...expected.migratorImage, archiveSizeBytes: 1 } },
    { ciReportSha256: sha("0") },
    { scannerReportSha256: sha("0") },
    { scannerRulesCommit: predecessor },
    { findingReviewSha256: sha("0") },
    { runtimeSmokeSha256: sha("0") },
    { migratorSmokeSha256: sha("0") },
    { backupRestoreSha256: sha("0") },
  ]) {
    assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, expected: { ...expected, ...changed } }));
  }
});

test("rejects invalid and swapped signatures, wrong key pins, non-Ed25519 and reused signer", () => {
  const fixture = signedFixture();
  const forged = { ...fixture.signatures, owner: fixture.signatures.builder };
  assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, signatures: forged }));
  assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, signatures: { ...fixture.signatures, builder: "!" } }));
  assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, trustedKeys: { ...fixture.trustedKeys, owner: { ...fixture.trustedKeys.owner, pinSha256: sha("0") } } }));
  const same = testKeys();
  same.trustedKeys.owner = same.trustedKeys.builder;
  assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, trustedKeys: same.trustedKeys }));
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPem = rsa.publicKey.export({ type: "spki", format: "pem" });
  const rsaPin = createHash("sha256").update(rsa.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, trustedKeys: { ...fixture.trustedKeys, owner: { publicKeyPem: rsaPem, pinSha256: rsaPin } } }));
});

test("rejects replayed sequence, missing ledger position and malformed nonce", () => {
  const fixture = signedFixture();
  for (const lastSequence of [42, 43, -1, undefined, "41"]) {
    assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, expected: { ...fixture.expected, lastSequence } }));
  }
  for (const nonce of ["1", "a".repeat(33), "A".repeat(32)]) {
    assert.throws(() => encodeCanonicalOfflineReleaseManifest({ ...testManifest(), nonce }));
  }
});

test("rejects oversized payload, non-JSON, illegal manifest fields or ambiguous order", () => {
  const fixture = signedFixture();
  for (const manifestBytes of [Buffer.alloc(8193, 0x20), Buffer.from("undefined"), Buffer.from("null")]) {
    assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, manifestBytes }));
  }
  for (const altered of [
    { version: 2 },
    { release_gate: "OWNER_APPROVED_EXACT_SHA_CODEQL_SARIF_GATE" },
    { platform: "linux/arm64" },
    { source_sha: revision.toUpperCase() },
    { source_archive_size_bytes: Number.MAX_SAFE_INTEGER },
    { runtime_image: { ...testManifest().runtime_image, archive_size_bytes: Number.MAX_SAFE_INTEGER } },
    { evidence: { ...testManifest().evidence, other: sha("3") } },
    { evidence: { ...testManifest().evidence, scanner_rules_commit: "unknown" } },
  ]) {
    assert.throws(() => encodeCanonicalOfflineReleaseManifest({ ...testManifest(), ...altered }));
  }
  const reversed = Object.fromEntries(Object.entries(testManifest()).reverse());
  assert.equal(encodeCanonicalOfflineReleaseManifest(reversed).equals(fixture.manifestBytes), true);
  assert.throws(() => verifyOfflineReleaseAttestation({ ...fixture, manifestBytes: Buffer.from(JSON.stringify(reversed) + "\n") }));
});
