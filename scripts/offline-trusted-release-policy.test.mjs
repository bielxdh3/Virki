import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import os from "node:os";
import test from "node:test";
import { encodeCanonicalOfflineReleaseManifest, verifyOfflineReleaseAttestation } from "./lib/offline-release-attestation.mjs";
import { approveOfflineReleaseManually } from "./lib/offline-release-approval.mjs";
import {
  prepareOfflineTrustedReleasePolicy,
  verifyInstalledOfflineRelease,
} from "./lib/offline-trusted-release-policy.mjs";

const sha = (character) => character.repeat(40);
const digest = (character) => character.repeat(64);
const host = digest("9");
const now = 1_800_000_000;
const prior = sha("a");
const next = sha("b");
const hash = (source) => createHash("sha256").update(source).digest("hex");
const keyPin = (key, keyId) => ({
  keyId,
  publicKeyPem: key.export({ type: "spki", format: "pem" }),
  pinSha256: hash(key.export({ type: "spki", format: "der" })),
});
const encode = (value) => Buffer.from(JSON.stringify(value));

function fixture() {
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const policy = {
    // Host policy v2 deliberately refuses the legacy pin-only policy: a
    // revocation by signer keyId cannot be represented in the v1 format.
    version: 2,
    mode: "offline-signed-v1",
    enabled: true,
    ownerAssuranceAccepted: true,
    hostIdentitySha256: host,
    ledgerAnchorSha: prior,
    platform: "linux/amd64",
    builder: keyPin(builder.publicKey, "trusted-builder-2026"),
    owner: keyPin(owner.publicKey, "trusted-owner-2026"),
    revokedKeyIds: [],
    revokedPinsSha256: [],
  };
  const ledger = { version: 1, anchorSha: prior, entries: [] };
  const manifest = {
    version: 1,
    release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git",
    source_sha: next,
    source_archive_sha256: digest("1"),
    source_archive_size_bytes: 1500,
    platform: "linux/amd64",
    host_identity_sha256: host,
    predecessor_sha: prior,
    runtime_image: { archive_sha256: digest("2"), archive_size_bytes: 1800, image_id: `sha256:${digest("3")}` },
    migrator_image: { archive_sha256: digest("4"), archive_size_bytes: 1900, image_id: `sha256:${digest("5")}` },
    evidence: {
      ci_report_sha256: digest("6"),
      scanner_report_sha256: digest("7"),
      scanner_rules_commit: sha("c"),
      finding_review_sha256: digest("8"),
      runtime_smoke_sha256: digest("a"),
      migrator_smoke_sha256: digest("b"),
      backup_restore_sha256: digest("c"),
    },
    issued_at: now - 60,
    expires_at: now + 900,
    nonce: "d".repeat(32),
    sequence: 1,
  };
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(manifest);
  const signatures = {
    builder: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0"), manifestBytes]), builder.privateKey).toString("base64"),
    owner: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0"), Buffer.from(hash(manifestBytes), "hex")]), owner.privateKey).toString("base64"),
  };
  const expected = {
    sourceSha: next,
    sourceArchiveSha256: manifest.source_archive_sha256,
    sourceArchiveSizeBytes: manifest.source_archive_size_bytes,
    platform: "linux/amd64",
    hostIdentitySha256: host,
    predecessorSha: prior,
    runtimeImage: { archiveSha256: manifest.runtime_image.archive_sha256, archiveSizeBytes: manifest.runtime_image.archive_size_bytes, imageId: manifest.runtime_image.image_id },
    migratorImage: { archiveSha256: manifest.migrator_image.archive_sha256, archiveSizeBytes: manifest.migrator_image.archive_size_bytes, imageId: manifest.migrator_image.image_id },
    ciReportSha256: manifest.evidence.ci_report_sha256,
    scannerReportSha256: manifest.evidence.scanner_report_sha256,
    scannerRulesCommit: manifest.evidence.scanner_rules_commit,
    findingReviewSha256: manifest.evidence.finding_review_sha256,
    runtimeSmokeSha256: manifest.evidence.runtime_smoke_sha256,
    migratorSmokeSha256: manifest.evidence.migrator_smoke_sha256,
    backupRestoreSha256: manifest.evidence.backup_restore_sha256,
    lastSequence: 0,
  };
  return { builder, owner, policy, ledger, manifestBytes, signatures, expected };
}

function prepare(sample, overrides = {}) {
  return prepareOfflineTrustedReleasePolicy({
    policyBytes: encode(sample.policy),
    ledgerBytes: encode(sample.ledger),
    measuredHostIdentitySha256: host,
    ...overrides,
  });
}

test("validates pinned host policy and ledger then verifies both genuine domain-separated signatures", () => {
  const sample = fixture();
  const prepared = prepare(sample);
  assert.equal(prepared.hostIdentitySha256, host);
  assert.equal(prepared.predecessorSha, prior);
  assert.equal(prepared.lastSequence, 0);
  assert.equal(prepared.trustedKeys.builder.keyId, "trusted-builder-2026");
  assert.equal(prepared.trustedKeys.owner.keyId, "trusted-owner-2026");
  const result = verifyOfflineReleaseAttestation({
    manifestBytes: sample.manifestBytes,
    signatures: sample.signatures,
    trustedKeys: prepared.trustedKeys,
    expected: { ...sample.expected, hostIdentitySha256: prepared.hostIdentitySha256, predecessorSha: prepared.predecessorSha, lastSequence: prepared.lastSequence },
    nowSeconds: now,
  });
  assert.equal(result.sourceSha, next);
  assert.equal(result.sequence, 1);
});

test("rejects unsigned, disabled, unauthorised or unpinned trust policy", async (t) => {
  for (const [name, mutate] of [
    ["missing explicit owner assurance", (s) => { s.policy.ownerAssuranceAccepted = false; }],
    ["offline disabled", (s) => { s.policy.enabled = false; }],
    ["unknown mode", (s) => { s.policy.mode = "ghcr"; }],
    ["wrong platform", (s) => { s.policy.platform = "linux/arm64"; }],
    ["forged host", (s) => { s.policy.hostIdentitySha256 = digest("0"); }],
    ["same key", (s) => { s.policy.owner = s.policy.builder; }],
    ["owner pin revoked", (s) => { s.policy.revokedPinsSha256 = [s.policy.owner.pinSha256]; }],
    ["builder pin revoked", (s) => { s.policy.revokedPinsSha256 = [s.policy.builder.pinSha256]; }],
    ["owner keyId revoked but pin NOT revoked", (s) => { s.policy.revokedKeyIds = [s.policy.owner.keyId]; }],
    ["builder keyId revoked but pin NOT revoked", (s) => { s.policy.revokedKeyIds = [s.policy.builder.keyId]; }],
    ["legacy pin-only policy forbidden", (s) => {
      s.policy.version = 1;
      s.policy.builder = { publicKeyPem: s.policy.builder.publicKeyPem, pinSha256: s.policy.builder.pinSha256 };
      s.policy.owner = { publicKeyPem: s.policy.owner.publicKeyPem, pinSha256: s.policy.owner.pinSha256 };
      delete s.policy.revokedKeyIds;
      delete s.policy.revokedPinsSha256;
      s.policy.revokedPins = [];
    }],
    ["unrecognized policy version", (s) => { s.policy.version = 1; }],
    ["reassigned duplicate signer keyIds", (s) => { s.policy.owner.keyId = s.policy.builder.keyId; }],
    ["missing builder keyId", (s) => { delete s.policy.builder.keyId; }],
    ["malformed builder keyId", (s) => { s.policy.builder.keyId = "builder id"; }],
    ["oversized builder keyId", (s) => { s.policy.builder.keyId = "b".repeat(65); }],
    ["unexpected embedded keyId alias", (s) => { s.policy.builder.identity = "trusted-builder-2026"; }],
    ["forged owner pin", (s) => { s.policy.owner.pinSha256 = digest("0"); }],
    ["invalid owner PEM", (s) => { s.policy.owner.publicKeyPem = "bad"; }],
    ["unexpected private key", (s) => { s.policy.owner.privateKeyPem = "secret"; }],
    ["unknown policy field", (s) => { s.policy.extra = "accepted"; }],
    ["duplicate pin revocation", (s) => { s.policy.revokedPinsSha256 = [digest("f"), digest("f")]; }],
    ["duplicate key ID revocation", (s) => { s.policy.revokedKeyIds = ["former-owner", "former-owner"]; }],
    ["malformed key ID revocation", (s) => { s.policy.revokedKeyIds = ["from bundle/../../etc"]; }],
    ["oversized pin revocation list", (s) => { s.policy.revokedPinsSha256 = Array.from({length: 129}, (_, i) => i.toString(16).padStart(64, "0")); }],
    ["oversized ID revocation list", (s) => { s.policy.revokedKeyIds = Array.from({length: 129}, (_, i) => `retired-${i}`); }],
    ["unrecognized old pin revocation field", (s) => { s.policy.revokedPins = []; }],
  ]) {
    await t.test(name, () => {
      const sample = fixture();
      mutate(sample);
      assert.throws(() => prepare(sample));
    });
  }
});

test("host independently enforces signer-compatible key-ID and public-pin revocation semantics", () => {
  const sample = fixture();
  sample.policy.revokedKeyIds = ["retired-builder-2025", "retired-owner-2025"];
  sample.policy.revokedPinsSha256 = [digest("f")];
  const prepared = prepare(sample);
  assert.equal(prepared.trustedKeys.builder.keyId, sample.policy.builder.keyId);
  assert.equal(prepared.trustedKeys.owner.keyId, sample.policy.owner.keyId);
  assert.equal(verifyOfflineReleaseAttestation({
    manifestBytes: sample.manifestBytes, signatures: sample.signatures,
    trustedKeys: prepared.trustedKeys, expected: sample.expected, nowSeconds: now,
  }).sourceSha, next);
  // Revocation is evaluated against the fixed-root host policy's own key IDs.
  // No key identifier is accepted from candidate or manifest inputs.
  sample.policy.revokedKeyIds = [sample.policy.builder.keyId];
  assert.throws(() => prepare(sample), /revoked/u);
  sample.policy.revokedKeyIds = [];
  sample.policy.revokedPinsSha256 = [sample.policy.builder.pinSha256];
  assert.throws(() => prepare(sample), /revoked/u);
});

test("independent owner signer and fixed-root host both refuse a revoked builder ID without a revoked pin", () => {
  const sample = fixture();
  const revokedBuilderId = sample.policy.builder.keyId;
  const reviewedManifestSha256 = hash(sample.manifestBytes);
  const signerPolicy = {
    version: 1, mode: "EXPLICIT_OWNER_MANUAL_OFFLINE_V1", enabled: true,
    builderKeyId: revokedBuilderId, ownerKeyId: sample.policy.owner.keyId,
    notBeforeSeconds: now - 100, notAfterSeconds: now + 100,
    revokedKeyIds: [revokedBuilderId], revokedPinsSha256: [],
  };
  const signerInput = {
    manifestBytes: sample.manifestBytes,
    builderSignatureBase64: sample.signatures.builder,
    trustedKeys: { builder: sample.policy.builder, owner: sample.policy.owner },
    ownerPrivateKey: sample.owner.privateKey,
    reviewedManifestSha256,
    expected: sample.expected,
    nowSeconds: now,
    trustedPolicy: signerPolicy,
    ownerAcknowledgement: {
      manifestSha256: reviewedManifestSha256, codeql: "NOT_RUN", hostedCi: "NOT_RUN",
      localEvidence: "LOCAL_ONLY", sast: "SEMGREP_OSS_IS_NOT_CODEQL",
      reducedAssuranceAcceptance: "I_EXPLICITLY_ACCEPT_REDUCED_OFFLINE_ASSURANCE",
    },
  };
  assert.throws(() => approveOfflineReleaseManually(signerInput), /revoked/u);
  // This is separately provisioned host state, not an ID supplied via a bundle.
  sample.policy.revokedKeyIds = [revokedBuilderId];
  assert.equal(sample.policy.revokedPinsSha256.length, 0);
  assert.throws(() => prepare(sample), /revoked/u);
});

test("rejects unknown, replayed, skipped or corrupt ledger history", async (t) => {
  const first = fixture();
  const accepted = { sequence: 1, priorSha: prior, nextSha: next, manifestSha256: digest("1"), nonce: "a".repeat(32), approvalDigest: digest("2") };
  for (const [name, mutate] of [
    ["missing anchor", (s) => { delete s.ledger.anchorSha; }],
    ["foreign prior anchor", (s) => { s.ledger.anchorSha = sha("f"); }],
    ["stale next sequence", (s) => { s.ledger.entries = [accepted]; }],
    ["forged predecessor", (s) => { s.ledger.entries = [{ ...accepted, priorSha: sha("f") }]; }],
    ["nonconsecutive history", (s) => { s.ledger.entries = [{ ...accepted, sequence: 3 }]; }],
    ["repeated historical nonce", (s) => { s.ledger.entries = [accepted, { ...accepted, sequence: 2, priorSha: next, nextSha: sha("e") }]; }],
    ["downgraded history", (s) => { s.ledger.entries = [{...accepted, nextSha: prior}]; }],
    ["extra ledger field", (s) => { s.ledger.injected = true; }],
  ]) {
    await t.test(name, () => {
      const sample = fixture();
      mutate(sample);
      const result = () => prepare(sample);
      if (name === "stale next sequence") {
        const prepared = result();
        assert.equal(prepared.lastSequence, 1);
        assert.throws(() => verifyOfflineReleaseAttestation({
          manifestBytes: first.manifestBytes, signatures: first.signatures,
          trustedKeys: prepared.trustedKeys,
          expected: { ...first.expected, predecessorSha: prepared.predecessorSha, lastSequence: prepared.lastSequence },
          nowSeconds: now,
        }));
      } else {
        assert.throws(result);
      }
    });
  }
});

test("rejects malformed, oversized, ambiguous policy and ledger bytes", async (t) => {
  for (const [name, overrides] of [
    ["missing policy", { policyBytes: undefined }],
    ["missing ledger", { ledgerBytes: undefined }],
    ["invalid policy utf8", { policyBytes: Buffer.from([0xff]) }],
    ["noncanonical policy", { policyBytes: Buffer.from(' { } ') }],
    ["duplicate policy JSON key", { policyBytes: Buffer.from('{"version":1,"version":1}') }],
    ["oversized policy", { policyBytes: Buffer.alloc(65_537, 32) }],
    ["invalid ledger JSON", { ledgerBytes: Buffer.from("null") }],
    ["oversized ledger", { ledgerBytes: Buffer.alloc(1024 * 1024 + 1, 32) }],
    ["host mismatch", { measuredHostIdentitySha256: digest("0") }],
  ]) {
    await t.test(name, () => assert.throws(() => prepare(fixture(), overrides)));
  }
});

test("native installed-policy loader never accepts a developer/WSL machine as production", () => {
  if (process.platform === "linux" && !/wsl|microsoft/iu.test(os.release())) return;
  assert.throws(() => verifyInstalledOfflineRelease({}), /native Linux/iu);
});

test("signed verification must reject forged signature even when trusted pins are genuine", () => {
  const sample = fixture();
  const prepared = prepare(sample);
  assert.throws(() => verifyOfflineReleaseAttestation({
    manifestBytes: sample.manifestBytes,
    signatures: { ...sample.signatures, owner: sample.signatures.builder },
    trustedKeys: prepared.trustedKeys,
    expected: sample.expected,
    nowSeconds: now,
  }));
});

test.skip("installed fixed-path root-owned filesystem and O_NOFOLLOW integration needs a separately provisioned native Linux host");
