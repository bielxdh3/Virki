import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import os from "node:os";
import test from "node:test";
import { encodeCanonicalOfflineReleaseManifest, verifyOfflineReleaseAttestation } from "./lib/offline-release-attestation.mjs";
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
const keyPin = (key) => ({
  publicKeyPem: key.export({ type: "spki", format: "pem" }),
  pinSha256: hash(key.export({ type: "spki", format: "der" })),
});
const encode = (value) => Buffer.from(JSON.stringify(value));

function fixture() {
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const policy = {
    version: 1,
    mode: "offline-signed-v1",
    enabled: true,
    ownerAssuranceAccepted: true,
    hostIdentitySha256: host,
    ledgerAnchorSha: prior,
    platform: "linux/amd64",
    builder: keyPin(builder.publicKey),
    owner: keyPin(owner.publicKey),
    revokedPins: [],
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
    ["owner revoked", (s) => { s.policy.revokedPins = [s.policy.owner.pinSha256]; }],
    ["builder revoked", (s) => { s.policy.revokedPins = [s.policy.builder.pinSha256]; }],
    ["forged owner pin", (s) => { s.policy.owner.pinSha256 = digest("0"); }],
    ["invalid owner PEM", (s) => { s.policy.owner.publicKeyPem = "bad"; }],
    ["unexpected private key", (s) => { s.policy.owner.privateKeyPem = "secret"; }],
    ["unknown policy field", (s) => { s.policy.extra = "accepted"; }],
    ["duplicate revocation", (s) => { s.policy.revokedPins = [digest("f"), digest("f")]; }],
    ["oversized revocation list", (s) => { s.policy.revokedPins = Array.from({length: 129}, (_, i) => i.toString(16).padStart(64, "0")); }],
  ]) {
    await t.test(name, () => {
      const sample = fixture();
      mutate(sample);
      assert.throws(() => prepare(sample));
    });
  }
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
