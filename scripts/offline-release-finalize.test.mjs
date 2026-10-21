import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { finalizeSignedOfflineRelease } from "./offline-release-finalize.mjs";
import { encodeCanonicalOfflineReleaseManifest } from "./lib/offline-release-attestation.mjs";
import { signOfflineBuilderManifest, signOfflineOwnerApproval } from "./lib/offline-release-signing.mjs";
import { inspectUntrustedOfflineCandidate } from "../infra/offline/trusted-host-entry.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hex = (ch, length = 64) => ch.repeat(length);
const NOW = 1_800_000_000;
const SOURCE_SHA = hex("a", 40);
const PREDECESSOR = hex("b", 40);
const INPUTS = ["manifest.json", "source.tar", "runtime.tar", "migrator.tar", "ci-report.json",
  "scanner-report.json", "finding-review.json", "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json"];
const OUTPUTS = [...INPUTS, "signatures.json"].sort();

function keyPin(publicKey) {
  return { publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
    pinSha256: hash(publicKey.export({ format: "der", type: "spki" })) };
}

function fixture(t, atSeconds = NOW) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-finalizer-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const unsignedDirectory = path.join(root, "unsigned");
  const outputParent = path.join(root, "published");
  mkdirSync(unsignedDirectory, { mode: 0o700 });
  mkdirSync(outputParent, { mode: 0o700 });
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const data = Object.fromEntries(INPUTS.filter((v) => v !== "manifest.json")
    .map((name, i) => [name, Buffer.from(`${name}: actual source fixture ${i}`)]));
  const image = (name, imageId) => ({ archive_sha256: hash(data[name]), archive_size_bytes: data[name].length,
    image_id: `sha256:${hex(imageId)}` });
  const manifest = {
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git",
    source_sha: SOURCE_SHA, source_archive_sha256: hash(data["source.tar"]),
    source_archive_size_bytes: data["source.tar"].length, platform: "linux/amd64",
    host_identity_sha256: hex("1"), predecessor_sha: PREDECESSOR,
    runtime_image: image("runtime.tar", "2"), migrator_image: image("migrator.tar", "3"),
    evidence: {
      ci_report_sha256: hash(data["ci-report.json"]),
      scanner_report_sha256: hash(data["scanner-report.json"]), scanner_rules_commit: hex("c", 40),
      finding_review_sha256: hash(data["finding-review.json"]),
      runtime_smoke_sha256: hash(data["runtime-smoke.json"]),
      migrator_smoke_sha256: hash(data["migrator-smoke.json"]),
      backup_restore_sha256: hash(data["backup-restore.json"]),
    },
    issued_at: atSeconds - 60, expires_at: atSeconds + 600, nonce: hex("d", 32), sequence: 9,
  };
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(manifest);
  data["manifest.json"] = manifestBytes;
  for (const [name, bytes] of Object.entries(data)) {
    writeFileSync(path.join(unsignedDirectory, name), bytes, { mode: 0o600 });
  }
  const reviewedManifestSha256 = hash(manifestBytes);
  const signatures = {
    builder: signOfflineBuilderManifest({ manifestBytes, builderPrivateKey: builder.privateKey }).builderSignatureBase64,
    owner: signOfflineOwnerApproval({ manifestBytes, ownerPrivateKey: owner.privateKey,
      reviewedManifestSha256 }).ownerSignatureBase64,
  };
  const expected = {
    sourceSha: manifest.source_sha, sourceArchiveSha256: manifest.source_archive_sha256,
    sourceArchiveSizeBytes: manifest.source_archive_size_bytes, platform: manifest.platform,
    hostIdentitySha256: manifest.host_identity_sha256, predecessorSha: manifest.predecessor_sha,
    runtimeImage: { archiveSha256: manifest.runtime_image.archive_sha256,
      archiveSizeBytes: manifest.runtime_image.archive_size_bytes, imageId: manifest.runtime_image.image_id },
    migratorImage: { archiveSha256: manifest.migrator_image.archive_sha256,
      archiveSizeBytes: manifest.migrator_image.archive_size_bytes, imageId: manifest.migrator_image.image_id },
    ciReportSha256: manifest.evidence.ci_report_sha256,
    scannerReportSha256: manifest.evidence.scanner_report_sha256,
    scannerRulesCommit: manifest.evidence.scanner_rules_commit,
    findingReviewSha256: manifest.evidence.finding_review_sha256,
    runtimeSmokeSha256: manifest.evidence.runtime_smoke_sha256,
    migratorSmokeSha256: manifest.evidence.migrator_smoke_sha256,
    backupRestoreSha256: manifest.evidence.backup_restore_sha256,
    lastSequence: 8,
  };
  const options = {
    unsignedDirectory, outputParent, signatures,
    trustedKeys: { builder: keyPin(builder.publicKey), owner: keyPin(owner.publicKey) },
    expected, reviewedManifestSha256, nowSeconds: atSeconds,
  };
  return { root, data, manifest, manifestBytes, builder, owner, unsignedDirectory,
    outputParent, options, reviewedManifestSha256 };
}

test("finalizes 10-file unsigned release into exactly 11 pinned private signed files compatible with native entry", async (t) => {
  const f = fixture(t);
  const signed = await finalizeSignedOfflineRelease(f.options);
  assert.equal(signed.manifestSha256, f.reviewedManifestSha256);
  assert.equal(signed.sourceSha, SOURCE_SHA);
  assert.equal(signed.status, "SIGNED_CANDIDATE_ONLY");
  assert.equal(Object.isFrozen(signed), true);
  assert.deepEqual(readdirSync(signed.candidateDirectory).sort(), OUTPUTS);
  assert.deepEqual(readdirSync(f.unsignedDirectory).sort(), INPUTS.slice().sort());
  assert.equal(lstatSync(signed.candidateDirectory).mode & 0o777, 0o700);
  for (const name of OUTPUTS) {
    const file = path.join(signed.candidateDirectory, name);
    const stat = lstatSync(file);
    assert.equal(stat.mode & 0o777, 0o600, name);
    assert.equal(stat.nlink, 1, name);
    if (name !== "signatures.json") assert.deepEqual(readFileSync(file), f.data[name]);
  }
  assert.deepEqual(JSON.parse(readFileSync(path.join(signed.candidateDirectory, "signatures.json"))), f.options.signatures);
  assert.equal(readFileSync(path.join(signed.candidateDirectory, "signatures.json"), "utf8").endsWith("\n"), false);
  const hostEnvelope = await inspectUntrustedOfflineCandidate({ candidateDirectory: signed.candidateDirectory });
  assert.equal(hostEnvelope.status, "UNTRUSTED_ENVELOPE_ONLY");
  assert.equal(hostEnvelope.manifestDigest, f.reviewedManifestSha256);
  assert.equal(hostEnvelope.signatures.owner, f.options.signatures.owner);
  assert.equal(readdirSync(f.outputParent).length, 1);
});

test("rejects missing/swapped signatures, unreviewed hash and untrusted pins before making an output", async (t) => {
  const f = fixture(t);
  const other = fixture(t);
  for (const altered of [
    { signatures: { ...f.options.signatures, owner: other.options.signatures.owner } },
    { signatures: { ...f.options.signatures, builder: other.options.signatures.builder } },
    { signatures: { ...f.options.signatures, owner: f.options.signatures.builder } },
    { signatures: { ...f.options.signatures, builder: "!" } },
    { signatures: { ...f.options.signatures, extra: true } },
    { signatures: undefined },
    { reviewedManifestSha256: hex("0") },
    { reviewedManifestSha256: undefined },
    { trustedKeys: { ...f.options.trustedKeys, owner: other.options.trustedKeys.owner } },
    { trustedKeys: { ...f.options.trustedKeys, owner: f.options.trustedKeys.builder } },
    { trustedKeys: { ...f.options.trustedKeys, builder: {
      ...f.options.trustedKeys.builder, pinSha256: hex("0") } } },
    { trustedKeys: undefined },
    { expected: { ...f.options.expected, sourceSha: PREDECESSOR } },
    { expected: { ...f.options.expected, hostIdentitySha256: hex("0") } },
    { expected: { ...f.options.expected, lastSequence: 9 } },
    { nowSeconds: NOW + 601 },
  ]) {
    await assert.rejects(finalizeSignedOfflineRelease({ ...f.options, ...altered }));
    assert.deepEqual(readdirSync(f.outputParent), []);
  }
});

test("rejects altered manifest, missing report, foreign file and replaced artifact", async (t) => {
  const f = fixture(t);
  const tamper = (name, bytes) => writeFileSync(path.join(f.unsignedDirectory, name), bytes);
  for (const [name, mutation] of [
    ["manifest.json", Buffer.from(f.manifestBytes.toString().replace('"sequence":9', '"sequence":8'))],
    ["runtime.tar", Buffer.from("forged runtime")],
    ["ci-report.json", Buffer.from("claimed green CI")],
    ["scanner-report.json", Buffer.from("changed scanner")],
  ]) {
    tamper(name, mutation);
    await assert.rejects(finalizeSignedOfflineRelease(f.options), undefined, name);
    assert.deepEqual(readdirSync(f.outputParent), []);
    tamper(name, f.data[name]);
  }
  writeFileSync(path.join(f.unsignedDirectory, "extra.txt"), "foreign", { mode: 0o600 });
  await assert.rejects(finalizeSignedOfflineRelease(f.options));
  unlinkSync(path.join(f.unsignedDirectory, "extra.txt"));
  unlinkSync(path.join(f.unsignedDirectory, "backup-restore.json"));
  await assert.rejects(finalizeSignedOfflineRelease(f.options));
  assert.deepEqual(readdirSync(f.outputParent), []);
});

test("rejects symlink, hardlink, misowned permissions and aliasing before copying", async (t) => {
  const f = fixture(t);
  const target = path.join(f.unsignedDirectory, "scanner-report.json");
  unlinkSync(target);
  symlinkSync(path.join(f.unsignedDirectory, "finding-review.json"), target);
  await assert.rejects(finalizeSignedOfflineRelease(f.options));
  unlinkSync(target);
  writeFileSync(target, f.data["scanner-report.json"], { mode: 0o600 });
  const linked = path.join(f.root, "linked");
  linkSync(target, linked);
  await assert.rejects(finalizeSignedOfflineRelease(f.options));
  unlinkSync(linked);
  chmodSync(target, 0o644);
  await assert.rejects(finalizeSignedOfflineRelease(f.options));
  chmodSync(target, 0o600);
  chmodSync(f.unsignedDirectory, 0o755);
  await assert.rejects(finalizeSignedOfflineRelease(f.options));
  chmodSync(f.unsignedDirectory, 0o700);
  chmodSync(f.outputParent, 0o777);
  await assert.rejects(finalizeSignedOfflineRelease(f.options));
  chmodSync(f.outputParent, 0o700);
  const alias = path.join(f.root, "stage-alias");
  symlinkSync(f.unsignedDirectory, alias);
  await assert.rejects(finalizeSignedOfflineRelease({ ...f.options, unsignedDirectory: alias }));
  assert.deepEqual(readdirSync(f.outputParent), []);
});

test("refuses unsupported platform / missing independent expected release facts", async (t) => {
  const f = fixture(t);
  for (const changed of [
    { expected: undefined },
    { expected: { ...f.options.expected, platform: "linux/arm64" } },
    { expected: { ...f.options.expected, runtimeImage: { ...f.options.expected.runtimeImage,
      archiveSizeBytes: f.options.expected.runtimeImage.archiveSizeBytes + 1 } } },
    { expected: { ...f.options.expected, scannerReportSha256: hex("0") } },
    { expected: { ...f.options.expected, predecessorSha: SOURCE_SHA } },
  ]) {
    await assert.rejects(finalizeSignedOfflineRelease({ ...f.options, ...changed }));
    assert.deepEqual(readdirSync(f.outputParent), []);
  }
});

test("operator CLI consumes canonical private independent request and emits only a signed candidate identity", (t) => {
  const f = fixture(t, Math.floor(Date.now() / 1000));
  const operator = path.join(f.root, "operator");
  mkdirSync(operator, { mode: 0o700 });
  const request = path.join(operator, "request.json");
  const { nowSeconds: _nowSeconds, ...values } = f.options;
  writeFileSync(request, JSON.stringify(values), { mode: 0o600 });
  const stdout = execFileSync(process.execPath, [path.join(import.meta.dirname, "offline-release-finalize.mjs"),
    "--request", request], { encoding: "utf8" });
  const info = JSON.parse(stdout);
  assert.equal(info.status, "SIGNED_CANDIDATE_ONLY");
  assert.equal(info.manifestSha256, f.reviewedManifestSha256);
  assert.deepEqual(readdirSync(info.candidateDirectory).sort(), OUTPUTS);
  assert.equal(Object.hasOwn(info, "trustedKeys"), false);
  assert.equal(Object.hasOwn(info, "signatures"), false);
});

test("operator CLI rejects duplicate-key or unprivileged trust file before creating any package", (t) => {
  const f = fixture(t, Math.floor(Date.now() / 1000));
  const operator = path.join(f.root, "operator");
  mkdirSync(operator, { mode: 0o700 });
  const request = path.join(operator, "request.json");
  const { nowSeconds: _nowSeconds, ...values } = f.options;
  const execute = () => execFileSync(process.execPath,
    [path.join(import.meta.dirname, "offline-release-finalize.mjs"), "--request", request],
    { encoding: "utf8", stdio: "pipe" });
  writeFileSync(request, JSON.stringify(values).replace('"signatures":', '"signatures":null,"signatures":'),
    { mode: 0o600 });
  assert.throws(execute);
  writeFileSync(request, JSON.stringify(values));
  chmodSync(request, 0o644);
  assert.throws(execute);
  assert.deepEqual(readdirSync(f.outputParent), []);
});
