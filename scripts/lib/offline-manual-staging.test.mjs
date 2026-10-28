import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encodeCanonicalOfflineReleaseManifest } from "./offline-release-attestation.mjs";
import { stageLocalOfflineCandidate } from "./offline-manual-staging.mjs";

const linux = { skip: process.platform !== "linux" };
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const files = ["source.tar", "runtime.tar", "migrator.tar", "ci-report.json", "scanner-report.json", "finding-review.json", "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json"];

function candidate(t) {
  const base = mkdtempSync(path.join(os.tmpdir(), "virki-manual-stage-"));
  chmodSync(base, 0o700);
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const source = path.join(base, "source");
  const dest = path.join(base, "stage-parent");
  mkdirSync(source, { mode: 0o700 });
  mkdirSync(dest, { mode: 0o700 });
  const content = Object.fromEntries(files.map((name) => [name, Buffer.from("fixture:" + name)]));
  for (const [name, bytes] of Object.entries(content)) writeFileSync(path.join(source, name), bytes, { flag: "wx", mode: 0o600 });
  const sha = (c) => c.repeat(40);
  const digest = (c) => c.repeat(64);
  const manifest = encodeCanonicalOfflineReleaseManifest({
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1", repository: "https://github.com/bielxdh3/Virki.git",
    source_sha: sha("a"), source_archive_sha256: hash(content["source.tar"]), source_archive_size_bytes: content["source.tar"].length,
    platform: "linux/amd64", host_identity_sha256: digest("9"), predecessor_sha: sha("b"),
    runtime_image: { archive_sha256: hash(content["runtime.tar"]), archive_size_bytes: content["runtime.tar"].length, image_id: "sha256:" + digest("1") },
    migrator_image: { archive_sha256: hash(content["migrator.tar"]), archive_size_bytes: content["migrator.tar"].length, image_id: "sha256:" + digest("2") },
    evidence: { ci_report_sha256: hash(content["ci-report.json"]), scanner_report_sha256: hash(content["scanner-report.json"]), scanner_rules_commit: sha("c"),
      finding_review_sha256: hash(content["finding-review.json"]), runtime_smoke_sha256: hash(content["runtime-smoke.json"]), migrator_smoke_sha256: hash(content["migrator-smoke.json"]),
      backup_restore_sha256: hash(content["backup-restore.json"]) },
    issued_at: 1_000_000, expires_at: 1_001_000, nonce: "d".repeat(32), sequence: 1,
  });
  writeFileSync(path.join(source, "manifest.json"), manifest, { flag: "wx", mode: 0o600 });
  writeFileSync(path.join(source, "signatures.json"), JSON.stringify({ builder: "A".repeat(86) + "==", owner: "A".repeat(86) + "==" }), { flag: "wx", mode: 0o600 });
  return { base, source, dest, manifest, content };
}

test("real source-to-staging copy creates a private 11-file candidate with identical read-back bytes and no authorization", linux, async (t) => {
  const f = candidate(t);
  const result = await stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest });
  assert.equal(result.status, "LOCAL_STAGING_BYTES_COPIED_UNTRUSTED");
  assert.equal(result.transferAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.manifestSha256, hash(f.manifest));
  assert.equal(lstatSync(result.stagedDirectory).mode & 0o777, 0o700);
  assert.deepEqual(readdirSync(result.stagedDirectory).sort(), ["manifest.json", "signatures.json", ...files].sort());
  for (const name of ["manifest.json", "signatures.json", ...files]) {
    assert.equal(lstatSync(path.join(result.stagedDirectory, name)).mode & 0o777, 0o600);
    assert.deepEqual(readFileSync(path.join(result.stagedDirectory, name)), readFileSync(path.join(f.source, name)));
  }
  assert.equal(readdirSync(f.dest).length, 1);
});

test("tampered candidate cannot create even an untrusted staged copy", linux, async (t) => {
  const f = candidate(t);
  writeFileSync(path.join(f.source, "runtime.tar"), "tampered archive");
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest }));
  assert.deepEqual(readdirSync(f.dest), []);
});

test("symlink, hardlink, foreign file, aliased destination and nested roots are refused before copying", linux, async (t) => {
  const f = candidate(t);
  const original = path.join(f.source, "source.tar");
  const other = path.join(f.base, "external-source");
  renameSync(original, other);
  symlinkSync(other, original);
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest }));
  rmSync(original);
  // The source itself must be a hardlink to an external inode, even with the
  // exact eleven-file inventory and no unexpected extra candidate file.
  linkSync(other, original);
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest }));
  rmSync(original);
  renameSync(other, original);
  const foreign = path.join(f.source, "foreign");
  writeFileSync(foreign, "unexpected", { mode: 0o600 });
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest }));
  rmSync(foreign);
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.source }));
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: path.join(f.source, "subdir") }));
  assert.deepEqual(readdirSync(f.dest), []);
});

test("never accepts caller approval, transport, or witness overrides as staging authority", linux, async (t) => {
  const f = candidate(t);
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest, ownerApproved: true }));
  await assert.rejects(stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest, witnessCasAuthorized: true }));
  assert.deepEqual(readdirSync(f.dest), []);
});

test("post-rename directory sync failure retains exactly owned stage and reports uncertain result", {
  skip: process.platform !== "linux" || !/microsoft|wsl/iu.test(os.release()),
}, async (t) => {
  const f = candidate(t);
  const old = process.env.VIRKI_TEST_MANUAL_STAGING_SYNC_FAIL;
  process.env.VIRKI_TEST_MANUAL_STAGING_SYNC_FAIL = "1";
  try {
    await assert.rejects(
      stageLocalOfflineCandidate({ candidateDirectory: f.source, stagingParent: f.dest }),
      (error) => error?.code === "MANUAL_STAGE_AFTER_RENAME_UNCERTAIN" &&
        typeof error.stagedDirectory === "string" &&
        error.stagedDirectory.startsWith(f.dest + path.sep) &&
        readdirSync(error.stagedDirectory).length === 11,
    );
    assert.equal(readdirSync(f.dest).length, 1);
  } finally {
    if (old === undefined) delete process.env.VIRKI_TEST_MANUAL_STAGING_SYNC_FAIL;
    else process.env.VIRKI_TEST_MANUAL_STAGING_SYNC_FAIL = old;
  }
});
