import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  inspectUntrustedOfflineCandidate,
  verifyTrustedHostOfflineCandidate,
} from "./trusted-host-entry.mjs";
import { encodeCanonicalOfflineReleaseManifest } from "../../scripts/lib/offline-release-attestation.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const sha = (char) => char.repeat(40);
const id = (char) => char.repeat(64);
const base = {
  version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
  repository: "https://github.com/bielxdh3/Virki.git",
  source_sha: sha("1"), source_archive_sha256: id("1"), source_archive_size_bytes: 1,
  platform: "linux/amd64", host_identity_sha256: id("9"), predecessor_sha: sha("2"),
  runtime_image: { archive_sha256: id("2"), archive_size_bytes: 1, image_id: "sha256:" + id("3") },
  migrator_image: { archive_sha256: id("4"), archive_size_bytes: 1, image_id: "sha256:" + id("5") },
  evidence: {
    ci_report_sha256: id("6"), scanner_report_sha256: id("7"), scanner_rules_commit: sha("8"),
    finding_review_sha256: id("8"), runtime_smoke_sha256: id("a"),
    migrator_smoke_sha256: id("b"), backup_restore_sha256: id("c"),
  },
  issued_at: 1800000000, expires_at: 1800000300,
  nonce: "abcdef0123456789abcdef0123456789", sequence: 1,
};
const REPORTS = ["ci-report.json", "scanner-report.json", "finding-review.json", "runtime-smoke.json", "migrator-smoke.json", "backup-restore.json"];
const TARS = ["source.tar", "runtime.tar", "migrator.tar"];
const DIR_FILES = ["manifest.json", "signatures.json", ...TARS, ...REPORTS];
// The native envelope reader relies on POSIX open flags, inode/uid ownership,
// and permission bits. Windows must not turn platform refusal into a test pass.
const linuxCandidateOnly = { skip: process.platform !== "linux" };

function fixture(t) {
  const candidateDirectory = mkdtempSync(path.join(os.tmpdir(), "virki-entry-native-"));
  chmodSync(candidateDirectory, 0o700);
  t.after(() => rmSync(candidateDirectory, { recursive: true, force: true }));
  const tarBytes = [
    Buffer.alloc(1024, 0x31), Buffer.alloc(1024, 0x32), Buffer.alloc(1024, 0x33),
  ];
  const reportBytes = REPORTS.map((_, index) => Buffer.from(JSON.stringify({ synthetic: true, index })));
  const manifest = structuredClone(base);
  manifest.source_archive_sha256 = hash(tarBytes[0]);
  manifest.source_archive_size_bytes = tarBytes[0].length;
  manifest.runtime_image.archive_sha256 = hash(tarBytes[1]);
  manifest.runtime_image.archive_size_bytes = tarBytes[1].length;
  manifest.migrator_image.archive_sha256 = hash(tarBytes[2]);
  manifest.migrator_image.archive_size_bytes = tarBytes[2].length;
  [
    "ci_report_sha256", "scanner_report_sha256", "finding_review_sha256",
    "runtime_smoke_sha256", "migrator_smoke_sha256", "backup_restore_sha256",
  ].forEach((key, index) => { manifest.evidence[key] = hash(reportBytes[index]); });
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(manifest);
  writeFileSync(path.join(candidateDirectory, "manifest.json"), manifestBytes, { mode: 0o600 });
  writeFileSync(path.join(candidateDirectory, "signatures.json"),
    JSON.stringify({ builder: "A".repeat(86) + "==", owner: "B".repeat(86) + "==" }), { mode: 0o600 });
  for (const [index, name] of TARS.entries()) {
    writeFileSync(path.join(candidateDirectory, name), tarBytes[index], { mode: 0o600 });
  }
  for (const [index, name] of REPORTS.entries()) {
    writeFileSync(path.join(candidateDirectory, name), reportBytes[index], { mode: 0o600 });
  }
  return { candidateDirectory, manifest, manifestBytes, tarBytes, reportBytes };
}

test("reads a candidate envelope as UNTRUSTED bytes with independent file hashes, never authorizes a release", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  const value = await inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory });
  assert.equal(value.status, "UNTRUSTED_ENVELOPE_ONLY");
  assert.equal(value.manifestBytes.equals(f.manifestBytes), true);
  assert.equal(value.expected.sourceSha, f.manifest.source_sha);
  assert.equal(value.expected.sourceArchiveSha256, f.manifest.source_archive_sha256);
  assert.equal(value.expected.runtimeImage.archiveSha256, f.manifest.runtime_image.archive_sha256);
  assert.equal(value.expected.ciReportSha256, f.manifest.evidence.ci_report_sha256);
  assert.equal(value.expected.lastSequence, 0);
  assert.equal(value.signatures.builder.length, 88);
  assert.equal(Object.hasOwn(value, "trustedKeys"), false);
  assert.equal(Object.hasOwn(value, "deploymentAuthorized"), false);
});

test("rejects bundle-supplied policy and keys, even when JSON looks credible", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  for (const file of ["trust-policy.json", "ledger.json", "host-identity.sha256", "owner-private-key.pem"]) {
    writeFileSync(path.join(f.candidateDirectory, file), "{}");
    await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory }));
    rmSync(path.join(f.candidateDirectory, file));
  }
});

test("strict shape validation rejects oversized, noncanonical and duplicate signature envelopes", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  const target = path.join(f.candidateDirectory, "signatures.json");
  for (const payload of [
    "{}", "[]", "null",
    '{"builder":"x","owner":"y","owner":"z"}',
    '{"owner":"x","builder":"y"}',
    '{"builder":"x","owner":"y","policy":{"builder":{}}}',
    " ".repeat(65537),
    Buffer.from([0xc3, 0x28]),
  ]) {
    writeFileSync(target, payload);
    await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory }));
  }
});

test("rejects malformed, reserialized, duplicate-key and archive-hash-mismatched manifests", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  const file = path.join(f.candidateDirectory, "manifest.json");
  const original = readFileSync(file);
  for (const input of [
    "{}",
    "not-json",
    original.toString("utf8").replace('"version":1', '"version":1,"version":1'),
    JSON.stringify(JSON.parse(original.toString("utf8"))),
    original.toString("utf8").replace(f.manifest.source_archive_sha256, id("f")),
    Buffer.alloc(8193, 0x20),
  ]) {
    writeFileSync(file, input);
    await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory }));
  }
  writeFileSync(file, original);
});

test("rejects caller-supplied keys, host, ledger or untrusted expected-identity objects", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  for (const key of ["trustedKeys", "expected", "ledger", "measuredHostIdentitySha256", "hostState"]) {
    await assert.rejects(inspectUntrustedOfflineCandidate({
      candidateDirectory: f.candidateDirectory,
      [key]: { injected: true },
    }));
  }
});

test("rejects missing, changed or swapped raw evidence and signed archives", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  for (const file of ["ci-report.json", "source.tar", "runtime.tar", "migrator.tar"]) {
    const target = path.join(f.candidateDirectory, file);
    const original = readFileSync(target);
    writeFileSync(target, "attacker");
    await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory }));
    writeFileSync(target, original);
  }
  rmSync(path.join(f.candidateDirectory, "scanner-report.json"));
  await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory }));
});

test("rejects mode, symlink and hardlink attacks before reading untrusted bytes", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  const badDirectory = path.join(os.tmpdir(), "virki-bad-alias-" + path.basename(f.candidateDirectory));
  symlinkSync(f.candidateDirectory, badDirectory, "dir");
  t.after(() => rmSync(badDirectory, { force: true }));
  await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: badDirectory }));
  const tar = path.join(f.candidateDirectory, "runtime.tar");
  const copy = path.join(f.candidateDirectory, "runtime-copy");
  linkSync(tar, copy);
  await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory }));
  rmSync(copy);
  chmodSync(tar, 0o644);
  await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: f.candidateDirectory }));
});

test("rejects relative, traversal, missing and root candidate paths", linuxCandidateOnly, async () => {
  for (const candidateDirectory of ["./bundle", ".", "../bundle", "/", null, ""]) {
    await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory }));
  }
});

test("rejects an owner-private candidate beneath an attacker-renameable nonsticky parent", linuxCandidateOnly, async (t) => {
  const f = fixture(t);
  const outer = mkdtempSync(path.join(os.tmpdir(), "virki-entry-ancestor-"));
  t.after(() => rmSync(outer, { recursive: true, force: true }));
  const parent = path.join(outer, "unsafe-parent");
  mkdirSync(parent, { mode: 0o700 });
  const candidate = path.join(parent, "candidate");
  renameSync(f.candidateDirectory, candidate);
  chmodSync(parent, 0o777);
  try {
    await assert.rejects(inspectUntrustedOfflineCandidate({ candidateDirectory: candidate }),
      /ancestor|writable|renameable|protected/iu,
      "a private leaf cannot prevent an attacker from replacing its writable parent");
  } finally { chmodSync(parent, 0o700); }
});

test("native trusted entry always rejects developer WSL kernel before opening bundle", async (t) => {
  const f = fixture(t);
  if (process.platform !== "linux" || /microsoft|wsl/iu.test(os.release())) {
    await assert.rejects(verifyTrustedHostOfflineCandidate({
      candidateDirectory: f.candidateDirectory,
      expected: { trustedKeys: { builder: "UNTRUSTED", owner: "UNTRUSTED" } },
    }), /native Linux/iu);
    assert.deepEqual(readdirSync(f.candidateDirectory).sort(), DIR_FILES.slice().sort());
  } else {
    t.skip("this adversarial platform rejection is for Windows/WSL");
  }
});

test("native trust-root and non-classic OCI Docker save are not silently accepted", (t) => {
  if (process.platform !== "linux" || /microsoft|wsl/iu.test(os.release())) {
    t.skip("native-Linux-only installed trust and Docker archive verification cannot run on WSL kernel");
  }
});

test("direct installed entrypoint CLI never returns success or starts Docker", (t) => {
  const f = fixture(t);
  const result = spawnSync(process.execPath,
    [fileURLToPath(new URL("./trusted-host-entry.mjs", import.meta.url)), f.candidateDirectory],
    { encoding: "utf8", timeout: 5000 });
  assert.equal(result.error, undefined, String(result.error));
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /preflight refused|deploy remains BLOCKED/iu);
  assert.doesNotMatch(result.stderr, /MODULE_NOT_FOUND|Cannot find module|ERR_MODULE_NOT_FOUND/iu);
  assert.doesNotMatch(result.stdout, /authorized|deployed|success/iu);
});
