import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, linkSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encodeCanonicalOfflineReleaseManifest } from "./lib/offline-release-attestation.mjs";
import {
  prepareOfflineHostVerificationContext,
  verifyOfflineHostRelease,
} from "./lib/offline-host-verifier.mjs";

const revision = "a".repeat(40);
const predecessor = "b".repeat(40);
const now = 1_800_000_000;
const repo = "https://github.com/bielxdh3/Virki.git";
const ociSource = "https://github.com/bielxdh3/Virki";
const source = Buffer.from("source tar fixture");
const runtime = Buffer.from("runtime image tar fixture");
const migrator = Buffer.from("migrator image tar fixture");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const digest = (character) => character.repeat(64);
const nativeKernel = process.platform === "linux" && process.arch === "x64" &&
  !/microsoft|wsl/iu.test(os.release());
const moduleUrl = new URL("./lib/offline-host-verifier.mjs", import.meta.url).href;

function keyEntry(publicKey) {
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    pinSha256: hash(publicKey.export({ type: "spki", format: "der" })),
  };
}

function fixture(t) {
  const artifactRoot = mkdtempSync(path.join(os.tmpdir(), "virki-offline-host-verifier-"));
  chmodSync(artifactRoot, 0o700);
  t.after(() => rmSync(artifactRoot, { recursive: true, force: true }));
  const archives = {
    sourceArchivePath: path.join(artifactRoot, "source.tar"),
    runtimeArchivePath: path.join(artifactRoot, "runtime.tar"),
    migratorArchivePath: path.join(artifactRoot, "migrator.tar"),
  };
  for (const [file, bytes] of [
    [archives.sourceArchivePath, source],
    [archives.runtimeArchivePath, runtime],
    [archives.migratorArchivePath, migrator],
  ]) writeFileSync(file, bytes, { mode: 0o600, flag: "wx" });
  const images = {
    runtime: { role: "runtime", imageId: `sha256:${digest("c")}`, sizeBytes: 1024, os: "linux", architecture: "amd64",
      labels: { "org.opencontainers.image.revision": revision, "org.opencontainers.image.source": ociSource } },
    migrator: { role: "migrator", imageId: `sha256:${digest("d")}`, sizeBytes: 2048, os: "linux", architecture: "amd64",
      labels: { "org.opencontainers.image.revision": revision, "org.opencontainers.image.source": ociSource } },
  };
  const hostState = {
    sourceSha: revision,
    hostIdentitySha256: digest("e"),
    predecessorSha: predecessor,
    lastSequence: 3,
    evidence: {
      ciReportSha256: digest("1"),
      scannerReportSha256: digest("2"),
      scannerRulesCommit: "f".repeat(40),
      findingReviewSha256: digest("3"),
      runtimeSmokeSha256: digest("4"),
      migratorSmokeSha256: digest("5"),
      backupRestoreSha256: digest("6"),
    },
  };
  const manifest = {
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: repo, source_sha: revision,
    source_archive_sha256: hash(source), source_archive_size_bytes: source.length,
    platform: "linux/amd64", host_identity_sha256: hostState.hostIdentitySha256,
    predecessor_sha: predecessor,
    runtime_image: { archive_sha256: hash(runtime), archive_size_bytes: runtime.length, image_id: images.runtime.imageId },
    migrator_image: { archive_sha256: hash(migrator), archive_size_bytes: migrator.length, image_id: images.migrator.imageId },
    evidence: {
      ci_report_sha256: hostState.evidence.ciReportSha256,
      scanner_report_sha256: hostState.evidence.scannerReportSha256,
      scanner_rules_commit: hostState.evidence.scannerRulesCommit,
      finding_review_sha256: hostState.evidence.findingReviewSha256,
      runtime_smoke_sha256: hostState.evidence.runtimeSmokeSha256,
      migrator_smoke_sha256: hostState.evidence.migratorSmokeSha256,
      backup_restore_sha256: hostState.evidence.backupRestoreSha256,
    },
    issued_at: now - 60, expires_at: now + 600,
    nonce: "7".repeat(32), sequence: 4,
  };
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const manifestBytes = encodeCanonicalOfflineReleaseManifest(manifest);
  const signatures = {
    builder: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0"), manifestBytes]),
      builder.privateKey).toString("base64"),
    owner: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0"), Buffer.from(hash(manifestBytes), "hex")]),
      owner.privateKey).toString("base64"),
  };
  return {
    manifestBytes,
    signatures,
    trustAnchor: { builder: keyEntry(builder.publicKey), owner: keyEntry(owner.publicKey) },
    hostState,
    artifacts: { artifactRoot, ...archives, images },
    nowSeconds: now,
  };
}

// Only the disposable child process may simulate an ordinary native kernel;
// production code receives no override flag, injectable platform, or bypass.
function runIsolatedKernelSimulation(value, simulateNative = true) {
  const childCode = `
    import os from "node:os";
    const input = JSON.parse(process.env.VIRKI_TEST_HOST_INPUT);
    input.manifestBytes = Buffer.from(input.manifestBytes, "base64");
    if (${simulateNative}) os.release = () => "6.8.0-generic";
    const { verifyOfflineHostRelease } = await import(${JSON.stringify(moduleUrl)});
    try {
      const result = await verifyOfflineHostRelease(input);
      process.stdout.write(JSON.stringify(result));
    } catch (error) {
      process.stderr.write(error.message);
      process.exitCode = 2;
    }
  `;
  const request = { ...value, manifestBytes: value.manifestBytes.toString("base64") };
  return spawnSync(process.execPath, ["--input-type=module", "-e", childCode], {
    encoding: "utf8",
    timeout: 10_000,
    env: { ...process.env, VIRKI_TEST_HOST_INPUT: JSON.stringify(request) },
  });
}

test("pure trust-context validation snapshots externally supplied keys, host identity and evidence", (t) => {
  const sample = fixture(t);
  const prepared = prepareOfflineHostVerificationContext({
    trustAnchor: sample.trustAnchor, hostState: sample.hostState,
  });
  sample.hostState.evidence.ciReportSha256 = digest("0");
  sample.trustAnchor.builder.pinSha256 = digest("0");
  assert.equal(prepared.hostState.evidence.ciReportSha256, digest("1"));
  assert.notEqual(prepared.trustedKeys.builder.pinSha256, digest("0"));
  assert.equal(Object.isFrozen(prepared), true);
  assert.equal(Object.isFrozen(prepared.hostState.evidence), true);
});

test("pure context refuses missing or injected trust material and malformed protected state", (t) => {
  const sample = fixture(t);
  for (const [trustAnchor, hostState] of [
    [null, sample.hostState],
    [{ ...sample.trustAnchor, fromBundle: true }, sample.hostState],
    [{ ...sample.trustAnchor, owner: sample.trustAnchor.builder }, sample.hostState],
    [{ ...sample.trustAnchor, owner: { ...sample.trustAnchor.owner, privateKeyPem: "secret" } }, sample.hostState],
    [sample.trustAnchor, { ...sample.hostState, predecessorSha: "INVALID" }],
    [sample.trustAnchor, { ...sample.hostState, lastSequence: -1 }],
    [sample.trustAnchor, { ...sample.hostState, evidence: { ...sample.hostState.evidence, scannerRulesCommit: "" } }],
    [sample.trustAnchor, { ...sample.hostState, evidence: { ...sample.hostState.evidence, unknown: "bad" } }],
  ]) assert.throws(() => prepareOfflineHostVerificationContext({ trustAnchor, hostState }));
});

test("rejects WSL/Microsoft kernel before touching even missing or unsafe artifact paths", async (t) => {
  if (nativeKernel) return t.skip("WSL rejection tested only under WSL kernel");
  await assert.rejects(
    verifyOfflineHostRelease({ artifacts: { artifactRoot: "/definitely-not-present" } }),
    /native Linux|WSL|Microsoft/iu,
  );
});

test("isolated child simulation binds both Ed25519 signatures to measured tar bytes and protected host state", (t) => {
  const sample = fixture(t);
  const child = runIsolatedKernelSimulation(sample);
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.sourceSha, revision);
  assert.equal(result.manifestSha256, hash(sample.manifestBytes));
  assert.equal(result.sequence, 4);
  assert.equal(result.artifacts.source_archive_sha256, hash(source));
  assert.equal(result.artifacts.runtime_image.archive_sha256, hash(runtime));
  assert.equal(result.artifacts.migrator_image.archive_sha256, hash(migrator));
  assert.equal(result.authorizesDeployment, undefined);
});

test("isolated child rejects altered tar and swapped tar paths after signing", async (t) => {
  const sample = fixture(t);
  writeFileSync(sample.artifacts.runtimeArchivePath, "tampered payload");
  assert.match(runIsolatedKernelSimulation(sample).stderr, /image|archive|identity/iu);
  writeFileSync(sample.artifacts.runtimeArchivePath, runtime);
  assert.match(runIsolatedKernelSimulation({
    ...sample,
    artifacts: { ...sample.artifacts, runtimeArchivePath: sample.artifacts.migratorArchivePath,
      migratorArchivePath: sample.artifacts.runtimeArchivePath },
  }).stderr, /image|archive/iu);
});

test("isolated child rejects forged signatures, wrong host/predecessor, replay, and wrong reports", (t) => {
  const sample = fixture(t);
  for (const altered of [
    { signatures: { ...sample.signatures, owner: sample.signatures.builder } },
    { trustAnchor: { ...sample.trustAnchor, owner: { ...sample.trustAnchor.owner, pinSha256: digest("0") } } },
    { hostState: { ...sample.hostState, hostIdentitySha256: digest("0") } },
    { hostState: { ...sample.hostState, predecessorSha: "c".repeat(40) } },
    { hostState: { ...sample.hostState, lastSequence: 4 } },
    { hostState: { ...sample.hostState, evidence: { ...sample.hostState.evidence, scannerReportSha256: digest("0") } } },
    { artifacts: { ...sample.artifacts, images: { ...sample.artifacts.images,
      runtime: { ...sample.artifacts.images.runtime, imageId: `sha256:${digest("0")}` } } } },
  ]) {
    const child = runIsolatedKernelSimulation({ ...sample, ...altered });
    assert.equal(child.status, 2, child.stderr);
  }
});

test("isolated child rejects non-private root, symlinks, and hardlinked archives", (t) => {
  const sample = fixture(t);
  chmodSync(sample.artifacts.artifactRoot, 0o750);
  assert.match(runIsolatedKernelSimulation(sample).stderr, /private|directory/iu);
  chmodSync(sample.artifacts.artifactRoot, 0o700);
  const alias = path.join(sample.artifacts.artifactRoot, "alias.tar");
  symlinkSync(sample.artifacts.runtimeArchivePath, alias);
  assert.equal(runIsolatedKernelSimulation({
    ...sample, artifacts: { ...sample.artifacts, runtimeArchivePath: alias },
  }).status, 2);
  rmSync(alias);
  linkSync(sample.artifacts.runtimeArchivePath, alias);
  assert.equal(runIsolatedKernelSimulation(sample).status, 2);
});

test("isolated child still refuses real WSL kernel without production override", (t) => {
  if (nativeKernel) return t.skip("Docker Desktop WSL-only behavior");
  const sample = fixture(t);
  const child = runIsolatedKernelSimulation(sample, false);
  assert.equal(child.status, 2);
  assert.match(child.stderr, /native Linux|WSL|Microsoft/iu);
});

test("genuine native Linux end-to-end verification", async (t) => {
  if (!nativeKernel) return t.skip("requires genuine native Linux/amd64 kernel, not Docker Desktop WSL");
  const sample = fixture(t);
  const result = await verifyOfflineHostRelease(sample);
  assert.equal(result.manifestSha256, hash(sample.manifestBytes));
});
