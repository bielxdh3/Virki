import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildUnsignedOfflineRelease } from "./offline-release-build.mjs";
import { encodeCanonicalOfflineReleaseManifest } from "./lib/offline-release-attestation.mjs";

const REMOTE = "https://github.com/bielxdh3/Virki.git";
const OCI = "https://github.com/bielxdh3/Virki";
const digest = (data) => createHash("sha256").update(data).digest("hex");
const EMPTY = digest("");
const STAGES = ["tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check"];

function octal(buffer, offset, width, value) {
  buffer.write(value.toString(8).padStart(width - 1, "0"), offset, "ascii");
  buffer[offset + width - 1] = 0;
}

function tar(files) {
  const chunks = [];
  for (const file of files) {
    const bytes = Buffer.from(file.bytes);
    const h = Buffer.alloc(512);
    h.write(file.name, 0, "ascii");
    octal(h, 100, 8, 0o644);
    octal(h, 108, 8, 0);
    octal(h, 116, 8, 0);
    octal(h, 124, 12, bytes.length);
    octal(h, 136, 12, 0);
    h.fill(32, 148, 156);
    h.write("0", 156, "ascii");
    h.write("ustar", 257, "ascii");
    h.write("00", 263, "ascii");
    octal(h, 148, 8, h.reduce((sum, n) => sum + n, 0));
    chunks.push(h, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function dockerArchive(revision, role) {
  const layer = tar([{ name: "app", bytes: Buffer.from(role) }]);
  const layerDigest = digest(layer);
  const layerName = `blobs/sha256/${layerDigest}`;
  const config = Buffer.from(JSON.stringify({
    os: "linux", architecture: "amd64", config: {
      User: "node:node", Labels: {
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": OCI,
      },
    },
    rootfs: { type: "layers", diff_ids: [`sha256:${digest(layer)}`] },
  }));
  const configDigest = digest(config);
  const imageId = `sha256:${configDigest}`;
  const ociManifest = Buffer.from(JSON.stringify({
    schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: imageId, size: config.length },
    layers: [{ mediaType: "application/vnd.oci.image.layer.v1.tar",
      digest: `sha256:${layerDigest}`, size: layer.length }],
  }));
  const ociManifestDigest = digest(ociManifest);
  const index = Buffer.from(JSON.stringify({
    schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [{ mediaType: "application/vnd.oci.image.manifest.v1+json",
      digest: `sha256:${ociManifestDigest}`, size: ociManifest.length }],
  }));
  const classicManifest = Buffer.from(JSON.stringify([{
    Config: `blobs/sha256/${configDigest}`, RepoTags: null, Layers: [layerName],
    LayerSources: { [`sha256:${layerDigest}`]: { mediaType: "application/vnd.oci.image.layer.v1.tar",
      size: layer.length, digest: `sha256:${layerDigest}` } },
  }]));
  return { imageId, bytes: tar([
    { name: `blobs/sha256/${configDigest}`, bytes: config },
    { name: layerName, bytes: layer },
    { name: `blobs/sha256/${ociManifestDigest}`, bytes: ociManifest },
    { name: "manifest.json", bytes: classicManifest },
    { name: "index.json", bytes: index },
    { name: "oci-layout", bytes: Buffer.from(JSON.stringify({ imageLayoutVersion: "1.0.0" })) },
  ]) };
}

function ciManifest(revision) {
  const start = Date.parse("2026-10-21T14:00:00.000Z");
  return {
    runId: "e5f8bc3d5c", sourceBranch: "main", sourceHead: revision,
    startedUtc: new Date(start).toISOString(), finishedUtc: new Date(start + 300000).toISOString(),
    nodeVersion: "v22.23.3", npmVersion: "10.9.9", stagedPatchSha256: EMPTY,
    workingTreePatchSha256: EMPTY, untrackedFiles: [], exitCode: 0, failedStages: [],
    unitTestsFailureCount: 0, unitTestsFailures: [],
    integrationTestsFailureCount: 0, integrationTestsFailures: [],
    productionOperationsFailureCount: 0, productionOperationsFailures: [],
    dockerMutationJournal: "docker-mutations.jsonl", dockerMutationUncertain: false,
    dockerCleanupVerified: true, bootstrapVirginTestsLog: "bootstrap-virgin-tests.tap.log",
    bootstrapVirginTestsExitCode: 0,
    stages: STAGES.map((name, i) => ({
      name, startedUtc: new Date(start + i * 10000 + 1000).toISOString(),
      finishedUtc: new Date(start + i * 10000 + 2000).toISOString(),
      durationMs: 1000, exitCode: 0,
    })),
  };
}

function git(cwd, ...args) { return execFileSync("git", args, { cwd, encoding: "utf8" }).trim(); }

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-offline-build-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repositoryRoot = path.join(root, "repo");
  const stagingParent = path.join(root, "stages");
  mkdirSync(repositoryRoot);
  mkdirSync(stagingParent);
  git(repositoryRoot, "init", "-b", "main");
  // Keep fixture blobs and Git archive bytes identical regardless of the host's
  // global core.autocrlf setting; production integrity verification stays strict.
  git(repositoryRoot, "config", "core.autocrlf", "false");
  git(repositoryRoot, "config", "user.email", "ci@example.test");
  git(repositoryRoot, "config", "user.name", "CI fixture");
  writeFileSync(path.join(repositoryRoot, "README.md"), "test exact source bytes\n");
  git(repositoryRoot, "add", "README.md");
  git(repositoryRoot, "commit", "-m", "fixture");
  const revision = git(repositoryRoot, "rev-parse", "HEAD");
  git(repositoryRoot, "remote", "add", "origin", REMOTE);
  git(repositoryRoot, "update-ref", "refs/remotes/origin/main", revision);
  const imageFiles = { runtime: dockerArchive(revision, "runtime"), migrator: dockerArchive(revision, "migrator") };
  const images = { runtime: imageFiles.runtime.imageId, migrator: imageFiles.migrator.imageId };
  const ciManifestPath = path.join(root, "ci.json");
  writeFileSync(ciManifestPath, JSON.stringify(ciManifest(revision)));
  const writeReport = (filename, data) => {
    const p = path.join(root, filename);
    writeFileSync(p, typeof data === "string" ? data : JSON.stringify(data));
    return p;
  };
  const scannerReportPath = writeReport("scanner.json", {
    version: "1.140.0", results: [], errors: [], paths: { scanned: ["README.md"], skipped: [] },
  });
  const findingReviewPath = writeReport("review.json", {
    version: 1, sourceSha: revision, scannerSha256: digest(readFileSync(scannerReportPath)),
    decision: "EXPLICITLY_REVIEWED", dispositions: [],
  });
  const predecessor = "b".repeat(40);
  const reports = {};
  for (const [prefix, kind] of [["runtimeSmoke", "runtime-smoke"],
    ["migratorSmoke", "migrator-smoke"], ["backupRestore", "backup-restore"]]) {
    const log = `raw, privately retained ${kind} execution trace fixture\n`;
    reports[`${prefix}LogPath`] = writeReport(`${kind}.log`, log);
    reports[`${prefix}Path`] = writeReport(`${kind}.json`, {
      version: 1, kind, sourceSha: revision, status: "PASS", exitCode: 0,
      rawLogSha256: digest(log),
      ...(kind === "backup-restore" ? { predecessorSha: predecessor } :
        { imageId: images[kind.startsWith("runtime") ? "runtime" : "migrator"] }),
    });
  }
  const evidencePaths = { scannerReportPath, findingReviewPath, ...reports };
  const calls = [];
  const runner = async (program, args, opts = {}) => {
    calls.push({ program, args: [...args] });
    if (program === "docker" && args[0] === "image" && args[1] === "inspect") {
      const role = Object.keys(images).find((key) => images[key] === args[2]);
      assert.ok(role);
      return JSON.stringify([{ Id: images[role], Size: 20000, Os: "linux", Architecture: "amd64",
        Config: { User: "node:node", Labels: {
          "org.opencontainers.image.revision": revision,
          "org.opencontainers.image.source": OCI,
        } },
      }]);
    }
    if (program === "docker" && args[0] === "save") {
      const role = Object.keys(images).find((key) => images[key] === args[3]);
      assert.ok(role);
      writeFileSync(args[2], imageFiles[role].bytes);
      return "";
    }
    if (program === "tar" && args[0] === "-tf") {
      const target = args[1].endsWith("runtime.tar") ? imageFiles.runtime : imageFiles.migrator;
      return execFileSync("tar", ["-tf", args[1]], { encoding: "utf8" }) || target.imageId;
    }
    return execFileSync(program, args, { cwd: opts.cwd, env: opts.env, input: opts.input,
      encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  };
  const releaseContext = {
    hostIdentitySha256: "2".repeat(64), predecessorSha: predecessor, scannerRulesCommit: "c".repeat(40),
    issuedAt: 1_800_000_000 - 100, expiresAt: 1_800_000_000 + 1000,
    sequence: 10,
  };
  return { root, revision, repositoryRoot, stagingParent, ciManifestPath, evidencePaths,
    images, runner, calls, releaseContext, writeReport,
    options: { repositoryRoot, stagingParent, revision, ciManifestPath, evidencePaths, images,
      releaseContext, runner, nowSeconds: 1_800_000_000 } };
}

test("builds a strict unsigned v1 manifest from actual source, Docker TARs and supplied raw evidence", async (t) => {
  const f = fixture(t);
  const result = await buildUnsignedOfflineRelease(f.options);
  assert.equal(result.assurance, "UNSIGNED_LOCAL_ONLY_CODEQL_NOT_RUN");
  assert.equal(result.ciEvidence.stageCount, 19);
  assert.deepEqual(readdirSync(result.directory).sort(), [
    "backup-restore.json", "ci-report.json", "finding-review.json", "manifest.json", "migrator-smoke.json",
    "migrator.tar", "runtime-smoke.json", "runtime.tar", "scanner-report.json", "source.tar",
  ]);
  assert.equal(f.calls.filter((call) => call.program === "docker" && call.args[0] === "save").length, 2);
  const raw = readFileSync(result.manifestPath);
  const manifest = JSON.parse(raw);
  assert.deepEqual(raw, encodeCanonicalOfflineReleaseManifest(manifest));
  assert.equal(result.manifestSha256, digest(raw));
  assert.equal(manifest.source_sha, f.revision);
  assert.match(manifest.nonce, /^[a-f0-9]{32}$/u);
  assert.equal(manifest.source_archive_sha256, digest(readFileSync(path.join(result.directory, "source.tar"))));
  assert.equal(manifest.runtime_image.archive_sha256, digest(readFileSync(path.join(result.directory, "runtime.tar"))));
  assert.equal(manifest.migrator_image.archive_size_bytes, readFileSync(path.join(result.directory, "migrator.tar")).length);
  assert.equal(manifest.evidence.scanner_report_sha256, digest(readFileSync(f.evidencePaths.scannerReportPath)));
  assert.equal(manifest.evidence.ci_report_sha256, digest(readFileSync(f.ciManifestPath)));
  assert.equal(Object.hasOwn(result, "signatures"), false);
});

test("unsigned manual release refuses 19-stage CI report if virgin bootstrap and owned Docker cleanup are omitted", async (t) => {
  const f = fixture(t);
  const incomplete = ciManifest(f.revision);
  for (const field of ["dockerMutationJournal", "dockerMutationUncertain", "dockerCleanupVerified", "bootstrapVirginTestsLog", "bootstrapVirginTestsExitCode"]) {
    delete incomplete[field];
  }
  writeFileSync(f.ciManifestPath, JSON.stringify(incomplete));
  await assert.rejects(buildUnsignedOfflineRelease(f.options), /virgin|bootstrap|Docker|offline/u);
  assert.deepEqual(readdirSync(f.stagingParent), []);
  assert.equal(f.calls.some((call) => call.program === "docker"), false);
});

test("rejects dirty main, wrong SHA, branch and origin/main drift without generating a release", async (t) => {
  const f = fixture(t);
  writeFileSync(path.join(f.repositoryRoot, "README.md"), "dirty");
  await assert.rejects(buildUnsignedOfflineRelease(f.options));
  git(f.repositoryRoot, "checkout", "--", "README.md");
  await assert.rejects(buildUnsignedOfflineRelease({ ...f.options, revision: "a".repeat(40) }));
  git(f.repositoryRoot, "switch", "-c", "feature");
  await assert.rejects(buildUnsignedOfflineRelease(f.options));
  git(f.repositoryRoot, "switch", "main");
  writeFileSync(path.join(f.repositoryRoot, "README.md"), "new committed revision\n");
  git(f.repositoryRoot, "add", "README.md");
  git(f.repositoryRoot, "commit", "-m", "advance main");
  git(f.repositoryRoot, "update-ref", "refs/remotes/origin/main", git(f.repositoryRoot, "rev-parse", "HEAD"));
  await assert.rejects(buildUnsignedOfflineRelease(f.options));
  assert.deepEqual(readdirSync(f.stagingParent), []);
});

test("refuses absent, aliased, forged, failed and unreviewed external evidence before archiving", async (t) => {
  const f = fixture(t);
  const scanner = JSON.parse(readFileSync(f.evidencePaths.scannerReportPath, "utf8"));
  const review = JSON.parse(readFileSync(f.evidencePaths.findingReviewPath, "utf8"));
  const runtime = JSON.parse(readFileSync(f.evidencePaths.runtimeSmokePath, "utf8"));
  const variants = [
    { evidencePaths: { ...f.evidencePaths, scannerReportPath: "/missing/report.json" } },
    { evidencePaths: { ...f.evidencePaths, findingReviewPath: f.evidencePaths.scannerReportPath } },
    { scanner: { ...scanner, errors: [{ message: "scanner crashed" }] } },
    { scanner: { ...scanner, paths: { scanned: [], skipped: ["README.md"] } } },
    { scanner: { ...scanner, results: [{ check_id: "unsafe", path: "README.md", start: { line: 1 }, extra: { fingerprint: "bad" } }] } },
    { review: { ...review, decision: "AUTOMATIC_PASS" } },
    { runtime: { ...runtime, status: "FAIL" } },
    { runtime: { ...runtime, sourceSha: "a".repeat(40) } },
    { runtime: { ...runtime, rawLogSha256: "0".repeat(64) } },
    { releaseContext: { ...f.releaseContext, scannerRulesCommit: "0" } },
    { releaseContext: { ...f.releaseContext, expiresAt: 1_800_000_000 } },
  ];
  for (const variant of variants) {
    if (variant.scanner) writeFileSync(f.evidencePaths.scannerReportPath, JSON.stringify(variant.scanner));
    else writeFileSync(f.evidencePaths.scannerReportPath, JSON.stringify(scanner));
    if (variant.review) writeFileSync(f.evidencePaths.findingReviewPath, JSON.stringify(variant.review));
    else writeFileSync(f.evidencePaths.findingReviewPath, JSON.stringify(review));
    if (variant.runtime) writeFileSync(f.evidencePaths.runtimeSmokePath, JSON.stringify(variant.runtime));
    else writeFileSync(f.evidencePaths.runtimeSmokePath, JSON.stringify(runtime));
    await assert.rejects(buildUnsignedOfflineRelease({ ...f.options, ...variant, scanner: undefined,
      review: undefined, runtime: undefined }), undefined, JSON.stringify(Object.keys(variant)));
  }
  assert.deepEqual(readdirSync(f.stagingParent), []);
});

test("rejects failed CI and invalid source image identities without signatures or production work", async (t) => {
  const f = fixture(t);
  const ci = ciManifest(f.revision);
  ci.stages[12].exitCode = 1;
  writeFileSync(f.ciManifestPath, JSON.stringify(ci));
  await assert.rejects(buildUnsignedOfflineRelease(f.options));
  writeFileSync(f.ciManifestPath, JSON.stringify(ciManifest(f.revision)));
  await assert.rejects(buildUnsignedOfflineRelease({ ...f.options, images: {
    ...f.images, migrator: "sha256:" + "0".repeat(64),
  } }));
  assert.ok(!f.calls.some((call) => ["ssh", "scp", "gh", "curl"].includes(call.program)));
});
