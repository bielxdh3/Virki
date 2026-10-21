import { createHash, randomBytes } from "node:crypto";
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { prepareOfflineReleaseBundle } from "./lib/offline-release-bundle.mjs";
import { inventoryOfflineArtifacts } from "./lib/offline-artifact-inventory.mjs";
import { verifyOfflineDockerSaveTar } from "./lib/offline-docker-tar-verifier.mjs";
import { encodeCanonicalOfflineReleaseManifest } from "./lib/offline-release-attestation.mjs";

// Strictly local, unsigned build-candidate orchestration. All evidence comes
// from existing caller-supplied files; no stage is run or fabricated here.
// A successful result is NOT release authorization, independent hosted CI,
// CodeQL, a trusted scanner run, or proof that a database was restored.
const SHA = /^[a-f0-9]{40}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const REPORTS = Object.freeze([
  ["scannerReportPath", "scanner-report.json"],
  ["findingReviewPath", "finding-review.json"],
  ["runtimeSmokePath", "runtime-smoke.json"],
  ["migratorSmokePath", "migrator-smoke.json"],
  ["backupRestorePath", "backup-restore.json"],
]);

function fail(reason) {
  throw new Error(`Unsigned offline release build refused: ${reason}`);
}

function exactFields(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) {
    fail(`${label} schema is invalid`);
  }
}

function safePath(filename, label) {
  if (typeof filename !== "string" || filename.length === 0 || filename.length > 4096 ||
      filename.includes("\0") || !path.isAbsolute(filename) || path.normalize(filename) !== filename) {
    fail(`${label} must be a canonical absolute path`);
  }
  for (let cursor = filename;; cursor = path.dirname(cursor)) {
    const metadata = lstatSync(cursor, { bigint: true });
    if (metadata.isSymbolicLink() || (cursor !== filename && !metadata.isDirectory())) {
      fail(`${label} has an unsafe path alias`);
    }
    if (cursor === path.dirname(cursor)) break;
  }
  return filename;
}

function sameFile(first, second) {
  return ["dev", "ino", "size", "mode", "nlink", "mtimeNs", "ctimeNs"].every((field) => first[field] === second[field]);
}

function readEvidence(filename, label) {
  safePath(filename, label);
  const before = lstatSync(filename, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size < 2n ||
      before.size > BigInt(MAX_REPORT_BYTES)) fail(`${label} must be a bounded single-link regular file`);
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!sameFile(before, fstatSync(fd, { bigint: true }))) fail(`${label} changed before reading`);
    const raw = readFileSync(fd);
    if (!sameFile(before, fstatSync(fd, { bigint: true })) ||
        !sameFile(before, lstatSync(filename, { bigint: true }))) fail(`${label} changed during reading`);
    return { raw, sha256: createHash("sha256").update(raw).digest("hex") };
  } finally { closeSync(fd); }
}

function reportJson(raw, label) {
  let parsed;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { fail(`${label} is not a valid UTF-8 JSON evidence artifact`); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail(`${label} must be a JSON object`);
  return parsed;
}

function validateScanner(scanner) {
  if (typeof scanner.version !== "string" || !/^\d+\.\d+(?:\.\d+)?(?:[-+][a-z0-9.-]+)?$/iu.test(scanner.version) ||
      !Array.isArray(scanner.results) || !Array.isArray(scanner.errors) || scanner.errors.length !== 0 ||
      !scanner.paths || !Array.isArray(scanner.paths.scanned) || scanner.paths.scanned.length === 0 ||
      !Array.isArray(scanner.paths.skipped) || scanner.paths.skipped.length > 0) {
    fail("raw Semgrep OSS results are incomplete, errored, or have unscanned/ignored paths");
  }
  const ids = new Set();
  for (const result of scanner.results) {
    if (typeof result?.check_id !== "string" || !result.check_id ||
        typeof result.path !== "string" || !result.path ||
        !Number.isSafeInteger(result.start?.line) || result.start.line < 1 ||
        typeof result.extra?.fingerprint !== "string" || !result.extra.fingerprint) {
      fail("Semgrep finding lacks stable rule, path, line or fingerprint");
    }
    const identity = createHash("sha256").update(JSON.stringify([
      result.check_id, result.path, result.start.line, result.extra.fingerprint,
    ])).digest("hex");
    if (ids.has(identity)) fail("duplicate scanner finding identity");
    ids.add(identity);
  }
  return ids;
}

function validateReview(review, revision, scannerSha, findings) {
  exactFields(review, ["version", "sourceSha", "scannerSha256", "decision", "dispositions"], "finding review");
  if (review.version !== 1 || review.sourceSha !== revision || review.scannerSha256 !== scannerSha ||
      review.decision !== "EXPLICITLY_REVIEWED" || !Array.isArray(review.dispositions) ||
      review.dispositions.length !== findings.size) fail("finding review does not cover the exact scanner results");
  const reviewed = new Set();
  for (const disposition of review.dispositions) {
    exactFields(disposition, ["findingId", "decision", "reason"], "finding disposition");
    if (!findings.has(disposition.findingId) || reviewed.has(disposition.findingId) ||
        !["ACCEPTED_RESIDUAL_RISK", "REMEDIATED"].includes(disposition.decision) ||
        typeof disposition.reason !== "string" || disposition.reason.trim().length < 16 ||
        disposition.reason.length > 2048) fail("unreviewed or ambiguous scanner finding");
    reviewed.add(disposition.findingId);
  }
}

function validateReceipt(receipt, kind, revision, imageId, predecessor) {
  const fields = ["version", "kind", "sourceSha", "status", "exitCode", "rawLogSha256",
    ...(imageId ? ["imageId"] : ["predecessorSha"])];
  exactFields(receipt, fields, kind);
  if (receipt.version !== 1 || receipt.kind !== kind || receipt.sourceSha !== revision ||
      receipt.status !== "PASS" || receipt.exitCode !== 0 || !HASH.test(receipt.rawLogSha256 ?? "") ||
      (imageId ? receipt.imageId !== imageId : receipt.predecessorSha !== predecessor)) {
    fail(`${kind} result is unsuccessful or mismatched`);
  }
  // A digest claim alone does not prove execution. Matching raw logs are
  // mandatory in this builder and explicitly remain LOCAL evidence only.
}

function requireContext(value, nowSeconds) {
  exactFields(value, ["hostIdentitySha256", "predecessorSha", "issuedAt", "expiresAt", "sequence", "scannerRulesCommit"], "release context");
  if (!HASH.test(value.hostIdentitySha256 ?? "") || !SHA.test(value.predecessorSha ?? "") ||
      !SHA.test(value.scannerRulesCommit ?? "") ||
      !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
      value.issuedAt > nowSeconds || value.expiresAt <= nowSeconds ||
      value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 86400 ||
      !Number.isSafeInteger(value.sequence) || value.sequence < 1) {
    fail("host, predecessor, pinned scanner rules, sequence or validity is invalid");
  }
}

function snapshotReports(reports) {
  exactFields(reports, [...REPORTS.map(([key]) => key), "runtimeSmokeLogPath", "migratorSmokeLogPath", "backupRestoreLogPath"], "evidence paths");
  const entries = {};
  const unique = new Set();
  for (const [key, output] of [...REPORTS,
    ["runtimeSmokeLogPath", "runtime-smoke.log"], ["migratorSmokeLogPath", "migrator-smoke.log"],
    ["backupRestoreLogPath", "backup-restore.log"]]) {
    const filename = safePath(reports[key], key);
    if (unique.has(filename)) fail("evidence reports must be distinct real input files");
    unique.add(filename);
    entries[key] = { ...readEvidence(filename, key), output };
  }
  return entries;
}

function verifyReportBindings(evidence, revision, images, predecessor) {
  const scanner = reportJson(evidence.scannerReportPath.raw, "scanner report");
  const findings = validateScanner(scanner);
  const review = reportJson(evidence.findingReviewPath.raw, "finding review");
  validateReview(review, revision, evidence.scannerReportPath.sha256, findings);
  for (const [prefix, kind, imageId] of [
    ["runtime", "runtime-smoke", images.runtime],
    ["migrator", "migrator-smoke", images.migrator],
    ["backupRestore", "backup-restore", null],
  ]) {
    const receipt = reportJson(evidence[`${prefix === "backupRestore" ? "backupRestore" : prefix + "Smoke"}Path`].raw, kind);
    const logKey = `${prefix === "backupRestore" ? "backupRestore" : prefix + "Smoke"}LogPath`;
    validateReceipt(receipt, kind, revision, imageId, predecessor);
    if (receipt.rawLogSha256 !== evidence[logKey].sha256) fail(`${kind} raw log does not match its receipt`);
  }
}

function persistRawEvidence(bundle, evidence, manifestBytes) {
  // The separately provisioned native host verifier permits exactly six raw
  // JSON reports, three TARs, manifest.json and a future signatures.json.
  // Retain the three raw smoke/restore logs at their supplied external paths;
  // their receipt JSON hashes bind them for independent operator inspection.
  renameSync(path.join(bundle.directory, "ci.json"), path.join(bundle.directory, "ci-report.json"));
  for (const [key] of REPORTS) {
    const item = evidence[key];
    writeFileSync(path.join(bundle.directory, item.output), item.raw, { flag: "wx", mode: 0o600 });
  }
  writeFileSync(path.join(bundle.directory, "manifest.json"), manifestBytes, { flag: "wx", mode: 0o600 });
}

/**
 * Caller runs CI, Semgrep, smoke tests, restore testing and Docker builds in
 * advance and provides their raw files. Runs no Git fetch, Docker build,
 * scanner, SSH, GHCR or production mutation. The output is UNSIGNED.
 * The base bundle enforces clean main == refs/remotes/origin/main == revision.
 */
export async function buildUnsignedOfflineRelease({
  repositoryRoot, revision, stagingParent, ciManifestPath, images,
  evidencePaths, releaseContext, nowSeconds, runner,
} = {}) {
  if (!SHA.test(revision ?? "") || typeof nowSeconds !== "number" ||
      !Number.isSafeInteger(nowSeconds) || nowSeconds < 1) fail("expected revision or trusted time is invalid");
  requireContext(releaseContext, nowSeconds);
  const evidence = snapshotReports(evidencePaths);
  // Check input artifacts before expensive archive creation; verify receipts
  // against the independently requested source SHA and immutable image IDs.
  verifyReportBindings(evidence, revision, images, releaseContext.predecessorSha);
  if (!images || typeof images.runtime !== "string" || typeof images.migrator !== "string" ||
      images.runtime === images.migrator) fail("distinct runtime and migrator images required");
  const bundle = await prepareOfflineReleaseBundle({
    repositoryRoot, revision, stagingParent, ciManifestPath, images,
    ...(runner === undefined ? {} : { runner }),
  });
  const initial = bundle.inventory;
  for (const [role, archivePath] of [
    ["runtime", bundle.runtimeArchivePath], ["migrator", bundle.migratorArchivePath],
  ]) {
    const image = initial[`${role}_image`];
    await verifyOfflineDockerSaveTar({
      archivePath, expectedImageId: image.image_id, expectedRevision: revision,
      expectedArchiveSha256: image.archive_sha256, expectedArchiveSizeBytes: image.archive_size_bytes, role,
    });
  }
  const inventory = await inventoryOfflineArtifacts({
    artifactRoot: bundle.directory,
    sourceArchivePath: bundle.sourceArchivePath,
    runtimeArchivePath: bundle.runtimeArchivePath,
    migratorArchivePath: bundle.migratorArchivePath,
    expectedRevision: revision, images: bundle.imageMetadata,
  });
  if (JSON.stringify(inventory) !== JSON.stringify(initial)) fail("archive files changed after initial verification");
  const manifestBytes = encodeCanonicalOfflineReleaseManifest({
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: inventory.repository, source_sha: revision,
    source_archive_sha256: inventory.source_archive_sha256,
    source_archive_size_bytes: inventory.source_archive_size_bytes,
    platform: inventory.platform, host_identity_sha256: releaseContext.hostIdentitySha256,
    predecessor_sha: releaseContext.predecessorSha,
    runtime_image: inventory.runtime_image, migrator_image: inventory.migrator_image,
    evidence: {
      ci_report_sha256: bundle.ciEvidence.manifestSha256,
      scanner_report_sha256: evidence.scannerReportPath.sha256,
      scanner_rules_commit: releaseContext.scannerRulesCommit,
      finding_review_sha256: evidence.findingReviewPath.sha256,
      runtime_smoke_sha256: evidence.runtimeSmokePath.sha256,
      migrator_smoke_sha256: evidence.migratorSmokePath.sha256,
      backup_restore_sha256: evidence.backupRestorePath.sha256,
    },
    issued_at: releaseContext.issuedAt, expires_at: releaseContext.expiresAt,
    nonce: randomBytes(16).toString("hex"), sequence: releaseContext.sequence,
  });
  // Persist ONLY raw evidence bytes and the explicit unsigned manifest. A
  // separate owner must inspect/hash it; none of the outputs convey CI success.
  persistRawEvidence(bundle, evidence, manifestBytes);
  const finalInventory = await inventoryOfflineArtifacts({
    artifactRoot: bundle.directory, sourceArchivePath: bundle.sourceArchivePath,
    runtimeArchivePath: bundle.runtimeArchivePath, migratorArchivePath: bundle.migratorArchivePath,
    expectedRevision: revision, images: bundle.imageMetadata,
  });
  if (JSON.stringify(finalInventory) !== JSON.stringify(inventory)) fail("bundle changed while recording evidence");
  return Object.freeze({
    directory: bundle.directory, manifestPath: path.join(bundle.directory, "manifest.json"),
    manifestSha256: createHash("sha256").update(manifestBytes).digest("hex"),
    revision, imageIds: Object.freeze({ ...images }), inventory: finalInventory,
    ciEvidence: bundle.ciEvidence,
    assurance: "UNSIGNED_LOCAL_ONLY_CODEQL_NOT_RUN",
    limitation: "Raw local reports and Docker archives were checked, but no independent runner, scanner, backup, or hosted CI provenance is established. Owner review and trusted host verification remain mandatory.",
  });
}

// Explicit local operator entrypoint: node scripts/offline-release-build.mjs
// --request /absolute/path/operator-request.json. The request contains only
// references to existing inputs and release identifiers, never signing keys.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const run = async () => {
    if (process.argv.length !== 4 || process.argv[2] !== "--request") {
      fail("usage: node scripts/offline-release-build.mjs --request <absolute-operator-request.json>");
    }
    const request = reportJson(readEvidence(process.argv[3], "operator request").raw, "operator request");
    exactFields(request, ["repositoryRoot", "revision", "stagingParent", "ciManifestPath", "images",
      "evidencePaths", "releaseContext"], "operator request");
    exactFields(request.images, ["runtime", "migrator"], "operator image references");
    const candidate = await buildUnsignedOfflineRelease({ ...request, nowSeconds: Math.floor(Date.now() / 1000) });
    // Only print the unsigned manifest identity and result classification;
    // never emit evidence contents, credentials or signatures.
    process.stdout.write(`${JSON.stringify({
      directory: candidate.directory, manifestPath: candidate.manifestPath,
      manifestSha256: candidate.manifestSha256, revision: candidate.revision,
      assurance: candidate.assurance, limitation: candidate.limitation,
    })}\n`);
  };
  run().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "Offline release build failed"}\n`);
    process.exitCode = 1;
  });
}
