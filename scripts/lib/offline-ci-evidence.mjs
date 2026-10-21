import { createHash } from "node:crypto";

// Structural checking only. These bytes are supplied by the claimant: the
// manifest has no independent runner, platform, log or execution attestation.
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_RUN_MILLISECONDS = 24 * 60 * 60 * 1000;
const EMPTY_SHA256 = createHash("sha256").update(Buffer.alloc(0)).digest("hex");
const REQUIRED_STAGES = Object.freeze([
  "tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check",
]);

function requireEvidence(condition, reason) {
  if (!condition) throw new Error(`Invalid offline CI manifest: ${reason}.`);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function utcTimestamp(value, field) {
  requireEvidence(typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/u.test(value), `${field} is not an explicit UTC timestamp`);
  const parsed = Date.parse(value);
  requireEvidence(Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19),
    `${field} has an invalid UTC calendar date`);
  return parsed;
}

function compatibleVersion(value, major, minimumMinor, minimumPatch) {
  const match = typeof value === "string" ? /^(?:v)?(\d+)\.(\d+)\.(\d+)$/u.exec(value) : null;
  if (!match || Number(match[1]) !== major) return false;
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  return minor > minimumMinor || (minor === minimumMinor && patch >= minimumPatch);
}

/**
 * Checks the claimed shape and cleanliness of one isolated local CI manifest.
 * It never contacts CI, GitHub, production or the runner. A forged manifest
 * with plausible values can pass; it is not trusted release authorization.
 *
 * @param {Uint8Array} rawBytes Exact raw run-manifest.json bytes, not a JS object.
 * @param {string} expectedRevision Full lower-case 40-hex Git commit SHA.
 * @param {string} [expectedBranch='main'] Branch explicitly expected by caller.
 */
export function validateOfflineCiEvidence(rawBytes, expectedRevision, expectedBranch = "main") {
  requireEvidence(rawBytes instanceof Uint8Array && rawBytes.byteLength > 0 &&
    rawBytes.byteLength <= MAX_MANIFEST_BYTES, "raw bytes are missing or oversized");
  requireEvidence(typeof expectedRevision === "string" && /^[0-9a-f]{40}$/u.test(expectedRevision),
    "expected revision is not a full canonical Git SHA");
  requireEvidence(typeof expectedBranch === "string" &&
    /^(?!\/)(?!.*(?:\/\/|\.\.))[A-Za-z0-9._/-]{1,200}$/u.test(expectedBranch), "expected branch is invalid");

  const manifestSha256 = createHash("sha256").update(rawBytes).digest("hex");
  let manifest;
  try {
    const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(rawBytes);
    manifest = JSON.parse(utf8);
  } catch {
    throw new Error("Invalid offline CI manifest: malformed UTF-8 or JSON.");
  }

  requireEvidence(isRecord(manifest), "root must be a JSON object");
  requireEvidence(manifest.sourceHead === expectedRevision, "source revision differs from requested SHA");
  requireEvidence(manifest.sourceBranch === expectedBranch, "source branch differs from expected branch");
  requireEvidence(typeof manifest.runId === "string" && /^[a-f0-9]{10}$/u.test(manifest.runId),
    "run identifier is invalid");
  requireEvidence(compatibleVersion(manifest.nodeVersion, 22, 13, 0), "unsupported Node runtime claim");
  requireEvidence(compatibleVersion(manifest.npmVersion, 10, 9, 3), "unsupported npm runtime claim");

  for (const name of ["stagedPatchSha256", "workingTreePatchSha256"]) {
    requireEvidence(manifest[name] === EMPTY_SHA256, `${name} does not match an empty patch`);
  }
  requireEvidence(Array.isArray(manifest.untrackedFiles) && manifest.untrackedFiles.length === 0,
    "untracked source files were reported or field is absent");
  requireEvidence(manifest.exitCode === 0, "outer run did not exit successfully");
  requireEvidence(Array.isArray(manifest.failedStages) && manifest.failedStages.length === 0,
    "outer run reported failed stages or lacks failure records");

  for (const prefix of ["unitTests", "integrationTests", "productionOperations"]) {
    requireEvidence(manifest[`${prefix}FailureCount`] === 0 &&
      Array.isArray(manifest[`${prefix}Failures`]) && manifest[`${prefix}Failures`].length === 0,
    `${prefix} failure records are incomplete or nonempty`);
  }

  const started = utcTimestamp(manifest.startedUtc, "run start");
  const finished = utcTimestamp(manifest.finishedUtc, "run finish");
  requireEvidence(finished > started && finished - started <= MAX_RUN_MILLISECONDS,
    "run duration is invalid or excessive");
  requireEvidence(Array.isArray(manifest.stages) && manifest.stages.length === REQUIRED_STAGES.length,
    "exactly 19 complete stages are required");

  let lastFinish = started;
  for (let i = 0; i < REQUIRED_STAGES.length; i += 1) {
    const stage = manifest.stages[i];
    requireEvidence(isRecord(stage) && stage.name === REQUIRED_STAGES[i],
      `stage ${i + 1} is missing, unknown, repeated, or out of sequence`);
    requireEvidence(stage.exitCode === 0, `stage ${i + 1} did not exit successfully`);
    const stageStart = utcTimestamp(stage.startedUtc, `stage ${i + 1} start`);
    const stageFinish = utcTimestamp(stage.finishedUtc, `stage ${i + 1} finish`);
    requireEvidence(stageStart >= lastFinish && stageFinish >= stageStart && stageFinish <= finished,
      `stage ${i + 1} ran outside the monotonic run interval`);
    requireEvidence(typeof stage.durationMs === "number" && Number.isFinite(stage.durationMs) &&
      stage.durationMs >= 0 && stage.durationMs <= MAX_RUN_MILLISECONDS &&
      Math.abs(stageFinish - stageStart - stage.durationMs) < 2_000,
    `stage ${i + 1} elapsed duration is invalid`);
    lastFinish = stageFinish;
  }

  return Object.freeze({
    ok: true,
    revision: expectedRevision,
    branch: expectedBranch,
    stageCount: REQUIRED_STAGES.length,
    manifestSha256,
    limitation: "Untrusted local metadata only: structural validation does not prove stages executed, Linux runner identity, independent CI, log authenticity, or deploy safety.",
  });
}
