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
const MANIFEST_FIELDS = new Set([
  "runId", "sourceBranch", "sourceHead", "startedUtc", "finishedUtc",
  "nodeVersion", "npmVersion", "browserImage", "playwrightVersion",
  "browserRevision", "browserVersion", "stagedPatchSha256",
  "workingTreePatchSha256", "untrackedFiles", "unitTestsLog",
  "unitTestsFailureCount", "unitTestsFailures", "integrationTestsLog",
  "integrationTestsFailureCount",
  "integrationTestsFailures", "productionOperationsLog",
  "productionOperationsFailureCount", "productionOperationsFailures",
  "browserE2ELog", "exitCode", "failedStages", "stages",
]);
const STAGE_FIELDS = new Set([
  "name", "startedUtc", "finishedUtc", "durationMs", "exitCode",
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

// JSON.parse silently keeps the last occurrence of duplicate object keys.
// This local evidence deliberately keeps the runner's pretty-printed JSON,
// so enforcing JSON.stringify roundtrips would reject authentic reports.
// Validate every object key, including escaped spelling, before JSON.parse.
function rejectDuplicateJsonKeys(source) {
  let at = 0;
  const whitespace = () => {
    while (at < source.length && /[\x20\t\n\r]/u.test(source[at])) at += 1;
  };
  const stringToken = () => {
    requireEvidence(source[at] === '"', "expected a JSON string");
    const start = at++;
    while (at < source.length) {
      const code = source.charCodeAt(at);
      if (code === 0x22) {
        at += 1;
        return JSON.parse(source.slice(start, at));
      }
      if (code === 0x5c) {
        at += 2;
      } else {
        requireEvidence(code >= 0x20, "unescaped JSON control character");
        at += 1;
      }
    }
    requireEvidence(false, "unterminated JSON string");
  };
  const token = (value) => {
    requireEvidence(source.startsWith(value, at), "malformed JSON literal");
    at += value.length;
  };
  const value = (depth) => {
    requireEvidence(depth <= 32, "JSON nesting exceeds the evidence limit");
    whitespace();
    const character = source[at];
    if (character === '"') {
      stringToken();
    } else if (character === "{") {
      at++;
      whitespace();
      const keys = new Set();
      if (source[at] === "}") { at++; return; }
      while (true) {
        whitespace();
        const key = stringToken();
        requireEvidence(!keys.has(key), "duplicate JSON object key");
        keys.add(key);
        requireEvidence(keys.size <= 2048, "too many JSON object keys");
        whitespace();
        requireEvidence(source[at] === ":", "malformed JSON object");
        at++;
        value(depth + 1);
        whitespace();
        if (source[at] === "}") { at++; break; }
        requireEvidence(source[at] === ",", "malformed JSON object separator");
        at++;
      }
    } else if (character === "[") {
      at++;
      whitespace();
      if (source[at] === "]") { at++; return; }
      while (true) {
        value(depth + 1);
        whitespace();
        if (source[at] === "]") { at++; break; }
        requireEvidence(source[at] === ",", "malformed JSON array separator");
        at++;
      }
    } else if (character === "t") {
      token("true");
    } else if (character === "f") {
      token("false");
    } else if (character === "n") {
      token("null");
    } else {
      const number = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/uy;
      number.lastIndex = at;
      const matched = number.exec(source);
      requireEvidence(matched !== null, "malformed JSON number or value");
      at = number.lastIndex;
    }
  };
  value(0);
  whitespace();
  requireEvidence(at === source.length, "trailing JSON content");
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
    rejectDuplicateJsonKeys(utf8);
    manifest = JSON.parse(utf8);
  } catch {
    throw new Error("Invalid offline CI manifest: malformed UTF-8 or JSON.");
  }

  requireEvidence(isRecord(manifest), "root must be a JSON object");
  requireEvidence(Object.keys(manifest).every((key) => MANIFEST_FIELDS.has(key)),
    "unrecognized root evidence field");
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
    requireEvidence(Object.keys(stage).length === STAGE_FIELDS.size &&
      Object.keys(stage).every((key) => STAGE_FIELDS.has(key)),
    `stage ${i + 1} has missing or unknown fields`);
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
