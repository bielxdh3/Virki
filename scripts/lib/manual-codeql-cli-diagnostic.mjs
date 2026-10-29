import { createHash, timingSafeEqual } from "node:crypto";

// Diagnostic record anchored to the W50 independent local CLI run; it is NOT a
// production policy, a signer key, or evidence of independent execution.
// Changing these pins requires a separately reviewed source and scan record.
export const PINNED_DIAGNOSTIC = Object.freeze({
  sourceCommit: "c3ea768956bc3522363b725c138086a3c3e1c399",
  sarifSha256: "af395b6840d587ed423c121c7a9310bc30ab55dad17e45b68be4b32281c40c76",
  scannerVersion: "2.27.3",
  category: "/language:javascript-typescript/",
  expectedJsTs: 459,
  observedResults: 72,
});

const FMT = "sarifv2.1.0";
const EXPECTED = "js/baseline/expected-extracted-files";
const EXTRACTED = "js/diagnostics/successfully-extracted-files";

function invalid(reason) {
  return Object.freeze({
    status: "INVALID", gateDecision: "NO_GO", authorizesRelease: false,
    trustedScannerExecution: false, expectedSourceCommit: PINNED_DIAGNOSTIC.sourceCommit,
    blockers: Object.freeze([reason]),
  });
}
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function requireIt(condition, message) {
  if (!condition) throw new Error(message);
}
function normalizeLocation(location, artifacts, { allowMissingIndex = false } = {}) {
  requireIt(isRecord(location), "SOURCE_LOCATION_MISSING");
  const uri = location.uri;
  requireIt(typeof uri === "string" && uri.length > 0 && uri.length < 4096 &&
    !/[\\?#%:]/u.test(uri) &&
    [...uri].every(character => { const codePoint = character.codePointAt(0); return codePoint > 31 && codePoint !== 127; }) &&
    !uri.startsWith("/") && !uri.endsWith("/") &&
    uri.split("/").every(part => part.length > 0 && part !== "." && part !== "..") &&
    (location.uriBaseId === undefined || location.uriBaseId === "%SRCROOT%"),
  "UNSAFE_SOURCE_LOCATION");
  if (artifacts) {
    const index = location.index;
    requireIt(allowMissingIndex || Number.isSafeInteger(index), "ARTIFACT_INDEX_MISSING");
    if (index !== undefined) {
      requireIt(Number.isSafeInteger(index) && index >= 0 && index < artifacts.length &&
        artifacts[index].location.uri === uri, "ARTIFACT_IDENTITY_MISMATCH");
    }
  }
  return uri;
}
function notificationFile(notice, artifacts) {
  const loc = notice.locations?.[0]?.physicalLocation?.artifactLocation;
  requireIt(notice.locations?.length === 1, "EXTRACTION_LOCATION_MISSING");
  return normalizeLocation(loc, artifacts);
}

/**
 * Parse UNTRUSTED SARIF for human diagnostics. This API always denies authority,
 * even for zero findings, self-reported success, or a forged coverage claim.
 * No caller-provided pin, review, trust identity or execution claim is accepted.
 */
export function inspectUntrustedCodeqlCliDocument(document) {
  try {
    requireIt(isRecord(document) && document.version === "2.1.0" &&
      Array.isArray(document.runs) && document.runs.length === 1, "INVALID_SARIF_ENVELOPE");
    const run = document.runs[0];
    const driver = run?.tool?.driver;
    requireIt(isRecord(driver) && driver.name === "CodeQL" &&
      driver.organization === "GitHub" &&
      driver.semanticVersion === PINNED_DIAGNOSTIC.scannerVersion &&
      (driver.version === undefined || driver.version === driver.semanticVersion),
    "INVALID_CODEQL_CLI_DRIVER");
    requireIt(run?.properties?.["semmle.formatSpecifier"] === FMT &&
      run?.automationDetails?.id === PINNED_DIAGNOSTIC.category,
    "INVALID_CODEQL_CLI_FORMAT_OR_CATEGORY");
    requireIt(Array.isArray(driver.rules) && driver.rules.length > 0 &&
      Array.isArray(run.artifacts) && Array.isArray(run.results) &&
      Array.isArray(run.invocations) && run.invocations.length === 1,
    "INVALID_CODEQL_CLI_TABLES");

    const ruleIndices = new Map();
    for (const [index, descriptor] of driver.rules.entries()) {
      requireIt(isRecord(descriptor) && typeof descriptor.id === "string" &&
        /^js\/[a-z0-9-]+(?:\/[a-z0-9-]+)*$/u.test(descriptor.id) &&
        !ruleIndices.has(descriptor.id), "INVALID_RULE_TABLE");
      ruleIndices.set(descriptor.id, index);
    }
    const seenArtifacts = new Set();
    for (const artifact of run.artifacts) {
      const uri = normalizeLocation(artifact?.location);
      requireIt(!seenArtifacts.has(uri), "DUPLICATE_SOURCE_ARTIFACT");
      seenArtifacts.add(uri);
    }
    for (const finding of run.results) {
      requireIt(isRecord(finding) && typeof finding.ruleId === "string" &&
        ruleIndices.get(finding.ruleId) === finding.ruleIndex &&
        typeof finding.message?.text === "string" && finding.message.text.length > 0 &&
        Array.isArray(finding.locations) && finding.locations.length === 1,
      "INVALID_RESULT_OR_RULE_REFERENCE");
      const physical = finding.locations[0].physicalLocation;
      normalizeLocation(physical?.artifactLocation, run.artifacts);
      requireIt(Number.isSafeInteger(physical?.region?.startLine) &&
        physical.region.startLine > 0, "INVALID_RESULT_LINE");
    }
    const invocation = run.invocations[0];
    requireIt(invocation?.executionSuccessful === true &&
      Array.isArray(invocation.toolExecutionNotifications),
    "CODEQL_EXECUTION_UNKNOWN_OR_FAILED");
    const expected = new Set();
    const extracted = new Set();
    let baselineCount = 0;
    let extractedCount = 0;
    for (const notice of invocation.toolExecutionNotifications) {
      requireIt(isRecord(notice) && notice.level !== "error" &&
        notice.descriptor?.id !== "js/diagnostics/extraction-errors", "CODEQL_EXECUTION_DIAGNOSTIC_ERROR");
      if (notice.descriptor?.id !== EXPECTED && notice.descriptor?.id !== EXTRACTED) continue;
      const name = notificationFile(notice, run.artifacts);
      if (notice.descriptor.id === EXPECTED) {
        baselineCount += 1;
        requireIt(!expected.has(name), "DUPLICATE_EXPECTED_FILE");
        expected.add(name);
      } else {
        extractedCount += 1;
        requireIt(!extracted.has(name), "DUPLICATE_EXTRACTED_FILE");
        extracted.add(name);
      }
    }
    requireIt(baselineCount > 0 && extractedCount > 0, "MISSING_EXTRACTION_TELEMETRY");
    // Successful extractions include e.g. JSON/YAML. Match only the expected
    // JS/TS set; a fabricated additional success outside it never counts.
    const extractedExpected = [...expected].filter(uri => extracted.has(uri));
    const missing = [...expected].filter(uri => !extracted.has(uri)).sort();
    const blockers = ["NO_INDEPENDENT_SCANNER_EXECUTION_ATTESTATION"];
    if (run.results.length > 0) blockers.push("UNADJUDICATED_FINDINGS");
    if (expected.size !== PINNED_DIAGNOSTIC.expectedJsTs || missing.length > 0) {
      blockers.push("INCOMPLETE_JS_TS_EXTRACTION");
    }
    // This parser has NO accepted-findings table and NO positive security state.
    return Object.freeze({
      status: "NO_GO", gateDecision: "NO_GO", authorizesRelease: false,
      trustedScannerExecution: false,
      scannerSelfReportsSuccess: true,
      provenance: "UNTRUSTED_SARIF_FORMAT_ONLY",
      expectedSourceCommit: PINNED_DIAGNOSTIC.sourceCommit,
      scannerVersion: driver.semanticVersion,
      counts: Object.freeze({ findings: run.results.length,
        expectedJsTs: expected.size, extractedExpectedJsTs: extractedExpected.length }),
      missingExpectedJsTs: Object.freeze(missing),
      blockers: Object.freeze(blockers),
    });
  } catch (error) {
    return invalid(error instanceof Error ? error.message : "INVALID_CODEQL_CLI_DOCUMENT");
  }
}

/**
 * Match the exact W50 byte stream using a fixed code-owned digest. This pin
 * identifies the archived local sample only. It DOES NOT authenticate CodeQL
 * execution, source checkout at scan time, owner, reviewer or hosted evidence.
 */
export function verifyPinnedManualCodeqlCliSarif(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 16 * 1024 * 1024) {
    return invalid("INVALID_SARIF_BYTES");
  }
  const found = createHash("sha256").update(bytes).digest();
  const expected = Buffer.from(PINNED_DIAGNOSTIC.sarifSha256, "hex");
  if (!timingSafeEqual(found, expected)) return invalid("SARIF_DIGEST_NOT_PINNED");
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch { return invalid("INVALID_SARIF_UTF8_JSON"); }
  const diagnosis = inspectUntrustedCodeqlCliDocument(value);
  if (diagnosis.status === "INVALID") return diagnosis;
  if (diagnosis.counts.findings !== PINNED_DIAGNOSTIC.observedResults ||
    diagnosis.counts.expectedJsTs !== PINNED_DIAGNOSTIC.expectedJsTs) {
    return invalid("PINNED_SAMPLE_METADATA_INCONSISTENT");
  }
  return Object.freeze({
    ...diagnosis,
    provenance: "EXACT_W50_SARIF_BYTES_ONLY_NO_EXECUTION_ATTESTATION",
    sarifSha256: PINNED_DIAGNOSTIC.sarifSha256,
    sourceCommit: PINNED_DIAGNOSTIC.sourceCommit,
  });
}
