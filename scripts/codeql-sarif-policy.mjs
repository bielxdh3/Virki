import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const acceptedFindings = new Map([
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts|da86d8805094bfc3:1|13", 1],
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts|60631c9015b3ab5a:1|13", 1],
  ["js/file-access-to-http|scripts/e2e/access-token.mts|90e07734df8b1ab3:1|6", 1],
  ["js/user-controlled-bypass|scripts/e2e/jwks-server.mjs|ebcb3e6db1dd4911:1|33", 1],
]);

function invalidSarif(message) {
  throw new Error(`Invalid SARIF: ${message}`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// CodeQL's documented SARIF contains rules for queries in the analysis and
// artifacts for files referenced by results. Neither is a coverage inventory.
// Keep this validator structural; only the exact-SHA hosted workflow provides
// evidence that the scanner really ran on the intended checkout.
function validateCodeqlRun(run) {
  if (!isObject(run) || !Array.isArray(run.results)) invalidSarif("each run needs a results array.");
  const driver = run.tool?.driver;
  if (!isObject(driver) || driver.name !== "CodeQL command-line toolchain"
    || driver.organization !== "GitHub" || typeof driver.version !== "string"
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(driver.version)) {
    invalidSarif("expected a versioned CodeQL CLI driver.");
  }
  if (!isObject(run.properties) || typeof run.properties["semmle.formatSpecifier"] !== "string"
    || !run.properties["semmle.formatSpecifier"].trim()) {
    invalidSarif("CodeQL exporter format is missing.");
  }
  if (run.automationDetails !== undefined && (!isObject(run.automationDetails)
    || !["/language:javascript-typescript", "/language:javascript-typescript/"].includes(run.automationDetails.id))) {
    invalidSarif("unexpected CodeQL analysis category.");
  }
  // CodeQL can group query descriptors by pack with --sarif-group-rules-by-pack.
  // A result referring to an extension must identify that component explicitly.
  const extensions = run.tool.extensions ?? [];
  if (!Array.isArray(driver.rules) || !Array.isArray(extensions)) invalidSarif("invalid rule component inventory.");
  const ruleTables = [driver, ...extensions].map((component) => {
    if (!isObject(component) || (component.rules !== undefined && !Array.isArray(component.rules))) {
      invalidSarif("invalid CodeQL rule component.");
    }
    const rules = new Map();
    for (const [index, descriptor] of (component.rules ?? []).entries()) {
      if (!isObject(descriptor) || typeof descriptor.id !== "string" || !descriptor.id.trim()
        || rules.has(descriptor.id)) invalidSarif("invalid or duplicate CodeQL rule descriptor.");
      rules.set(descriptor.id, index);
    }
    return rules;
  });
  if (ruleTables.every((rules) => rules.size === 0)) invalidSarif("CodeQL rule descriptors are missing.");
  if (!Array.isArray(run.artifacts)) invalidSarif("CodeQL artifact table is missing.");
  const artifactPaths = new Map();
  run.artifacts.forEach((artifact, index) => {
    if (!isObject(artifact) || !isObject(artifact.location)) invalidSarif("invalid artifact entry.");
    const location = artifact.location;
    if (location.index !== undefined && location.index !== index) invalidSarif("inconsistent artifact index.");
    const normalized = normalizeArtifactPath(location.uri);
    if (!normalized || (location.uriBaseId !== undefined && location.uriBaseId !== "%SRCROOT%")) {
      invalidSarif("invalid artifact source location.");
    }
    if (artifactPaths.has(normalized)) invalidSarif("duplicate artifact source location.");
    artifactPaths.set(normalized, index);
  });
  if (run.invocations !== undefined) {
    if (!Array.isArray(run.invocations) || run.invocations.some((invocation) =>
      !isObject(invocation) || invocation.executionSuccessful === false
      || (invocation.toolExecutionNotifications !== undefined
        && (!Array.isArray(invocation.toolExecutionNotifications)
          || invocation.toolExecutionNotifications.some((notice) =>
            !isObject(notice) || notice.level === "error"
            || notice.descriptor?.id === "js/diagnostics/extraction-errors"))))) {
      invalidSarif("CodeQL invocation reports failure or invalid diagnostics.");
    }
  }
  for (const result of run.results) {
    if (!isObject(result) || typeof result.ruleId !== "string"
      || !isObject(result.message) || ![result.message.text, result.message.markdown]
        .some((value) => typeof value === "string" && value.trim())) {
      invalidSarif("result has no rule identifier or message.");
    }
    const toolComponent = result.rule?.toolComponent;
    let componentIndex = 0;
    if (toolComponent !== undefined) {
      if (!isObject(toolComponent) || !Number.isSafeInteger(toolComponent.index)
        || toolComponent.index < -1 || toolComponent.index >= extensions.length) {
        invalidSarif("invalid CodeQL tool extension reference.");
      }
      componentIndex = toolComponent.index + 1;
    }
    const registeredIndex = ruleTables[componentIndex].get(result.ruleId);
    if (registeredIndex === undefined) invalidSarif("result rule is absent from referenced component.");
    if (result.ruleIndex !== undefined && result.ruleIndex !== registeredIndex) {
      invalidSarif("result ruleIndex does not match ruleId.");
    }
    if (result.rule !== undefined && (!isObject(result.rule)
      || (result.rule.id !== undefined && result.rule.id !== result.ruleId)
      || (result.rule.index !== undefined && result.rule.index !== registeredIndex))) {
      invalidSarif("result rule reference does not match its component.");
    }
    const locations = result.locations;
    if (!Array.isArray(locations) || locations.length !== 1
      || !isObject(locations[0]?.physicalLocation?.artifactLocation)) {
      invalidSarif("result needs one source location.");
    }
    const location = locations[0].physicalLocation.artifactLocation;
    if (location.uriBaseId !== undefined && location.uriBaseId !== "%SRCROOT%") {
      invalidSarif("unexpected result source root.");
    }
    const normalized = location.uri === undefined ? undefined : normalizeArtifactPath(location.uri);
    if (location.uri !== undefined && !normalized) invalidSarif("invalid result source location.");
    if (location.index !== undefined && (!Number.isSafeInteger(location.index)
      || location.index < 0 || location.index >= run.artifacts.length)) {
      invalidSarif("result references an unknown artifact index.");
    }
    const artifactPath = location.index === undefined
      ? normalized : normalizeArtifactPath(run.artifacts[location.index].location.uri);
    if (!artifactPath || (normalized !== undefined && normalized !== artifactPath)
      || artifactPaths.get(artifactPath) === undefined) {
      invalidSarif("result source location is inconsistent with its artifact.");
    }
  }
}

export function evaluateCodeqlSarif(documents) {
  if (!Array.isArray(documents) || documents.length !== 1) {
    throw new Error("Invalid SARIF: expected one JavaScript/TypeScript SARIF document.");
  }
  const acceptedCounts = new Map();
  const violations = [];
  let totalResults = 0;

  for (const document of documents) {
    if (!isObject(document) || document.version !== "2.1.0" || !Array.isArray(document.runs) || document.runs.length !== 1) {
      throw new Error("Invalid SARIF: expected version 2.1.0 and exactly one run.");
    }
    for (const run of document.runs) {
      validateCodeqlRun(run);
      for (const result of run.results) {
        totalResults += 1;
        const ruleId = result.ruleId;
        const location = result.locations[0].physicalLocation.artifactLocation;
        const artifactPath = normalizeArtifactPath(location.uri ?? run.artifacts[location.index].location.uri);
        const lineFingerprint = result?.partialFingerprints?.primaryLocationLineHash;
        const columnFingerprint = result?.partialFingerprints?.primaryLocationStartColumnFingerprint;
        const hasFingerprint = typeof lineFingerprint === "string" && lineFingerprint.trim()
          && typeof columnFingerprint === "string" && columnFingerprint.trim();
        const key = hasFingerprint
          ? `${ruleId}|${artifactPath}|${lineFingerprint}|${columnFingerprint}`
          : `${ruleId}|${artifactPath}|missing-fingerprint`;
        const maximum = acceptedFindings.get(key);
        if (maximum === undefined) {
          violations.push({ ruleId, path: artifactPath, reason: "unreviewed-finding" });
          continue;
        }
        const count = (acceptedCounts.get(key) ?? 0) + 1;
        acceptedCounts.set(key, count);
        if (count > maximum) {
          violations.push({ ruleId, path: artifactPath, reason: "accepted-finding-count-exceeded" });
        }
      }
    }
  }

  return {
    ok: violations.length === 0,
    totalResults,
    acceptedResults: totalResults - violations.length,
    violations
  };
}

function normalizeArtifactPath(uri) {
  if (typeof uri !== "string" || !uri || uri.trim() !== uri || /[\\?#]/u.test(uri)) return null;
  let value = uri;
  try {
    if (value.startsWith("file://")) {
      const location = new URL(value);
      if (location.protocol !== "file:" || location.host) return null;
      value = location.pathname;
    }
    value = decodeURIComponent(value);
  } catch {
    return null;
  }
  const workspaceMarker = "/github/workspace/";
  if (value.startsWith(workspaceMarker)) value = value.slice(workspaceMarker.length);
  else if (value.startsWith("/")) return null;
  value = value.replace(/^\.\//u, "");
  if (!value || /[:\\]/u.test(value) || [...value].some((char) => char.charCodeAt(0) < 32)
    || value.split("/").some((part) => !part || part === "." || part === "..")) return null;
  return value;
}

export function readSarifDirectory(directory) {
  const absolute = path.resolve(directory);
  const files = collectSarifFiles(absolute);
  if (files.length === 0) throw new Error("CodeQL SARIF policy found no SARIF files.");
  return files.map((file) => JSON.parse(readFileSync(file, "utf8")));
}

function collectSarifFiles(directory) {
  const results = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) results.push(...collectSarifFiles(fullPath));
    else if (entry.isFile() && entry.name.endsWith(".sarif")) results.push(fullPath);
  }
  return results.sort();
}

function isMainModule() {
  return Boolean(process.argv[1]) && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  try {
    const directory = process.argv[2];
    if (!directory || process.argv.length !== 3) throw new Error("Usage: node scripts/codeql-sarif-policy.mjs <sarif-directory>");
    const result = evaluateCodeqlSarif(readSarifDirectory(directory));
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "CodeQL SARIF policy failed.");
    process.exitCode = 1;
  }
}
