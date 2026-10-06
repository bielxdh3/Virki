import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const acceptedFindings = new Map([
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts|da86d8805094bfc3:1|13", 1],
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts|60631c9015b3ab5a:1|13", 1],
  ["js/file-access-to-http|scripts/e2e/access-token.mts|90e07734df8b1ab3:1|6", 1],
  ["js/user-controlled-bypass|scripts/e2e/jwks-server.mjs|ebcb3e6db1dd4911:1|33", 1],
]);

export function evaluateCodeqlSarif(documents) {
  if (!Array.isArray(documents) || documents.length === 0) {
    throw new Error("Invalid SARIF: expected at least one SARIF document.");
  }
  const acceptedCounts = new Map();
  const violations = [];
  let totalResults = 0;

  for (const document of documents) {
    if (!document || typeof document !== "object" || Array.isArray(document)
      || document.version !== "2.1.0" || !Array.isArray(document.runs) || document.runs.length === 0) {
      throw new Error("Invalid SARIF: expected version 2.1.0 and a non-empty runs array.");
    }
    for (const run of document.runs) {
      if (!run || typeof run !== "object" || Array.isArray(run) || !Array.isArray(run.results)) {
        throw new Error("Invalid SARIF: each run must contain a results array.");
      }
      for (const result of run.results) {
        totalResults += 1;
        const ruleId = typeof result?.ruleId === "string" ? result.ruleId : "unknown-rule";
        const uri = result?.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
        const artifactPath = normalizeArtifactPath(uri);
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
  if (typeof uri !== "string" || !uri.trim()) return "unknown-path";
  let value = uri.trim().replaceAll("\\", "/");
  try {
    if (value.startsWith("file://")) value = new URL(value).pathname;
    value = decodeURIComponent(value);
  } catch {
    return "invalid-path";
  }
  const workspaceMarker = "/github/workspace/";
  const workspaceIndex = value.indexOf(workspaceMarker);
  if (workspaceIndex >= 0) value = value.slice(workspaceIndex + workspaceMarker.length);
  value = value.replace(/^\/+/, "").replace(/^\.\//u, "");
  return value || "unknown-path";
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
