import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const acceptedFindings = new Map([
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts", 2],
  ["js/file-access-to-http|scripts/e2e/access-token.mts", 1],
  ["js/user-controlled-bypass|scripts/e2e/jwks-server.mjs", 1],
]);

export function evaluateCodeqlSarif(documents) {
  const acceptedCounts = new Map();
  const violations = [];
  let totalResults = 0;

  for (const document of documents) {
    for (const run of Array.isArray(document?.runs) ? document.runs : []) {
      for (const result of Array.isArray(run?.results) ? run.results : []) {
        totalResults += 1;
        const ruleId = typeof result?.ruleId === "string" ? result.ruleId : "unknown-rule";
        const uri = result?.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
        const artifactPath = normalizeArtifactPath(uri);
        const key = `${ruleId}|${artifactPath}`;
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
