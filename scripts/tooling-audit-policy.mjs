import { readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const EXPECTED_TOOLING_VERSIONS = {
  prisma: "6.19.3",
  "@prisma/client": "6.19.3",
  "@prisma/config": "6.19.3",
  "deepmerge-ts": "7.1.5"
};

const expectedCounts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
const expectedVulnerabilities = {};
const AUDIT_PROCESS_TIMEOUT_MS = 45_000;
const MAX_EXCEPTION_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;
const severityKeys = Object.keys(expectedCounts);

export const TEMPORARY_TOOLING_ADVISORY_EXCEPTION = Object.freeze({
  advisoryId: "GHSA-fc5q-39xc-vjpf",
  advisoryUrl: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
  package: "picomatch",
  vulnerableRange: "<=4.0.7",
  severity: "high",
  createdAt: "2026-11-18T00:00:00Z",
  expiresAt: "2026-12-02T00:00:00Z",
  allowedChainPackages: Object.freeze([
    "picomatch",
    "fdir",
    "tinyglobby",
    "@typescript-eslint/typescript-estree",
    "@typescript-eslint/utils",
    "@typescript-eslint/parser",
    "@typescript-eslint/type-utils",
    "@typescript-eslint/eslint-plugin",
    "typescript-eslint"
  ]),
  acceptedRisk: "ReDoS in dev-only ESLint glob expansion (typescript-eslint -> tinyglobby -> fdir -> picomatch <=4.0.7); zero production reachability and no upstream patch published (first_patched_version: null).",
  removalCondition: "Remove immediately once picomatch >4.0.7 (or a compatible typescript-eslint release without vulnerable picomatch) is published."
});

const ALLOWED_EXCEPTION_CHAIN = new Set(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.allowedChainPackages);

export function isTemporaryToolingExceptionValid(audit, { productionReachable, now = new Date() } = {}) {
  if (productionReachable !== false) return false;
  const createdMs = Date.parse(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.createdAt);
  const expiresMs = Date.parse(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.expiresAt);
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(createdMs) || !Number.isFinite(expiresMs) || !Number.isFinite(nowMs)) return false;
  if (expiresMs <= createdMs || expiresMs - createdMs > MAX_EXCEPTION_WINDOW_MS) return false;
  if (nowMs < createdMs || nowMs > expiresMs) return false;

  const counts = audit?.metadata?.vulnerabilities;
  const vulnerabilities = audit?.vulnerabilities;
  if (!plainRecord(counts) || !plainRecord(vulnerabilities)) return false;
  const entries = Object.entries(vulnerabilities);
  if (entries.length === 0) return false;
  if (counts.info !== 0 || counts.low !== 0 || counts.moderate !== 0 || counts.critical !== 0) return false;
  if (counts.high !== entries.length || counts.total !== entries.length) return false;

  const root = vulnerabilities[TEMPORARY_TOOLING_ADVISORY_EXCEPTION.package];
  if (!plainRecord(root) || root.isDirect !== false || root.severity !== TEMPORARY_TOOLING_ADVISORY_EXCEPTION.severity) return false;
  if (!Array.isArray(root.via) || root.via.length === 0) return false;
  const rootViaValid = root.via.every((item) =>
    plainRecord(item) &&
    item.name === TEMPORARY_TOOLING_ADVISORY_EXCEPTION.package &&
    item.url === TEMPORARY_TOOLING_ADVISORY_EXCEPTION.advisoryUrl &&
    item.severity === TEMPORARY_TOOLING_ADVISORY_EXCEPTION.severity &&
    item.range === TEMPORARY_TOOLING_ADVISORY_EXCEPTION.vulnerableRange
  );
  if (!rootViaValid) return false;

  return entries.every(([pkgName, entry]) => {
    if (!ALLOWED_EXCEPTION_CHAIN.has(pkgName) || !plainRecord(entry) || entry.severity !== "high") return false;
    if (pkgName === TEMPORARY_TOOLING_ADVISORY_EXCEPTION.package) return true;
    return Array.isArray(entry.via) && entry.via.length > 0 && entry.via.every((dep) => typeof dep === "string" && ALLOWED_EXCEPTION_CHAIN.has(dep));
  });
}

export function evaluateToolingAudit(audit, { versions = EXPECTED_TOOLING_VERSIONS, productionReachable, now = new Date() } = {}) {
  const errors = [];
  const counts = audit?.metadata?.vulnerabilities;
  const vulnerabilities = audit?.vulnerabilities;

  if (productionReachable === true) errors.push("The tooling advisory is reachable from the production tree.");
  if (audit?.auditReportVersion !== 2) errors.push("Unexpected npm audit report version.");
  const hasZeroVulnerabilities = stable(counts) === stable(expectedCounts) && stable(vulnerabilities) === stable(expectedVulnerabilities);
  const allowedByTemporaryException = !hasZeroVulnerabilities && isTemporaryToolingExceptionValid(audit, { productionReachable, now });
  if (!hasZeroVulnerabilities && !allowedByTemporaryException) {
    if (stable(counts) !== stable(expectedCounts)) errors.push("The tooling dependency audit found vulnerabilities.");
    if (stable(vulnerabilities) !== stable(expectedVulnerabilities)) errors.push("The tooling dependency audit returned vulnerability entries.");
  }
  if (stable(versions) !== stable(EXPECTED_TOOLING_VERSIONS)) errors.push("Prisma tooling versions drifted from the pinned versions.");
  return {
    ok: errors.length === 0,
    status: errors.length === 0 ? "passed" : "failed",
    ...(allowedByTemporaryException && errors.length === 0 ? { temporaryException: TEMPORARY_TOOLING_ADVISORY_EXCEPTION.advisoryId, expiresAt: TEMPORARY_TOOLING_ADVISORY_EXCEPTION.expiresAt } : {}),
    errors
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // A fixture path in an inherited environment must never bypass the live
  // registry audit gate. Deterministic tests call the pure exported parser.
  const execution = runAudit();
  if (execution.status !== "reported") {
    console.log(JSON.stringify({ ok: false, status: "unavailable", reason: execution.reason }));
    process.exitCode = 1;
  } else {
    let productionReachable = false;
    const prodExecution = runAudit({ omitDev: true });
    if (prodExecution.status !== "reported" || prodExecution.report?.metadata?.vulnerabilities?.total !== 0) {
      productionReachable = true;
    }
    const versions = readCurrentVersions();
    const output = summarizeToolingAuditReport(execution.report, versions, { productionReachable });
    console.log(JSON.stringify(output));
    if (!output.ok) process.exitCode = 1;
  }
}

export function summarizeToolingAuditReport(report, versions, { productionReachable, now = new Date() } = {}) {
  const result = evaluateToolingAudit(report, { versions, productionReachable, now });
  if (result.ok) return result;
  const counts = report.metadata.vulnerabilities;
  // Raw npm audit JSON may contain registry URLs, package paths and private
  // local version fields. Only fixed labels and safe counts reach stdout.
  return {
    ...result,
    observed: {
      auditReportVersion: 2,
      vulnerabilityCounts: Object.fromEntries(severityKeys.map((key) => [key, counts[key]]))
    }
  };
}
export function npmAuditArguments({ omitDev = false } = {}) {
  // Disable retry/backoff amplification; do NOT suppress audit or substitute
  // cached/fixture findings. An inaccessible registry must fail closed.
  return ["audit", ...(omitDev ? ["--omit=dev"] : []), "--package-lock-only", "--json", "--fetch-retries=0", "--fetch-timeout=25000"];
}

function plainRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function interpretNpmAuditResult(result) {
  if (result?.error) return {
    status: "unavailable",
    reason: result.error.code === "ETIMEDOUT" ? "process-timeout" : "execution-error"
  };
  if (typeof result?.stdout !== "string" || !result.stdout.trim()) {
    return { status: "unavailable", reason: "empty-output" };
  }
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    return { status: "unavailable", reason: "invalid-json" };
  }
  if (plainRecord(report) && plainRecord(report.error)) {
    // npm itself serializes registry/auth/network errors as {error:{...}}.
    // Never echo the untrusted error summary: it may include registry URLs,
    // tokens, request details or package names.
    return { status: "unavailable", reason: "registry-or-network-error" };
  }
  const counts = report?.metadata?.vulnerabilities;
  if (report?.auditReportVersion !== 2 ||
      !plainRecord(report.vulnerabilities) ||
      !plainRecord(counts) ||
      severityKeys.some((key) => !Number.isSafeInteger(counts[key]) || counts[key] < 0)) {
    return { status: "unavailable", reason: "invalid-report" };
  }
  // npm exits 1 for real vulnerabilities, so the only trustworthy exit codes
  // for a complete version-2 report are 0 or 1. A clean report + code 1
  // cannot authorize a pass (the command might have failed after emitting).
  if (result.status !== 0 && result.status !== 1) {
    return { status: "unavailable", reason: "unexpected-exit" };
  }
  if (result.status === 1 && counts.total === 0) {
    return { status: "unavailable", reason: "unexpected-exit" };
  }
  return { status: "reported", report };
}

function runAudit({ omitDev = false } = {}) {
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  const result = spawnSync(npmCommand, npmAuditArguments({ omitDev }), {
    cwd: path.resolve(fileURLToPath(new URL("..", import.meta.url))),
    encoding: "utf8",
    shell: process.platform === "win32",
    windowsHide: true,
    maxBuffer: 20 * 1024 * 1024,
    timeout: AUDIT_PROCESS_TIMEOUT_MS,
    killSignal: "SIGTERM"
  });
  return interpretNpmAuditResult(result);
}

function readCurrentVersions() {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  return Object.fromEntries(Object.keys(EXPECTED_TOOLING_VERSIONS).map((name) => {
    const packageJson = path.join(root, "node_modules", ...name.split("/"), "package.json");
    return [name, JSON.parse(readFileSync(packageJson, "utf8")).version];
  }));
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}
