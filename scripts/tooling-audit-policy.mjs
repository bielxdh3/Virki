import { readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const EXPECTED_TOOLING_VERSIONS = {
  prisma: "6.19.3",
  "@prisma/client": "6.19.3",
  "@prisma/config": "6.19.3",
  "deepmerge-ts": "8.0.2"
};

const expectedCounts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
const expectedVulnerabilities = {};
const AUDIT_PROCESS_TIMEOUT_MS = 45_000;
const severityKeys = Object.keys(expectedCounts);

export function evaluateToolingAudit(audit, { versions = EXPECTED_TOOLING_VERSIONS, productionReachable = false } = {}) {
  const errors = [];
  const counts = audit?.metadata?.vulnerabilities;
  const vulnerabilities = audit?.vulnerabilities;

  if (productionReachable) errors.push("The tooling advisory is reachable from the production tree.");
  if (audit?.auditReportVersion !== 2) errors.push("Unexpected npm audit report version.");
  if (stable(counts) !== stable(expectedCounts)) errors.push("The tooling dependency audit found vulnerabilities.");
  if (stable(vulnerabilities) !== stable(expectedVulnerabilities)) errors.push("The tooling dependency audit returned vulnerability entries.");
  if (stable(versions) !== stable(EXPECTED_TOOLING_VERSIONS)) errors.push("Prisma tooling versions drifted from the pinned versions.");
  return { ok: errors.length === 0, status: errors.length === 0 ? "passed" : "failed", errors };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // A fixture path in an inherited environment must never bypass the live
  // registry audit gate. Deterministic tests call the pure exported parser.
  const execution = runAudit();
  if (execution.status !== "reported") {
    console.log(JSON.stringify({ ok: false, status: "unavailable", reason: execution.reason }));
    process.exitCode = 1;
  } else {
    const versions = readCurrentVersions();
    const output = summarizeToolingAuditReport(execution.report, versions);
    console.log(JSON.stringify(output));
    if (!output.ok) process.exitCode = 1;
  }
}

export function summarizeToolingAuditReport(report, versions) {
  const result = evaluateToolingAudit(report, { versions });
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
export function npmAuditArguments() {
  // Disable retry/backoff amplification; do NOT suppress audit or substitute
  // cached/fixture findings. An inaccessible registry must fail closed.
  return ["audit", "--package-lock-only", "--json", "--fetch-retries=0", "--fetch-timeout=25000"];
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

function runAudit() {
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  const result = spawnSync(npmCommand, npmAuditArguments(), {
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
