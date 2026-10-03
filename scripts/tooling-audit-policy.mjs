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
  const audit = process.env.BIELOS_TOOLING_AUDIT_JSON
    ? JSON.parse(readFileSync(process.env.BIELOS_TOOLING_AUDIT_JSON, "utf8"))
    : runAudit();
  const versions = readCurrentVersions();
  const result = evaluateToolingAudit(audit, { versions });
  const output = result.ok ? result : {
    ...result,
    observed: {
      auditReportVersion: audit?.auditReportVersion ?? null,
      vulnerabilities: audit?.vulnerabilities ?? null,
      counts: audit?.metadata?.vulnerabilities ?? null,
      versions
    }
  };
  console.log(JSON.stringify(output, null, 2));
  if (!result.ok) process.exitCode = 1;
}

function runAudit() {
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  const result = spawnSync(npmCommand, ["audit", "--package-lock-only", "--json"], {
    cwd: path.resolve(fileURLToPath(new URL("..", import.meta.url))),
    encoding: "utf8",
    shell: process.platform === "win32",
    windowsHide: true,
    maxBuffer: 20 * 1024 * 1024
  });
  if (result.error || !result.stdout?.trim()) throw new Error("npm audit did not produce structured JSON.");
  return JSON.parse(result.stdout);
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
