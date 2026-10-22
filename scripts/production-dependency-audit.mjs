import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const forbiddenPackages = ["prisma", "@prisma/config", "deepmerge-ts"];
const npmOmitArgs = ["--omit=dev", "--omit=peer", "--omit=optional"];
const severityKeys = ["info", "low", "moderate", "high", "critical"];
const PRODUCTION_NPM_TIMEOUT_MS = 45_000;

export function npmProductionArguments() {
  return {
    audit: ["audit", ...npmOmitArgs, "--json", "--fetch-retries=0", "--fetch-timeout=25000"],
    ls: ["ls", ...npmOmitArgs, "--all", "--json"]
  };
}

const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const unavailable = (reason) => ({ status: "unavailable", reason });

// npm audit returns status 1 for real findings as well as for registry failures.
// Interpret the complete report before distinguishing those cases. Never emit
// stdout/stderr from npm: it can contain private registry endpoints or tokens.
export function interpretProductionNpmResult(kind, result) {
  if (kind !== "audit" && kind !== "ls") throw new TypeError("Unknown production npm command.");
  if (result?.error) {
    return unavailable(result.error.code === "ETIMEDOUT" ? "process-timeout" : "execution-error");
  }
  if (typeof result?.stdout !== "string" || !result.stdout.trim()) return unavailable("empty-output");
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    return unavailable("invalid-json");
  }
  if (!record(report)) return unavailable("invalid-report");
  if (Object.hasOwn(report, "error")) {
    if (kind === "ls") {
      return unavailable(report.error?.code === "ELSPROBLEMS" ? "invalid-dependency-tree" : "tree-command-error");
    }
    const networkCodes = ["FETCH_ERROR", "ENOTFOUND", "ETIMEDOUT", "ECONNRESET", "EAI_AGAIN", "E401", "E403"];
    return unavailable(networkCodes.includes(report.error?.code) ? "registry-or-network-error" : "audit-command-error");
  }

  if (kind === "ls") {
    if (result.status !== 0) return unavailable("unexpected-exit");
    if (typeof result.stderr === "string" && result.stderr.trim()) return unavailable("command-stderr");
    if (typeof report.name !== "string" || !report.name.trim() || !record(report.dependencies)) {
      return unavailable("invalid-tree");
    }
    const names = new Set();
    if (!readDependencyTree(report, names)) return unavailable("invalid-tree");
    return { status: "reported", names };
  }

  // JSON cannot override a contradictory npm stderr diagnostic.
  if (typeof result.stderr === "string" && result.stderr.trim()) return unavailable("command-stderr");

  const counts = report?.metadata?.vulnerabilities;
  if (report.auditReportVersion !== 2 || !record(counts) || !record(report.vulnerabilities) ||
      [...severityKeys, "total"].some((key) => !Number.isSafeInteger(counts[key]) || counts[key] < 0)) {
    return unavailable("invalid-report");
  }
  const summed = severityKeys.reduce((total, severity) => total + counts[severity], 0);
  const entries = Object.entries(report.vulnerabilities);
  if (summed !== counts.total || entries.length !== counts.total ||
      entries.some(([name, value]) =>
        !name || !record(value) || value.name !== name || !severityKeys.includes(value.severity))) {
    return unavailable("invalid-report");
  }
  if (result.status !== 0 && result.status !== 1) return unavailable("unexpected-exit");
  if (result.status === 1 && counts.total === 0) return unavailable("unexpected-exit");
  // Only validated counts leave the parser. Raw advisory entries and npm output
  // must never be included in the JSON result.
  return { status: "reported", counts: Object.fromEntries([...severityKeys, "total"].map((key) => [key, counts[key]])) };
}

function readDependencyTree(root, names) {
  const pending = [root];
  while (pending.length > 0) {
    const node = pending.pop();
    if (!record(node) || Object.hasOwn(node, "error") ||
        ["invalid", "missing", "extraneous"].some((flag) => Boolean(node[flag])) ||
        (Object.hasOwn(node, "problems") &&
          (!Array.isArray(node.problems) || node.problems.length !== 0))) return false;
    if (node.dependencies === undefined) continue;
    if (!record(node.dependencies)) return false;
    for (const [name, child] of Object.entries(node.dependencies)) {
      if (!name || !record(child)) return false;
      // npm ls can include {} placeholders for omitted peer dependencies.
      // They are not installed: verify actual package directories separately.
      if (Object.keys(child).length > 0) names.add(name);
      pending.push(child);
    }
  }
  return true;
}

export function evaluateProductionDependencies({
  audit, tree, requiredClient, physicalForbidden, prismaBinaryFound
}) {
  const errors = [];
  if (audit?.status !== "reported") {
    errors.push(`npm audit unavailable (${audit?.reason ?? "missing-result"}).`);
  } else if (audit.counts.total !== 0) {
    errors.push("The production dependency audit reported one or more vulnerabilities.");
  }
  if (tree?.status !== "reported") errors.push(`npm ls unavailable (${tree?.reason ?? "missing-result"}).`);
  if (!requiredClient || (tree?.status === "reported" && !tree.names.has("@prisma/client"))) {
    errors.push("@prisma/client is missing from the production tree.");
  }
  const forbidden = forbiddenPackages.filter((name) =>
    physicalForbidden.includes(name) || (tree?.status === "reported" && tree.names.has(name))
  );
  if (forbidden.length > 0 || prismaBinaryFound) {
    errors.push("Prisma tooling is reachable from the production tree.");
  }
  return {
    status: errors.length === 0 ? "passed" : "failed",
    productionTree: tree?.status === "reported",
    requiredClient: Boolean(requiredClient),
    forbiddenPackages: forbidden,
    prismaBinary: Boolean(prismaBinaryFound),
    vulnerabilities: audit?.status === "reported" ? audit.counts : null,
    errors
  };
}

function runProductionCommand(args, kind) {
  const result = spawnSync(npmCommand, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    shell: process.platform === "win32",
    windowsHide: true,
    maxBuffer: 20 * 1024 * 1024,
    timeout: PRODUCTION_NPM_TIMEOUT_MS,
    killSignal: "SIGTERM"
  });
  return interpretProductionNpmResult(kind, result);
}

function runProductionAudit() {
  const args = npmProductionArguments();
  const audit = runProductionCommand(args.audit, "audit");
  const tree = runProductionCommand(args.ls, "ls");
  const moduleRoots = findNodeModulesRoots(repositoryRoot);
  const physicalForbidden = forbiddenPackages.filter((name) =>
    moduleRoots.some((root) => existsSync(packagePath(root, name)))
  );
  return evaluateProductionDependencies({
    audit,
    tree,
    requiredClient: moduleRoots.some((root) => existsSync(packagePath(root, "@prisma/client/package.json"))),
    physicalForbidden,
    prismaBinaryFound: moduleRoots.some((root) => existsSync(path.join(root, ".bin", "prisma")))
  });
}

function packagePath(root, name) {
  return path.join(root, ...name.split("/"));
}

function findNodeModulesRoots(root) {
  const roots = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      if ([".git", ".next", "build", "coverage", "dist", "out"].includes(entry.name)) continue;
      const child = path.join(current, entry.name);
      if (entry.name === "node_modules") roots.push(child);
      pending.push(child);
    }
  }
  return roots;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = runProductionAudit();
    console.log(JSON.stringify(result, null, 2));
    if (result.status !== "passed") process.exitCode = 1;
  } catch {
    console.log(JSON.stringify({ status: "failed", errors: ["Production dependency inspection failed."] }));
    process.exitCode = 1;
  }
}
