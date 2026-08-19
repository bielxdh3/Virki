import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const forbiddenPackages = ["prisma", "@prisma/config", "deepmerge-ts"];

const npmOmitArgs = ["--omit=dev", "--omit=peer", "--omit=optional"];
const audit = runJson(["audit", ...npmOmitArgs, "--json"]);
const tree = runJson(["ls", ...npmOmitArgs, "--all", "--json"]);
const moduleRoots = findNodeModulesRoots(repositoryRoot);
const forbiddenPaths = moduleRoots.flatMap((root) =>
  forbiddenPackages
    .filter((name) => existsSync(packagePath(root, name)))
    .map((name) => `${root}/<${name}>`)
);
const prismaBinaryFound = moduleRoots.some((root) => existsSync(path.join(root, ".bin", "prisma")));
const treeNames = new Set();
collectDependencyNames(tree, treeNames);
const treeForbidden = forbiddenPackages.filter((name) => treeNames.has(name) && forbiddenPaths.some((entry) => entry.endsWith(`<${name}>`)));
const requiredClient = moduleRoots.some((root) => existsSync(packagePath(root, "@prisma/client/package.json")));
const counts = audit?.metadata?.vulnerabilities;
const vulnerabilities = audit?.vulnerabilities;
const auditClean = counts && counts.total === 0 && Object.keys(vulnerabilities ?? {}).length === 0;
const errors = [];

if (!requiredClient) errors.push("@prisma/client is missing from the production tree.");
if (forbiddenPaths.length > 0 || treeForbidden.length > 0 || prismaBinaryFound) {
  errors.push("Prisma tooling is reachable from the production tree.");
}
if (!auditClean) errors.push("The production dependency audit reported one or more vulnerabilities.");

const result = {
  status: errors.length === 0 ? "passed" : "failed",
  productionTree: true,
  requiredClient,
  forbiddenPackages: forbiddenPackages.filter((name) => forbiddenPaths.some((entry) => entry.endsWith(`<${name}>`)) || treeForbidden.includes(name)),
  prismaBinary: prismaBinaryFound,
  vulnerabilities: counts ?? null,
  errors
};
console.log(JSON.stringify(result, null, 2));
if (errors.length > 0) process.exitCode = 1;

function runJson(args) {
  const result = spawnSync(npmCommand, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    shell: process.platform === "win32",
    windowsHide: true,
    maxBuffer: 20 * 1024 * 1024
  });
  if (result.error || !result.stdout?.trim()) {
    console.log(JSON.stringify({ status: "failed", errors: ["A production dependency command did not produce JSON."] }));
    process.exit(1);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    console.log(JSON.stringify({ status: "failed", errors: ["A production dependency command produced invalid JSON."] }));
    process.exit(1);
  }
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

function collectDependencyNames(node, names) {
  for (const [name, dependency] of Object.entries(node?.dependencies ?? {})) {
    names.add(name);
    collectDependencyNames(dependency, names);
  }
}
