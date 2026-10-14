// Fails when a test file exists in the repository but no runner references it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const testRoots = ["apps", "packages", "scripts", "e2e"];
const skippedDirectories = new Set(["node_modules", ".next", "dist", "build", "coverage"]);
const testFilePattern = /\.(test|spec)\.(ts|tsx|mjs|mts)$/;
// Discovered by scripts/integration/run.mjs, which scans apps/ and packages/ only.
const integrationFilePattern = /\.integration\.test\.ts$/;
// Executed by the Playwright configuration (testDir: ./e2e).
const playwrightSpecPattern = /^e2e\/.*\.spec\.(ts|tsx|mjs|mts)$/;
// Each entry must name a file and give a one-line reason it cannot run in a runner above.
const intentionallyExcluded = [];

function collectTestFiles(directory, found) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (skippedDirectories.has(entry.name) || entry.name.startsWith(".")) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) collectTestFiles(full, found);
    else if (entry.isFile() && testFilePattern.test(entry.name)) found.push(path.relative(root, full).split(path.sep).join("/"));
  }
  return found;
}

function referencedPaths() {
  const sources = [
    readFileSync(path.join(root, "package.json"), "utf8"),
    readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8")
  ];
  return new Set(sources.join("\n").split(/[\s"'`,]+/).map((token) => token.replace(/^\.\//u, "")));
}

const testFiles = testRoots.flatMap((directory) => collectTestFiles(path.join(root, directory), [])).sort();

test("test inventory discovers the repository test files", () => {
  assert.ok(testFiles.length > 0, "No test files were discovered.");
});

test("every test file is referenced by a root script or the CI workflow", () => {
  const references = referencedPaths();
  const excluded = new Set(intentionallyExcluded.map((entry) => entry.file));
  for (const entry of intentionallyExcluded) {
    assert.ok(entry.reason && entry.reason.length > 0, `Exclusion ${entry.file} needs a reason.`);
  }
  const unreferenced = testFiles.filter((file) => {
    if (integrationFilePattern.test(file) || playwrightSpecPattern.test(file) || excluded.has(file)) return false;
    return !references.has(file);
  });
  assert.deepEqual(
    unreferenced,
    [],
    `Test files not referenced by package.json scripts or .github/workflows/ci.yml:\n${unreferenced.join("\n")}`
  );
});

test("integration test files live where the integration runner discovers them", () => {
  const misplaced = testFiles.filter((file) => integrationFilePattern.test(file) && !/^(apps|packages)\//u.test(file));
  assert.deepEqual(misplaced, [], "Integration tests must live under apps/ or packages/.");
});

test("every workspace declares a typecheck script and the root typecheck names it", () => {
  const rootPackage = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const workspaceDirectories = ["apps", "packages"].flatMap((directory) =>
    readdirSync(path.join(root, directory), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(root, directory, entry.name))
  );
  const missing = [];
  const names = [];
  for (const directory of workspaceDirectories) {
    const manifest = path.join(directory, "package.json");
    let workspace;
    try {
      workspace = JSON.parse(readFileSync(manifest, "utf8"));
    } catch {
      continue;
    }
    names.push(workspace.name);
    if (typeof workspace.scripts?.typecheck !== "string") missing.push(workspace.name);
  }
  assert.deepEqual(missing, [], "Workspaces without a typecheck script.");
  const typecheck = rootPackage.scripts.typecheck;
  assert.ok(!/--if-present/u.test(typecheck), "Root typecheck must not skip workspaces silently.");
  for (const name of names) {
    assert.ok(typecheck.includes(`-w ${name}`), `Root typecheck does not cover ${name}.`);
  }
});
