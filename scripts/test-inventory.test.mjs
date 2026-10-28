// Fails when a test file exists in the repository but no runner references it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { discoverGenericIntegrationTests, assertGenericIntegrationSelection } from "./integration/discovery.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const testRoots = ["apps", "packages", "scripts", "e2e"];
const skippedDirectories = new Set(["node_modules", ".next", "dist", "build", "coverage"]);
const testFilePattern = /\.(test|spec)\.(ts|tsx|mjs|mts)$/;
// Located under apps/ and packages/; specialized integration suites use dedicated runners.
const integrationFilePattern = /\.integration\.test\.ts$/;
// Executed by the Playwright configuration (testDir: ./e2e).
const playwrightSpecPattern = /^e2e\/.*\.spec\.(ts|tsx|mjs|mts)$/;
// Each entry must name a file and give a one-line reason it cannot run in a runner above.
const intentionallyExcluded = [];

test("PG18 OIDC integration is isolated from generic discovery and explicit selection", () => {
  const dedicated = "packages/oidc-node/src/postgres-store.integration.test.ts";
  const files = discoverGenericIntegrationTests(root);
  assert.ok(files.includes("packages/auth/src/passkeys.integration.test.ts"), "ordinary suites must stay discoverable");
  assert.equal(files.includes(dedicated), false, "PG18 suite needs its separately provisioned runner");
  assert.throws(() => assertGenericIntegrationSelection([dedicated]), /dedicated PostgreSQL 18 runner/u);
  assert.throws(() => assertGenericIntegrationSelection([dedicated.replace(/\//gu, "\\")]), /dedicated PostgreSQL 18 runner/u);
  for (const alias of [
    "packages/oidc-node/src/../src/postgres-store.integration.test.ts",
    "packages//oidc-node/src/postgres-store.integration.test.ts",
    "packages/./oidc-node/src/postgres-store.integration.test.ts",
    "packages/OIDC-NODE/src/postgres-store.integration.test.ts"
  ]) {
    assert.throws(() => assertGenericIntegrationSelection([alias]), /dedicated PostgreSQL 18 runner/u,
      `generic runner must not accept PG18 path alias: ${alias}`);
  }
  assert.doesNotThrow(() => assertGenericIntegrationSelection(["packages/auth/src/passkeys.integration.test.ts"]));
});

test("excluded PG18 OIDC suite remains reachable through its owned disposable runner", () => {
  const scripts = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).scripts;
  assert.match(scripts["test:oidc-node:postgres"], /scripts\/oidc-node-disposable-postgres\.mjs/u);
  const dedicatedRunner = readFileSync(path.join(root, "scripts", "oidc-node-disposable-postgres.mjs"), "utf8");
  assert.match(dedicatedRunner, /postgres-store\.integration\.test\.ts/u);
  assert.match(dedicatedRunner, /VIRKI_OIDC_PG_CONTAINER/u);
});

test("generic integration CLI rejects explicit PG18 selection before requiring a database", () => {
  const dedicated = "packages/oidc-node/src/postgres-store.integration.test.ts";
  const cli = spawnSync(process.execPath, [path.join(root, "scripts", "integration", "run.mjs"), dedicated], {
    cwd: root,
    encoding: "utf8",
    timeout: 5_000,
    env: { ...process.env, VIRKI_INTEGRATION_DATABASE_URL: "", VIRKI_CORE_TEST_DATABASE_CONFIRM: "" }
  });
  assert.equal(cli.status, 1);
  assert.match(cli.stderr, /dedicated PostgreSQL 18 runner/u);
});

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

test("native Prisma DDL observation, P2 result, source and container tests are root-inventoried together", () => {
  const scripts = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).scripts;
  const unit = scripts["test:offline:prisma-native:unit"];
  for (const filename of [
    "scripts/offline-prisma-native-ddl-observation.test.mjs",
    "scripts/offline-prisma-native-container.test.mjs",
    "scripts/offline-prisma-native-source.test.mjs",
    "scripts/lib/offline-prisma-native-result.test.mjs",
  ]) assert.ok(unit.includes(filename), `missing from root native-Prisma unit inventory: ${filename}`);
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
