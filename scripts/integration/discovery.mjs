import { readdirSync } from "node:fs";
import path from "node:path";

const dedicatedSuites = new Map([
  ["packages/oidc-node/src/postgres-store.integration.test.ts", "npm run test:oidc-node:postgres"]
]);

function dedicatedRunner(file) {
  // Windows filesystem lookup is case-insensitive; normalize aliases before fencing.
  const normalized = path.posix.normalize(String(file).replace(/\\/gu, "/")).toLowerCase();
  for (const [suite, runner] of dedicatedSuites) {
    if (normalized === suite || normalized.endsWith(`/${suite}`)) return runner;
  }
  return null;
}

export function discoverGenericIntegrationTests(root) {
  function walk(directory) {
    return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      if (entry.name === "node_modules" || entry.name.startsWith(".")) return [];
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) return walk(full);
      return entry.name.endsWith(".integration.test.ts") ? [path.relative(root, full).split(path.sep).join("/")] : [];
    });
  }
  return ["apps", "packages"].flatMap((directory) => walk(path.join(root, directory)))
    .filter((file) => !dedicatedRunner(file)).sort();
}

export function assertGenericIntegrationSelection(files) {
  for (const file of files) {
    const runner = dedicatedRunner(file);
    if (runner) throw new Error(`Integration suite requires dedicated PostgreSQL 18 runner: ${runner}`);
  }
}
