// Runs generic *.integration.test.ts suites against an explicitly confirmed disposable PostgreSQL.
// Specialized PG18 OIDC tests require their own disposable provisioning runner.
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertGenericIntegrationSelection, discoverGenericIntegrationTests } from "./discovery.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const localEnvFile = path.join(os.tmpdir(), "virki-integration-database.env");

if (process.argv.includes("--local") && existsSync(localEnvFile)) {
  for (const line of readFileSync(localEnvFile, "utf8").split("\n")) {
    const separator = line.indexOf("=");
    if (separator > 0) process.env[line.slice(0, separator)] ??= line.slice(separator + 1);
  }
}

const requested = process.argv.slice(2).filter((argument) => !argument.startsWith("--"));
const files = requested.length > 0 ? requested : discoverGenericIntegrationTests(root);
try {
  assertGenericIntegrationSelection(files);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
if (files.length === 0) {
  console.error("No generic integration test files were found.");
  process.exit(1);
}

const databaseUrl = process.env.VIRKI_INTEGRATION_DATABASE_URL?.trim();
if (!databaseUrl || process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
  console.error("Integration tests require VIRKI_INTEGRATION_DATABASE_URL and VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable.");
  process.exit(1);
}
const parsed = new URL(databaseUrl);
if (parsed.hostname !== "127.0.0.1" || parsed.username !== "virki_runtime_test") {
  console.error("Integration tests only run against a loopback disposable database with the isolated test role.");
  process.exit(1);
}

const result = spawnSync(process.execPath, [path.join(root, "node_modules", "tsx", "dist", "cli.mjs"), "--test", "--test-concurrency=1", ...files], {
  cwd: root,
  env: {
    ...process.env,
    DATABASE_URL: databaseUrl,
    NODE_ENV: "test",
    VIRKI_INTEGRATION_ENABLED: "true",
    // Ephemeral, test-only values; the suite never sends mail or reaches a real host.
    VIRKI_PORTAL_URL: "http://localhost:3000",
    VIRKI_HUB_URL: "http://localhost:3001",
    VIRKI_OIDC_ADAPTER_KEY: process.env.VIRKI_OIDC_ADAPTER_KEY ?? randomBytes(32).toString("hex")
  },
  stdio: "inherit",
  windowsHide: true
});
process.exit(result.status ?? 1);
