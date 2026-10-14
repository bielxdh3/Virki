// Verifies the Prisma migration wrapper refuses unsafe commands before Prisma or any database is contacted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const guard = path.join(root, "packages", "database", "scripts", "prisma-migrate.mjs");
// Port 1 on loopback is never listening; these URLs are only inspected by the guard, never connected to.
const migratorUrl = "postgresql://virki_migrator:placeholder@127.0.0.1:1/virki_guard_test?schema=public";
const runtimeUrl = "postgresql://virki_runtime:placeholder@127.0.0.1:1/virki_guard_test?schema=public";

function runGuard(command, { nodeEnv, migrationUrl }) {
  const env = { ...process.env };
  delete env.DATABASE_URL;
  delete env.MIGRATION_DATABASE_URL;
  delete env.NODE_ENV;
  if (nodeEnv !== undefined) env.NODE_ENV = nodeEnv;
  if (migrationUrl !== undefined) env.MIGRATION_DATABASE_URL = migrationUrl;
  return spawnSync(process.execPath, [guard, command], { cwd: root, encoding: "utf8", env, timeout: 30_000, windowsHide: true });
}

for (const command of ["push", "dev"]) {
  test(`production refuses prisma ${command} before attempting Prisma`, () => {
    const result = runGuard(command, { nodeEnv: "production", migrationUrl: migratorUrl });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "", "Prisma must not produce output for a refused command.");
    assert.equal(result.stderr.trim(), "Prisma development schema commands are disabled in production.");
  });
}

test("non-migrator database role is refused outside production", () => {
  const result = runGuard("deploy", { nodeEnv: "test", migrationUrl: runtimeUrl });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr.trim(), "MIGRATION_DATABASE_URL must use the virki_migrator database role.");
});

test("missing migration URL is refused outside production", () => {
  const result = runGuard("status", { nodeEnv: "test", migrationUrl: undefined });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), "MIGRATION_DATABASE_URL must use the virki_migrator database role.");
});

test("invalid schema command is refused", () => {
  const result = runGuard("reset", { nodeEnv: "test", migrationUrl: migratorUrl });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), "Prisma schema command is invalid.");
});
