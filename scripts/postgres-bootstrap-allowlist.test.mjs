import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("PostgreSQL bootstrap allowlist accepts every table introduced by committed migrations", () => {
  const bootstrap = readFileSync(path.join(root, "infra/postgres-init/10-virki-database-roles.sh"), "utf8");
  const start = bootstrap.indexOf("AND relation.relname NOT IN (");
  assert.ok(start >= 0, "bootstrap must retain its explicit public-schema allowlist");
  const end = bootstrap.indexOf(")\n      AND NOT EXISTS", start);
  assert.ok(end > start, "bootstrap must retain the extension exclusion");
  const allowed = new Set([...bootstrap.slice(start, end).matchAll(/'([^']+)'/gu)].map((match) => match[1]));

  const migrations = path.join(root, "packages/database/prisma/migrations");
  const created = new Set();
  for (const migration of readdirSync(migrations, { withFileTypes: true })) {
    if (!migration.isDirectory()) continue;
    const sql = readFileSync(path.join(migrations, migration.name, "migration.sql"), "utf8");
    for (const match of sql.matchAll(/\bCREATE TABLE(?: IF NOT EXISTS)?\s+(?:public\.)?"([^"]+)"/gu)) {
      created.add(match[1]);
    }
  }
  assert.deepEqual([...created].filter((name) => !allowed.has(name)).sort(), [],
    "schema upgrades must not make bootstrap role reconciliation reject legitimate Virki tables");
});
