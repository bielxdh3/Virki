import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const command = process.argv[2];
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const prismaCli = createRequire(import.meta.url).resolve("prisma/build/index.js");
const schemaPath = path.join(workspaceRoot, "prisma", "schema.prisma");
const commands = new Map([
  ["dev", ["migrate", "dev"]],
  ["deploy", ["migrate", "deploy"]],
  ["status", ["migrate", "status"]],
  ["push", ["db", "push"]],
  ["resolve-baseline", ["migrate", "resolve", "--applied", "0_init"]],
  ["verify-schema", ["migrate", "diff", "--from-schema-datasource", schemaPath, "--to-schema-datamodel", schemaPath, "--exit-code"]]
]);
const args = commands.get(command);
if (!args) {
  console.error("Prisma schema command is invalid.");
  process.exit(1);
}
if (process.env.NODE_ENV === "production" && !["deploy", "status", "resolve-baseline", "verify-schema"].includes(command)) {
  console.error("Prisma development schema commands are disabled in production.");
  process.exit(1);
}
const migrationUrl = process.env.MIGRATION_DATABASE_URL?.trim();
if (!migrationUrl || !isMigratorUrl(migrationUrl)) {
  console.error("MIGRATION_DATABASE_URL must use the virki_migrator database role.");
  process.exit(1);
}
const auditRetentionDays = command === "deploy" ? readAuditRetentionDays(process.env.AUDIT_LOG_RETENTION_DAYS) : null;
if (command === "deploy" && auditRetentionDays === null) {
  console.error("AUDIT_LOG_RETENTION_DAYS must be an integer between 1 and 3650.");
  process.exit(1);
}
const prismaArgs = command === "verify-schema" ? args : [...args, "--schema", schemaPath];
const result = spawnSync(process.execPath, [prismaCli, ...prismaArgs], {
  cwd: workspaceRoot,
  env: { ...process.env, DATABASE_URL: migrationUrl },
  stdio: "inherit",
  windowsHide: true
});

let exitCode = result.status ?? 1;
if (result.error) {
  console.error("Prisma schema command could not start.");
  exitCode = 1;
}

if (command === "deploy" && exitCode === 0) {
  const reconcileAuditRetention = spawnSync(process.execPath, [prismaCli, "db", "execute", "--stdin", "--schema", schemaPath], {
    cwd: workspaceRoot,
    env: { ...process.env, DATABASE_URL: migrationUrl },
    input: `DO $virki$\nDECLARE\n  updated_rows bigint;\nBEGIN\n  IF to_regclass('virki_security.audit_retention_policy') IS NULL THEN\n    RAISE EXCEPTION 'Virki audit retention policy is missing after migrations';\n  END IF;\n\n  UPDATE virki_security.audit_retention_policy\n  SET retention_days = ${auditRetentionDays}\n  WHERE singleton = true;\n  GET DIAGNOSTICS updated_rows = ROW_COUNT;\n\n  IF updated_rows <> 1 THEN\n    RAISE EXCEPTION 'Virki audit retention policy must contain exactly one singleton row';\n  END IF;\nEND\n$virki$;`,
    stdio: ["pipe", "inherit", "inherit"],
    windowsHide: true
  });
  if (reconcileAuditRetention.error || reconcileAuditRetention.status !== 0) {
    console.error("Virki audit retention policy could not be reconciled by the migration role after schema deployment.");
    exitCode = 1;
  }
}

if (["dev", "deploy", "resolve-baseline"].includes(command)) {
  const restrictMigrationLedger = spawnSync(process.execPath, [prismaCli, "db", "execute", "--stdin", "--schema", schemaPath], {
    cwd: workspaceRoot,
    env: { ...process.env, DATABASE_URL: migrationUrl },
    input: `DO $virki$ BEGIN
  IF to_regclass('public."_prisma_migrations"') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public."_prisma_migrations" FROM PUBLIC, virki_runtime';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
      EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public."_prisma_migrations" FROM virki_runtime_test';
    END IF;
  END IF;
END $virki$;`,
    stdio: ["pipe", "inherit", "inherit"],
    windowsHide: true
  });
  if (restrictMigrationLedger.error || restrictMigrationLedger.status !== 0) {
    console.error("Prisma migration ledger privileges could not be restricted after the schema command.");
    exitCode = 1;
  }
}

process.exitCode = exitCode;

function isMigratorUrl(value) {
  try {
    const url = new URL(value);
    return ["postgres:", "postgresql:"].includes(url.protocol) && decodeURIComponent(url.username) === "virki_migrator" && Boolean(url.password && url.hostname && url.pathname.length > 1);
  } catch {
    return false;
  }
}

function readAuditRetentionDays(value) {
  const normalized = value?.trim() || "180";
  if (!/^\d{1,4}$/u.test(normalized)) return null;
  const days = Number(normalized);
  return Number.isInteger(days) && days >= 1 && days <= 3650 ? days : null;
}
