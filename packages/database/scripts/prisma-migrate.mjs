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
  console.error("MIGRATION_DATABASE_URL must use the bielos_migrator database role.");
  process.exit(1);
}
const prismaArgs = command === "verify-schema" ? args : [...args, "--schema", schemaPath];
const result = spawnSync(process.execPath, [prismaCli, ...prismaArgs], {
  cwd: workspaceRoot,
  env: { ...process.env, DATABASE_URL: migrationUrl },
  stdio: "inherit",
  windowsHide: true
});

if (result.error) {
  console.error("Prisma schema command could not start.");
  process.exit(1);
}
process.exitCode = result.status ?? 1;

function isMigratorUrl(value) {
  try {
    const url = new URL(value);
    return ["postgres:", "postgresql:"].includes(url.protocol) && decodeURIComponent(url.username) === "bielos_migrator" && Boolean(url.password && url.hostname && url.pathname.length > 1);
  } catch {
    return false;
  }
}
