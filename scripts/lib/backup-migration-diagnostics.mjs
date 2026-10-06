const schemaDirectories = {
  "source-legacy": "temporary/prisma",
  "source-transition": "temporary/prisma",
  "source-baseline": "repository/packages/database/prisma",
  restored: "repository/packages/database/prisma",
};
const processCodes = new Set(["ENOENT", "EACCES", "EPERM", "ETIMEDOUT", "ENOBUFS"]);

export function describeBackupMigrationFailure(result, stage) {
  const directory = Object.hasOwn(schemaDirectories, stage) ? schemaDirectories[stage] : "unknown";
  const details = {
    stage: directory === "unknown" ? "unknown" : stage,
    schema: `${directory}/schema.prisma`,
    migrations: `${directory}/migrations`,
    migration: extractMigrationName(result.stderr, result.stdout),
    exitStatus: Number.isInteger(result.status) ? result.status : null,
    processCode: processCodes.has(result.error?.code) ? result.error.code : result.error ? "unknown" : null,
    stdout: summarizeOutput(result.stdout),
    stderr: summarizeOutput(result.stderr),
  };
  return `Disposable backup migration deployment failed (${JSON.stringify(details)}).`;
}

function extractMigrationName(...streams) {
  for (const output of streams) {
    if (typeof output !== "string") continue;
    const match = output.match(/^\s*Migration name:\s*([0-9]{14}_[a-z0-9_]{1,80})\s*$/imu);
    if (match) return match[1];
  }
  return null;
}

function summarizeOutput(output) {
  if (typeof output !== "string" || output.length === 0) return "empty";
  // Emit only structured codes and a fixed known failure description. Raw CLI
  // output can contain connection strings, SQL data, and operator-specific paths.
  const prismaCode = output.match(/^\s*(?:Error(?: code)?:\s*)?(P\d{4})\b/mu)?.[1];
  const sqlState = output.match(/^\s*(?:Database error code:|SQLSTATE[\s:]+)\s*([0-9A-Z]{5})\b/imu)?.[1];
  const missingRole = output.includes("bielos_audit_maintenance must be provisioned before applying AuditLog privilege boundaries");
  return [
    prismaCode && `Prisma=${prismaCode}`,
    sqlState && `SQLSTATE=${sqlState.toUpperCase()}`,
    missingRole && "audit-maintenance role missing",
    "other output redacted",
  ].filter(Boolean).join("; ");
}
