import assert from "node:assert/strict";
import test from "node:test";
import { describeBackupMigrationFailure } from "./lib/backup-migration-diagnostics.mjs";

test("migration diagnostics retain stage, stable context and codes while redacting both streams", () => {
  const databaseUrl = ["postgresql:/", "/operator:", "fixture-password@private-host/database?token=fixture-token"].join("");
  const privateKeyMarker = ["-----BEGIN ", "PRIVATE KEY----- fixture-key-material"].join("");
  const privateDetails = [
    databaseUrl,
    "C:\\Users\\private-operator\\AppData\\Local\\Temp\\private-directory\\schema.prisma",
    "/home/private-operator/private-directory/schema.prisma",
    "password=fixture-password token=fixture-token",
    privateKeyMarker,
  ].join("\n");
  const diagnostic = describeBackupMigrationFailure({
    status: 1,
    stdout: `Error: P3018\n${privateDetails}`,
    stderr: `Migration name: 20261006120000_audit_log_role_boundaries\nDatabase error code: P0001\nERROR: bielos_audit_maintenance must be provisioned before applying AuditLog privilege boundaries\n${privateDetails}`,
    error: { code: "ETIMEDOUT", message: privateDetails, cause: new Error(privateDetails) },
  }, "source-transition");

  assert.match(diagnostic, /"stage":"source-transition"/u);
  assert.match(diagnostic, /"schema":"temporary\/prisma\/schema\.prisma"/u);
  assert.match(diagnostic, /"migrations":"temporary\/prisma\/migrations"/u);
  assert.match(diagnostic, /"migration":"20261006120000_audit_log_role_boundaries"/u);
  assert.match(diagnostic, /"exitStatus":1/u);
  assert.match(diagnostic, /"processCode":"ETIMEDOUT"/u);
  assert.match(diagnostic, /"stdout":"Prisma=P3018; other output redacted"/u);
  assert.match(diagnostic, /"stderr":"SQLSTATE=P0001; audit-maintenance role missing; other output redacted"/u);
  assert.doesNotMatch(diagnostic, /postgresql|operator|private-host|fixture-|Users|AppData|\/home|PRIVATE KEY/u);
});

test("repository stages use stable context and unknown values cannot expose raw errors", () => {
  for (const stage of ["source-baseline", "restored"]) {
    const diagnostic = describeBackupMigrationFailure({ status: 1, stdout: "unclassified private content", stderr: "" }, stage);
    assert.match(diagnostic, /"schema":"repository\/packages\/database\/prisma\/schema\.prisma"/u);
    assert.match(diagnostic, /"migrations":"repository\/packages\/database\/prisma\/migrations"/u);
    assert.match(diagnostic, /"migration":null/u);
    assert.match(diagnostic, /"stdout":"other output redacted","stderr":"empty"/u);
    assert.doesNotMatch(diagnostic, /unclassified private content/u);
  }
  const diagnostic = describeBackupMigrationFailure({ status: null, error: { code: "/private/error", message: "private error" } }, "/private/schema");
  assert.match(diagnostic, /"stage":"unknown"/u);
  assert.match(diagnostic, /"exitStatus":null,"processCode":"unknown"/u);
  assert.doesNotMatch(diagnostic, /private/u);
});
