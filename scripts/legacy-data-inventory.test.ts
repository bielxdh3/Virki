import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  parseInventoryArguments,
  summarizeEmailInventory,
  validateConnectedServerAddress,
  validateConnectedServerPort,
  validateInventoryCanonicalEmailIndex,
  validateInventoryMigrationSet,
  validateInventoryPrivilegeSnapshot,
  validateInventoryTarget,
  inspectInventoryPrivilegeSnapshot,
  hashInventoryMigrationSql,
  type InventoryPrivilegeSnapshot
} from "./legacy-data-inventory";

const inventoryTableNames = [
  "User",
  "Session",
  "SecurityElevation",
  "UserProjectGrant",
  "AccountRecoveryRequest",
  "EmailOutboxMessage",
  "ProjectConnection",
  "_prisma_migrations"
];

function validInventoryPrivilegeSnapshot(): InventoryPrivilegeSnapshot {
  return {
    relations: [
      ...inventoryTableNames.map((name) => ({
        name,
        kind: "r",
        canSelect: true,
        hasAnyPrivilege: true,
        hasWritePrivilege: false,
        hasAnyColumnPrivilege: true,
        hasColumnWritePrivilege: false,
        rowSecurityEnabled: false,
        ownedByCurrentRole: false
      })),
      {
        name: "AuditLog",
        kind: "r",
        canSelect: false,
        hasAnyPrivilege: false,
        hasWritePrivilege: false,
        hasAnyColumnPrivilege: false,
        hasColumnWritePrivilege: false,
        rowSecurityEnabled: false,
        ownedByCurrentRole: false
      }
    ],
    sequences: [{ name: "User_id_seq", hasAnyPrivilege: false, ownedByCurrentRole: false }],
    functions: [{ name: "virki_audit_cleanup", canExecute: false, ownedByCurrentRole: false }],
    schemas: [
      { name: "public", canUse: true, canCreate: false, ownedByCurrentRole: false },
      { name: "information_schema", canUse: true, canCreate: false, ownedByCurrentRole: false },
      { name: "extensions", canUse: false, canCreate: false, ownedByCurrentRole: false }
    ],
    database: { canCreate: false, canCreateTemporaryObjects: false, ownedByCurrentRole: false },
    hasUnsafeDefaultPrivileges: false,
    ownsAnyDatabaseObject: false
  };
}

test("legacy inventory requires an explicit expected host, database, and confirmation", () => {
  assert.deepEqual(parseInventoryArguments([
    "--expected-host", "db.example.test",
    "--expected-port", "55401",
    "--expected-database", "virki",
    "--expected-server-address", "10.0.0.5",
    "--expected-server-port", "5432",
    "--confirm-target"
  ]), { expectedHost: "db.example.test", expectedPort: 55401, expectedDatabase: "virki", expectedServerAddress: "10.0.0.5", expectedServerPort: 5432 });
  assert.throws(() => parseInventoryArguments(["--expected-host", "db.example.test"]), /explicit target/u);
  for (const badPort of ["0", "65536", "-1", "123.5", "abc"]) {
    assert.throws(() => parseInventoryArguments([
      "--expected-host", "db.example.test", "--expected-port", badPort,
      "--expected-database", "virki", "--expected-server-address", "10.0.0.5",
      "--expected-server-port", "5432", "--confirm-target"
    ]), /explicit target/u);
  }
});

test("legacy inventory requires the connected PostgreSQL server address to match the approved target", () => {
  assert.equal(validateConnectedServerAddress("10.0.0.5", "10.0.0.5"), true);
  assert.throws(() => validateConnectedServerAddress("10.0.0.6", "10.0.0.5"), /server/u);
  assert.throws(() => validateConnectedServerAddress(null, "10.0.0.5"), /server/u);
  assert.equal(validateConnectedServerPort(5432, 5432), true);
  assert.throws(() => validateConnectedServerPort(55401, 5432), /server/u);
  assert.throws(() => validateConnectedServerPort(null, 5432), /server/u);
});

test("legacy inventory checks configured database host and name without returning them", () => {
  assert.equal(validateInventoryTarget("postgresql://reader@DB.example.test:5432/virki", "db.example.test", "virki", 5432), true);
  assert.equal(validateInventoryTarget("postgresql://reader@[2001:db8::5]:5432/virki", "2001:db8::5", "virki", 5432), true);
  assert.throws(() => validateInventoryTarget("postgresql://reader@other.example.test:5432/virki", "db.example.test", "virki", 5432), /target/u);
  assert.throws(() => validateInventoryTarget("postgresql://reader@db.example.test:5432/other", "db.example.test", "virki", 5432), /target/u);
  assert.throws(() => validateInventoryTarget("postgresql://reader@db.example.test:55402/virki", "db.example.test", "virki", 55401), /target/u);
  assert.equal(validateInventoryTarget("postgresql://reader@db.example.test/virki", "db.example.test", "virki", 5432), true);
});

test("schema privilege discovery does not hide ordinary schemas starting with pg", async () => {
  const sqlQueries: string[] = [];
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray) => {
      const sql = strings.join("");
      sqlQueries.push(sql);
      if (sql.includes('"hasUnsafeDefaultPrivileges"')) {
        return [{ hasUnsafeDefaultPrivileges: false, ownsAnyDatabaseObject: false }];
      }
      if (sql.includes('"canCreateTemporaryObjects"')) {
        return [{ canCreate: false, canCreateTemporaryObjects: false, ownedByCurrentRole: false }];
      }
      return [];
    }
  };
  await inspectInventoryPrivilegeSnapshot(transaction as never);
  const schemaSql = sqlQueries.find((sql) => sql.includes("FROM pg_namespace n"));
  assert.ok(schemaSql);
  assert.match(schemaSql, /left\(n\.nspname,\s*3\)\s*<>\s*'pg_'/u);
});

test("legacy schema preflight rejects a missing or weakened canonical email unique index", () => {
  const valid = {
    columnName: "emailNormalized", isUnique: true, isValid: true, isReady: true,
    keyColumns: 1, totalColumns: 1, noPredicate: true, noExpressions: true
  };
  assert.equal(validateInventoryCanonicalEmailIndex([valid]), true);
  assert.throws(() => validateInventoryCanonicalEmailIndex([]), /schema/u);
  assert.throws(() => validateInventoryCanonicalEmailIndex([valid, valid]), /schema/u);
  for (const changed of [
    { columnName: "email" }, { isUnique: false }, { isValid: false }, { isReady: false },
    { keyColumns: 2 }, { totalColumns: 2 }, { noPredicate: false }, { noExpressions: false }
  ]) {
    assert.throws(() => validateInventoryCanonicalEmailIndex([{ ...valid, ...changed }]), /schema/u);
  }
});

test("legacy inventory permits only table SELECT on the eight allowlisted relations", () => {
  assert.equal(validateInventoryPrivilegeSnapshot(validInventoryPrivilegeSnapshot()), true);

  const extraPublicSelect = validInventoryPrivilegeSnapshot();
  extraPublicSelect.relations[8]!.canSelect = true;
  extraPublicSelect.relations[8]!.hasAnyPrivilege = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(extraPublicSelect), /privilege boundary/u);

  const extraPublicWrite = validInventoryPrivilegeSnapshot();
  extraPublicWrite.relations[8]!.hasWritePrivilege = true;
  extraPublicWrite.relations[8]!.hasAnyPrivilege = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(extraPublicWrite), /privilege boundary/u);
});

test("legacy inventory rejects column grants, sequences, routines, and default ACLs outside its data path", () => {
  const columnOnlyRead = validInventoryPrivilegeSnapshot();
  columnOnlyRead.relations[8]!.hasAnyColumnPrivilege = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(columnOnlyRead), /privilege boundary/u);

  const columnWrite = validInventoryPrivilegeSnapshot();
  columnWrite.relations[0]!.hasColumnWritePrivilege = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(columnWrite), /privilege boundary/u);

  const sequenceAccess = validInventoryPrivilegeSnapshot();
  sequenceAccess.sequences[0]!.hasAnyPrivilege = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(sequenceAccess), /privilege boundary/u);

  const routineAccess = validInventoryPrivilegeSnapshot();
  routineAccess.functions[0]!.canExecute = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(routineAccess), /privilege boundary/u);

  const defaultGrant = validInventoryPrivilegeSnapshot();
  defaultGrant.hasUnsafeDefaultPrivileges = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(defaultGrant), /privilege boundary/u);
});

test("legacy inventory rejects extra schema, ownership, database DDL, RLS, and incomplete table grants", () => {
  const extraSchema = validInventoryPrivilegeSnapshot();
  extraSchema.schemas[2]!.canUse = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(extraSchema), /privilege boundary/u);

  const ownedObject = validInventoryPrivilegeSnapshot();
  ownedObject.ownsAnyDatabaseObject = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(ownedObject), /privilege boundary/u);

  const tempDatabasePrivilege = validInventoryPrivilegeSnapshot();
  tempDatabasePrivilege.database.canCreateTemporaryObjects = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(tempDatabasePrivilege), /privilege boundary/u);

  const rlsRequiredTable = validInventoryPrivilegeSnapshot();
  rlsRequiredTable.relations[0]!.rowSecurityEnabled = true;
  assert.throws(() => validateInventoryPrivilegeSnapshot(rlsRequiredTable), /privilege boundary/u);

  const missingRead = validInventoryPrivilegeSnapshot();
  missingRead.relations[0]!.canSelect = false;
  assert.throws(() => validateInventoryPrivilegeSnapshot(missingRead), /privilege boundary/u);
});

test("email inventory follows normalizeEmail and returns aggregate collision counts only", () => {
  const result = summarizeEmailInventory([
    { email: " Alice@Example.Test ", emailNormalized: "alice@example.test" },
    { email: "alice@example.test", emailNormalized: "alice@example.test" },
    { email: "bob@example.test", emailNormalized: null },
    { email: "Carol@example.test", emailNormalized: "WRONG" },
    { email: "dave@example.test", emailNormalized: " \t" },
    { email: "\u00a0ÉXAMPLE@Example.Test\u00a0", emailNormalized: "éxample@example.test" }
  ]);
  assert.deepEqual(result, {
    totalUsers: 6,
    normalizedNull: 1,
    normalizedBlank: 1,
    normalizationMismatch: 2,
    collisionGroupCount: 1,
    collisionMemberCount: 2
  });
  assert.equal(JSON.stringify(result).includes("example.test"), false);
});

test("legacy inventory requires matching migration checksums, not only directory names", () => {
  const expected = [
    { name: "0_init", checksum: "a".repeat(64) },
    { name: "20261001000000_security_polish", checksum: "b".repeat(64) }
  ];
  const completed = expected.map(({ name, checksum }) => ({
    migrationName: name,
    checksum,
    finishedAt: new Date("2026-10-01T00:00:00Z"),
    rolledBackAt: null
  }));
  assert.equal(validateInventoryMigrationSet(completed, expected), 2);
  assert.throws(() => validateInventoryMigrationSet([
    { ...completed[0]!, checksum: "c".repeat(64) }, completed[1]!
  ], expected), /migration state/u);
  assert.throws(() => validateInventoryMigrationSet([
    completed[0]!, completed[0]!, completed[1]!
  ], expected), /migration state/u);
  assert.throws(() => validateInventoryMigrationSet([completed[0]!], expected), /migration state/u);
  assert.throws(() => validateInventoryMigrationSet([
    ...completed,
    { ...completed[0]!, migrationName: "unexpected", checksum: "d".repeat(64) }
  ], expected), /migration state/u);
  assert.throws(() => validateInventoryMigrationSet([
    { ...completed[0]!, finishedAt: null }, completed[1]!
  ], expected), /migration state/u);
  assert.throws(() => validateInventoryMigrationSet([
    { ...completed[0]!, rolledBackAt: new Date("2026-10-01T00:01:00Z") }, completed[1]!
  ], expected), /migration state/u);
  assert.equal(validateInventoryMigrationSet([
    { ...completed[0]!, finishedAt: null, rolledBackAt: new Date("2026-09-30T23:59:00Z") },
    ...completed
  ], expected), 2, "a resolved failed attempt may precede a valid completed migration");
});

test("migration checksum matches canonical Git LF bytes across Windows CRLF checkout", () => {
  const lf = Buffer.from("-- migration\nSELECT 1;\n", "utf8");
  const crlf = Buffer.from("-- migration\r\nSELECT 1;\r\n", "utf8");
  const expected = createHash("sha256").update(lf).digest("hex");
  assert.equal(hashInventoryMigrationSql(lf), expected);
  assert.equal(hashInventoryMigrationSql(crlf), expected);
  assert.notEqual(hashInventoryMigrationSql(Buffer.from("-- migration\nSELECT 2;\n")), expected);
  assert.throws(() => hashInventoryMigrationSql(Buffer.from("SELECT 1;\rSELECT 2;")), /migration/iu);
  assert.throws(() => hashInventoryMigrationSql(Buffer.from([0xff, 0xfe])), /migration/iu);
});
