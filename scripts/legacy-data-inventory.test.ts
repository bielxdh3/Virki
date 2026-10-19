import assert from "node:assert/strict";
import test from "node:test";
import {
  parseInventoryArguments,
  summarizeEmailInventory,
  validateConnectedServerAddress,
  validateInventoryPrivilegeSnapshot,
  validateInventoryTarget,
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
    "--expected-database", "virki",
    "--expected-server-address", "10.0.0.5",
    "--confirm-target"
  ]), { expectedHost: "db.example.test", expectedDatabase: "virki", expectedServerAddress: "10.0.0.5" });
  assert.throws(() => parseInventoryArguments(["--expected-host", "db.example.test"]), /explicit target/u);
});

test("legacy inventory requires the connected PostgreSQL server address to match the approved target", () => {
  assert.equal(validateConnectedServerAddress("10.0.0.5", "10.0.0.5"), true);
  assert.throws(() => validateConnectedServerAddress("10.0.0.6", "10.0.0.5"), /server/u);
  assert.throws(() => validateConnectedServerAddress(null, "10.0.0.5"), /server/u);
});

test("legacy inventory checks configured database host and name without returning them", () => {
  assert.equal(validateInventoryTarget("postgresql://reader@DB.example.test:5432/virki", "db.example.test", "virki"), true);
  assert.equal(validateInventoryTarget("postgresql://reader@[2001:db8::5]:5432/virki", "2001:db8::5", "virki"), true);
  assert.throws(() => validateInventoryTarget("postgresql://reader@other.example.test:5432/virki", "db.example.test", "virki"), /target/u);
  assert.throws(() => validateInventoryTarget("postgresql://reader@db.example.test:5432/other", "db.example.test", "virki"), /target/u);
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
