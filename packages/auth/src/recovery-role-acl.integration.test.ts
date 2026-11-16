import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { integrationOptions } from "./integration-fixtures";

after(() => prisma.$disconnect());

test("PostgreSQL 18: RecoveryEmailRebind ownership and role ACLs survive committed migrations", integrationOptions, async () => {
  const rows = await prisma.$queryRaw<Array<{
    owner: string;
    runtimeRead: boolean;
    runtimeWrite: boolean;
    testRead: boolean;
    testWrite: boolean;
    maintenanceRead: boolean;
    maintenanceWrite: boolean;
    worldPrivilege: boolean;
  }>>`
    SELECT
      tables.tableowner AS owner,
      has_table_privilege('virki_runtime', 'public."RecoveryEmailRebind"', 'SELECT') AS "runtimeRead",
      (has_table_privilege('virki_runtime', 'public."RecoveryEmailRebind"', 'INSERT')
       AND has_table_privilege('virki_runtime', 'public."RecoveryEmailRebind"', 'UPDATE')
       AND has_table_privilege('virki_runtime', 'public."RecoveryEmailRebind"', 'DELETE')) AS "runtimeWrite",
      has_table_privilege('virki_runtime_test', 'public."RecoveryEmailRebind"', 'SELECT') AS "testRead",
      (has_table_privilege('virki_runtime_test', 'public."RecoveryEmailRebind"', 'INSERT')
       AND has_table_privilege('virki_runtime_test', 'public."RecoveryEmailRebind"', 'UPDATE')
       AND has_table_privilege('virki_runtime_test', 'public."RecoveryEmailRebind"', 'DELETE')) AS "testWrite",
      has_table_privilege('virki_audit_maintenance', 'public."RecoveryEmailRebind"', 'SELECT') AS "maintenanceRead",
      (has_table_privilege('virki_audit_maintenance', 'public."RecoveryEmailRebind"', 'INSERT')
       OR has_table_privilege('virki_audit_maintenance', 'public."RecoveryEmailRebind"', 'UPDATE')
       OR has_table_privilege('virki_audit_maintenance', 'public."RecoveryEmailRebind"', 'DELETE')) AS "maintenanceWrite",
      EXISTS (
        SELECT 1 FROM aclexplode((SELECT relacl FROM pg_class WHERE oid = 'public."RecoveryEmailRebind"'::regclass))
        WHERE grantee = 0
      ) AS "worldPrivilege"
    FROM pg_tables AS tables
    WHERE tables.schemaname = 'public' AND tables.tablename = 'RecoveryEmailRebind'
  `;
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0], {
    owner: "virki_migrator",
    runtimeRead: true,
    runtimeWrite: true,
    testRead: true,
    testWrite: true,
    maintenanceRead: false,
    maintenanceWrite: false,
    worldPrivilege: false
  });
});
