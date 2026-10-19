import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { inspectInventoryPrivilegeSnapshot, validateInventoryPrivilegeSnapshot } from "../../../scripts/legacy-data-inventory";
import { integrationOptions } from "./integration-fixtures";

after(() => prisma.$disconnect());

test("inventory privilege SQL identifies and rejects the disposable application role's extra public access", integrationOptions, async () => {
  const snapshot = await prisma.$transaction(async (transaction) => {
    await transaction.$executeRawUnsafe("SET TRANSACTION READ ONLY");
    return inspectInventoryPrivilegeSnapshot(transaction);
  }, { maxWait: 10_000, timeout: 30_000 });

  assert.ok(snapshot.relations.some((relation) => relation.name === "AuditLog" && relation.hasAnyPrivilege));
  assert.throws(() => validateInventoryPrivilegeSnapshot(snapshot), /privilege boundary/u);
});
