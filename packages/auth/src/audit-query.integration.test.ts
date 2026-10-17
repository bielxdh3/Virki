import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { prisma } from "@virki/database";
import { createAuditLogData, hashAuditIdentifier, writeAuditLogInTransaction, writeAuditLogRequired, runWithAuditContext } from "./audit";
import { buildAuditQuery, parseAuditFilters } from "./audit-query";
import { integrationOptions } from "./integration-fixtures";

test("structured audit persists/query filters, isolated correlation, UTC bounds and append-only role", integrationOptions, async () => {
  const resource = `test.${randomUUID()}`;
  const requestId = randomUUID();
  await runWithAuditContext({ requestId, service: "issuer", route: "/token", method: "POST" }, async () => {
    await writeAuditLogRequired({ eventType: "SSO_TOKEN_REJECTED", result: "DENIED", resource, metadata: { error: "invalid_grant", privatePayload: "private@example.invalid", password: "synthetic" } });
    await writeAuditLogRequired({ eventType: "SSO_TOKEN_ISSUED", result: "SUCCESS", resource });
  });
  const rows = await prisma.auditLog.findMany({ ...buildAuditQuery(parseAuditFilters({ resource, category: "SSO", result: "DENIED" })), select: { id: true, metadata: true, requestId: true, action: true, route: true, schemaVersion: true } });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].requestId, requestId);
  assert.equal(rows[0].schemaVersion, 1);
  assert.equal(rows[0].route, "/token");
  assert.equal(rows[0].action, "sso.token.rejected");
  assert.doesNotMatch(JSON.stringify(rows[0]), /private@example|synthetic/u);
  await assert.rejects(prisma.auditLog.update({ where: { id: rows[0].id }, data: { result: "SUCCESS" } }));
  await assert.rejects(prisma.auditLog.delete({ where: { id: rows[0].id } }));
  // Characterize the actual Prisma version: a missing cursor returns [], not P2025.
  assert.deepEqual(await prisma.auditLog.findMany({ cursor: { id: `missing-${randomUUID()}` }, skip: 1, take: 1 }), []);
  const rollbackId = randomUUID();
  await assert.rejects(prisma.$transaction(async (transaction) => {
    await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_STATE_CHANGED", result: "SUCCESS", resource: rollbackId });
    throw new Error("synthetic rollback");
  }));
  assert.equal(await prisma.auditLog.count({ where: { resource: rollbackId } }), 0);
  const actorId = randomUUID();
  await prisma.auditLog.createMany({ data: Array.from({ length: 53 }, (_, index) => ({ ...createAuditLogData({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource }), actorRef: hashAuditIdentifier(actorId), createdAt: new Date(Date.UTC(2026, 0, 1, 4, index)), id: `${resource}-${String(index).padStart(3, "0")}` })) });
  const filters = parseAuditFilters({ resource, actor: hashAuditIdentifier(actorId).slice(0, 12), from: "2026-01-01", to: "2026-01-01", sort: "oldest" });
  const first = await prisma.auditLog.findMany(buildAuditQuery(filters));
  const second = await prisma.auditLog.findMany(buildAuditQuery({ ...filters, page: 2 }));
  assert.equal(first.length, 51);
  assert.equal(second.length, 3);
  assert.equal(first[0].id, `${resource}-000`);
  assert.equal(second[0].id, `${resource}-050`);
  assert.equal((await prisma.auditLog.findMany(buildAuditQuery({ ...filters, q: "AUTH_LOGIN_FAILURE" }))).length, 51);
  assert.equal((await prisma.auditLog.findMany(buildAuditQuery({ ...filters, id: `${resource}-000` }))).length, 1);
  assert.equal(await prisma.auditLog.count({ where: { resource, requestId } }), 2);
});
