import assert from "node:assert/strict";
import { randomUUID, randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import * as administration from "./administration";
import { hashOidcIdentifier } from "./oidc-secrets";

after(() => prisma.$disconnect());

const domain = administration;
async function fixture() {
  const admin = await createTestUser({ role: "ADMIN", label: "grant-admin" });
  const user = await createTestUser({ label: "grant-target" });
  const session = await prisma.session.create({ data: { userId: admin.id, tokenHash: randomBytes(32).toString("hex"), expiresAt: new Date(Date.now() + 86400000) } });
  await prisma.securityElevation.create({ data: { userId: admin.id, sessionId: session.id, requestKey: randomBytes(24).toString("base64url"), scope: "PROJECT_ACCESS_CHANGE", challengeHash: "fixture", status: "ACTIVE", expiresAt: new Date(Date.now() + 600000), protocolVersion: 1 } });
  const clientId = randomUUID();
  const connection = await prisma.projectConnection.create({ data: { name: "Fixture", slug: clientId, clientId, origin: "https://project.example.invalid", clientSecretCiphertext: "fixture", redirectUris: [] } });
  return { actor: { id: admin.id, role: "ADMIN" }, sessionId: session.id, userId: user.id, connectionId: connection.id, clientId };
}

test("audit actor references prohibit identity rewrite and deletion while account suspension remains available", integrationOptions, async () => {
  const user = await createTestUser({ label: "audit-actor" });
  const log = await prisma.auditLog.create({ data: { actorUserId: user.id, eventType: "AUTH_LOGIN_SUCCESS", result: "SUCCESS" } });
  await assert.rejects(prisma.user.update({ where: { id: user.id }, data: { id: `changed-${randomUUID()}` } }));
  await assert.rejects(prisma.user.delete({ where: { id: user.id } }));
  await prisma.user.update({ where: { id: user.id }, data: { isActive: false, accountStatus: "INACTIVE" } });
  assert.equal((await prisma.auditLog.findUniqueOrThrow({ where: { id: log.id } })).actorUserId, user.id);
  const disposable = await createTestUser({ label: "no-history-delete" });
  await prisma.user.delete({ where: { id: disposable.id } });
});

for (const kind of ["suspend", "disable"] as const) test(`grant rejects a concurrent ${kind} committed before the grant`, integrationOptions, async () => {
  assert.equal(typeof domain.grantProjectAccess, "function");
  const f = await fixture();
  let locked!: () => void; let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const change = prisma.$transaction(async (transaction) => {
    if (kind === "suspend") await transaction.user.update({ where: { id: f.userId }, data: { isActive: false, accountStatus: "INACTIVE" } });
    else await transaction.projectConnection.update({ where: { id: f.connectionId }, data: { enabled: false } });
    locked(); await gate;
  });
  await ready;
  const granting = domain.grantProjectAccess(f.actor, f.sessionId, f.userId, f.connectionId);
  const rejected = assert.rejects(granting);
  await new Promise((resolve) => setTimeout(resolve, 100));
  release(); await change; await rejected;
  assert.equal(await prisma.userProjectGrant.count({ where: { userId: f.userId, connectionId: f.connectionId } }), 0);
});

test("repeated and concurrent grant revocation preserves the first timestamp and has one audit and side effect", integrationOptions, async () => {
  assert.equal(typeof domain.grantProjectAccess, "function");
  assert.equal(typeof domain.revokeProjectAccess, "function");
  const f = await fixture();
  await domain.grantProjectAccess(f.actor, f.sessionId, f.userId, f.connectionId);
  const grant = await prisma.userProjectGrant.findUniqueOrThrow({ where: { userId_connectionId: { userId: f.userId, connectionId: f.connectionId } } });
  const artifact = () => prisma.oidcArtifact.create({ data: { model: "AccessToken", idHash: randomUUID(), payloadCiphertext: "fixture", clientIdHash: hashOidcIdentifier(f.clientId), accountIdHash: hashOidcIdentifier(f.userId) } });
  await artifact();
  await Promise.all([domain.revokeProjectAccess(f.actor, f.sessionId, grant.id), domain.revokeProjectAccess(f.actor, f.sessionId, grant.id)]);
  const first = await prisma.userProjectGrant.findUniqueOrThrow({ where: { id: grant.id } });
  assert.ok(first.revokedAt);
  assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: hashOidcIdentifier(f.clientId) } }), 0);
  await artifact();
  await domain.revokeProjectAccess(f.actor, f.sessionId, grant.id);
  assert.deepEqual((await prisma.userProjectGrant.findUniqueOrThrow({ where: { id: grant.id } })).revokedAt, first.revokedAt);
  assert.equal(await prisma.oidcArtifact.count({ where: { clientIdHash: hashOidcIdentifier(f.clientId) } }), 1);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: f.actor.id, eventType: "PROJECT_ACCESS_REVOKED" } }), 1);
});
