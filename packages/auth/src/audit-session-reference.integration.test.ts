import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { prisma } from "@virki/database";
import { hashAuditSessionReference, writeAuditLogRequired, writeAuditLogInTransaction, hashSessionToken } from "./index";
import { recordSecurityDenial } from "../../../apps/hub/src/lib/audit-denial";
import { createTestUser, integrationOptions } from "./integration-fixtures";

test("login, denial, OIDC, logout, and verified ADMIN mutation events join on one persisted session", integrationOptions, async () => {
  const user = await createTestUser({ role: "ADMIN", label: "audit-session-join" });
  const token = randomBytes(32).toString("base64url");
  const session = await prisma.session.create({ data: {
    userId: user.id,
    tokenHash: hashSessionToken(token),
    expiresAt: new Date(Date.now() + 60_000)
  } });
  const sessionRef = hashAuditSessionReference(session.id);
  const requestHeaders = new Headers({ "x-virki-audit-request-id": "f4e4e886-0e23-42f0-a3d4-3fb3d75fb705" });

  try {
    await writeAuditLogRequired({ eventType: "AUTH_LOGIN_SUCCESS", result: "SUCCESS", actorUserId: user.id, actorRole: "ADMIN", sessionRef, resource: "hub" });
    await recordSecurityDenial(requestHeaders, "integration-denial", "csrf", {
      id: session.id,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      authenticationMethods: session.authenticationMethods,
      user: { id: user.id, role: "ADMIN", email: user.email, displayName: "Integration" }
    });
    await writeAuditLogRequired({ eventType: "SSO_INTERACTION_COMPLETED", result: "SUCCESS", actorUserId: user.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(session.id), resource: "sso.interaction" });
    await writeAuditLogRequired({ eventType: "AUTH_LOGOUT", result: "SUCCESS", actorUserId: user.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(session.id), resource: "hub" });
    await writeAuditLogInTransaction(prisma, { eventType: "PROJECT_CONNECTION_UPDATED", result: "SUCCESS", actorUserId: user.id, actorRole: "ADMIN", sessionRef: hashAuditSessionReference(session.id), resource: "project.connection" });

    const rows = await prisma.auditLog.findMany({ where: { actorUserId: user.id, eventType: { in: ["AUTH_LOGIN_SUCCESS", "CSRF_DENIED", "SSO_INTERACTION_COMPLETED", "AUTH_LOGOUT", "PROJECT_CONNECTION_UPDATED"] } }, orderBy: { createdAt: "asc" }, select: { eventType: true, actorRole: true, sessionRef: true } });
    assert.deepEqual(rows.map(({ eventType }) => eventType).sort(), ["AUTH_LOGIN_SUCCESS", "AUTH_LOGOUT", "CSRF_DENIED", "PROJECT_CONNECTION_UPDATED", "SSO_INTERACTION_COMPLETED"].sort());
    assert.ok(rows.every((row) => row.sessionRef === sessionRef));
    const mutation = rows.find((row) => row.eventType === "PROJECT_CONNECTION_UPDATED");
    assert.equal(mutation?.actorRole, "ADMIN");
    assert.equal(mutation?.sessionRef, sessionRef);
  } finally {
    await prisma.session.delete({ where: { id: session.id } });
  }
});
