import "next/dist/server/node-environment-baseline";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { after, test } from "node:test";
import React from "react";
import { prisma } from "@virki/database";
import * as auth from "./index";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import { CSRF_FORM_FIELD_NAME } from "./csrf";
import { createSessionCsrfTokenFor } from "../../../apps/hub/src/lib/session-csrf";

Object.assign(globalThis, { AsyncLocalStorage, React });
after(() => prisma.$disconnect());

type RevokeOthers = (userId: string, currentSessionId: string) => Promise<number>;
const revokeOthers = (auth as Record<string, unknown>).revokeOtherAccountSessions as RevokeOthers;
const expiry = () => new Date(Date.now() + 86_400_000);

async function addSession(userId: string, token = randomBytes(32).toString("base64url")) {
  const session = await prisma.session.create({ data: { userId, tokenHash: auth.hashSessionToken(token), expiresAt: expiry() } });
  return { session, token };
}

async function requestContext<T>(host: string, token: string, origin: string, operation: () => Promise<T>): Promise<T> {
  const { workAsyncStorage } = await import("next/dist/server/app-render/work-async-storage.external");
  const { workUnitAsyncStorage } = await import("next/dist/server/app-render/work-unit-async-storage.external");
  const { createRequestStoreForAPI } = await import("next/dist/server/async-storage/request-store");
  const { NextRequest } = await import("next/server");
  const request = new NextRequest(`https://${host}/account/security`, { method: "POST", headers: { host, origin, cookie: `${auth.SESSION_COOKIE_NAME}=${token}` } });
  const store = createRequestStoreForAPI(request, { pathname: "/account/security" }, { tags: [], expirationsByCacheKind: new Map() } as never, undefined, undefined, undefined);
  return workAsyncStorage.run({ route: "/account/security" } as never, () => workUnitAsyncStorage.run(store, operation));
}

test("USER revokes every active other session beyond the 50-row display limit, with one audit event", integrationOptions, async () => {
  assert.equal(typeof revokeOthers, "function");
  const owner = await createTestUser({ label: "revoke-all-owner" });
  const foreign = await createTestUser({ label: "revoke-all-foreign" });
  const current = await addSession(owner.id);
  const victim = await addSession(owner.id);
  const unrelated = await addSession(foreign.id);
  await prisma.session.createMany({ data: Array.from({ length: 54 }, () => ({ userId: owner.id, tokenHash: auth.hashSessionToken(randomBytes(32).toString("base64url")), expiresAt: expiry() })) });

  assert.equal(await revokeOthers(owner.id, current.session.id), 55);
  assert.ok(await auth.getSessionByToken(current.token));
  assert.equal(await auth.getSessionByToken(victim.token), null);
  assert.ok(await auth.getSessionByToken(unrelated.token));
  assert.equal(await prisma.session.count({ where: { userId: owner.id, revokedAt: null } }), 1);
  const audit = await prisma.auditLog.findMany({ where: { actorUserId: owner.id, eventType: "AUTH_SESSION_REVOKED" } });
  assert.equal(audit.length, 1);
  assert.equal((audit[0]?.metadata as { revokedCount?: number } | null)?.revokedCount, 55);
  assert.equal(audit[0]?.actorRole, "USER");
  assert.equal(audit[0]?.sessionRef, auth.hashAuditSessionReference(current.session.id));
  assert.equal(await revokeOthers(owner.id, current.session.id), 0, "repeat submission is idempotent");
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: owner.id, eventType: "AUTH_SESSION_REVOKED" } }), 1);
});

test("foreign, revoked, expired, and ADMIN current sessions cannot authorize USER bulk revocation", integrationOptions, async () => {
  assert.equal(typeof revokeOthers, "function");
  const user = await createTestUser({ label: "revoke-all-isolation" });
  const other = await createTestUser({ label: "revoke-all-other" });
  const admin = await createTestUser({ role: "ADMIN", label: "revoke-all-admin" });
  const current = await addSession(user.id);
  const victim = await addSession(user.id);
  const foreign = await addSession(other.id);
  const adminCurrent = await addSession(admin.id);
  const adminOther = await addSession(admin.id);

  await assert.rejects(revokeOthers(user.id, foreign.session.id));
  await assert.rejects(revokeOthers(admin.id, adminCurrent.session.id));
  await prisma.session.update({ where: { id: current.session.id }, data: { revokedAt: new Date() } });
  await assert.rejects(revokeOthers(user.id, current.session.id));
  await prisma.session.update({ where: { id: current.session.id }, data: { revokedAt: null, expiresAt: new Date(Date.now() - 1) } });
  const storedExpiry = await prisma.session.findUniqueOrThrow({ where: { id: current.session.id }, select: { expiresAt: true } });
  assert.ok(storedExpiry.expiresAt.getTime() < Date.now(), "the current session must be expired before revocation is attempted");
  await assert.rejects(revokeOthers(user.id, current.session.id));

  assert.ok(await auth.getSessionByToken(victim.token));
  assert.ok(await auth.getSessionByToken(adminOther.token));
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: user.id, eventType: "AUTH_SESSION_REVOKED" } }), 0);
});

test("simultaneous USER bulk revocations remain idempotent and produce one audit for changed rows", integrationOptions, async () => {
  assert.equal(typeof revokeOthers, "function");
  const user = await createTestUser({ label: "revoke-all-race" });
  const current = await addSession(user.id);
  const other = await addSession(user.id);
  const [first, second] = await Promise.all([revokeOthers(user.id, current.session.id), revokeOthers(user.id, current.session.id)]);
  assert.equal(first + second, 1);
  assert.ok(await auth.getSessionByToken(current.token));
  assert.equal(await auth.getSessionByToken(other.token), null);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: user.id, eventType: "AUTH_SESSION_REVOKED" } }), 1);
});

test("security page data reports all other sessions while keeping the current one in a bounded list", integrationOptions, async () => {
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.example.invalid";
  const user = await createTestUser({ label: "revoke-all-list" });
  const current = await addSession(user.id);
  await prisma.session.createMany({ data: Array.from({ length: 55 }, () => ({ userId: user.id, tokenHash: auth.hashSessionToken(randomBytes(32).toString("base64url")), expiresAt: expiry() })) });
  const { getAccountSecurityData } = await import("../../../apps/hub/src/app/account/security/actions");
  const data = await requestContext("portal.example.invalid", current.token, "https://portal.example.invalid", getAccountSecurityData);
  assert.equal(data?.otherSessionCount, 55);
  assert.equal(data?.sessions.length, 50);
  assert.equal(data?.sessions[0]?.id, current.session.id);
});

test("portal action requires correct origin, session-bound CSRF, USER role, confirmation, and password", integrationOptions, async () => {
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.example.invalid";
  const { revokeOtherAccountSessionsAction } = await import("../../../apps/hub/src/app/account/security/actions");
  assert.equal(typeof revokeOtherAccountSessionsAction, "function");
  const user = await createTestUser({ label: "revoke-all-action" });
  const admin = await createTestUser({ role: "ADMIN", label: "revoke-all-admin-action" });
  const current = await addSession(user.id);
  const other = await addSession(user.id);
  const adminCurrent = await addSession(admin.id);
  const adminOther = await addSession(admin.id);
  const form = (token: string) => {
    const data = new FormData();
    data.set(CSRF_FORM_FIELD_NAME, createSessionCsrfTokenFor(token, "account-security"));
    data.set("password", user.password);
    data.set("confirmed", "yes");
    return data;
  };
  const invoke = (token: string, origin: string, data: FormData) => requestContext("portal.example.invalid", token, origin, () => revokeOtherAccountSessionsAction(data));

  await assert.rejects(invoke(current.token, "https://wrong.example.invalid", form(current.token)));
  await assert.rejects(invoke(current.token, "https://portal.example.invalid", form(adminCurrent.token)));
  const unconfirmed = form(current.token);
  unconfirmed.delete("confirmed");
  await assert.rejects(invoke(current.token, "https://portal.example.invalid", unconfirmed));
  const badPassword = form(current.token);
  badPassword.set("password", "incorrect-password");
  await assert.rejects(invoke(current.token, "https://portal.example.invalid", badPassword));
  await assert.rejects(invoke(adminCurrent.token, "https://portal.example.invalid", form(adminCurrent.token)));
  assert.ok(await auth.getSessionByToken(other.token));
  assert.ok(await auth.getSessionByToken(adminOther.token));

  const { getAccountSecurityData } = await import("../../../apps/hub/src/app/account/security/actions");
  const before = await requestContext("portal.example.invalid", current.token, "https://portal.example.invalid", getAccountSecurityData);
  assert.equal(before?.otherSessionCount, 1);
  await assert.rejects(invoke(current.token, "https://portal.example.invalid", form(current.token)));
  assert.ok(await auth.getSessionByToken(current.token));
  assert.equal(await auth.getSessionByToken(other.token), null);
  assert.ok(await auth.getSessionByToken(adminOther.token));
});
