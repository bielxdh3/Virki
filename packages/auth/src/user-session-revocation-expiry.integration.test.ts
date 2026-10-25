import "next/dist/server/node-environment-baseline";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { after, test } from "node:test";
import React from "react";
import { prisma } from "@virki/database";
import * as auth from "./index";
import { AccountSessionRevocationError } from "./session-revocation";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import { CSRF_FORM_FIELD_NAME } from "./csrf";
import { createSessionCsrfTokenFor } from "../../../apps/hub/src/lib/session-csrf";

Object.assign(globalThis, { AsyncLocalStorage, React });
after(() => prisma.$disconnect());

type RevokeOthers = (userId: string, currentSessionId: string) => Promise<number>;
const revokeOthers = (auth as Record<string, unknown>).revokeOtherAccountSessions as RevokeOthers;
const expiry = () => new Date(Date.now() + 86_400_000);

async function addSession(userId: string) {
  const token = randomBytes(32).toString("base64url");
  const session = await prisma.session.create({ data: { userId, tokenHash: auth.hashSessionToken(token), expiresAt: expiry() } });
  return { session, token };
}

async function requestContext<T>(host: string, token: string, origin: string, operation: () => Promise<T>, pathname = "/account/security"): Promise<T> {
  const { workAsyncStorage } = await import("next/dist/server/app-render/work-async-storage.external");
  const { workUnitAsyncStorage } = await import("next/dist/server/app-render/work-unit-async-storage.external");
  const { createRequestStoreForAPI } = await import("next/dist/server/async-storage/request-store");
  const { NextRequest } = await import("next/server");
  const request = new NextRequest(`https://${host}${pathname}`, { method: "POST", headers: { host, origin, cookie: `${auth.SESSION_COOKIE_NAME}=${token}` } });
  const store = createRequestStoreForAPI(request, { pathname }, { tags: [], expirationsByCacheKind: new Map() } as never, undefined, undefined, undefined);
  return workAsyncStorage.run({ route: pathname, incrementalCache: {}, cacheLifeProfiles: {} } as never,
    () => workUnitAsyncStorage.run(store, operation));
}
async function waitForBlockedTargetUpdate(blockerPid: number): Promise<Date> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const rows = await prisma.$queryRaw<Array<{ xactStart: Date | null }>>`
      SELECT xact_start AS "xactStart" FROM pg_stat_activity
      WHERE wait_event_type = 'Lock'
        AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        AND query LIKE '%UPDATE%Session%'
    `;
    if (rows[0]?.xactStart) return rows[0].xactStart;
    await new Promise<void>((resolve) => setTimeout(resolve, 15));
  }
  throw Error("No real PostgreSQL UPDATE Session blocked on target lock");
}

async function holdTargetLock(userId: string, targetSessionId: string) {
  let acquired!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { acquired = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let blockerPid = 0;
  const holder = prisma.$transaction(async (tx) => {
    [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    await tx.$queryRaw`SELECT "id" FROM "Session" WHERE "id" = ${targetSessionId} AND "userId" = ${userId} FOR UPDATE`;
    acquired();
    await gate;
  }, { timeout: 10_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );
  await Promise.race([
    ready,
    holder.then((result) => { throw result.error ?? Error("Target blocker finished before lock acquisition"); })
  ]);
  return { blockerPid, release, holder };
}

async function expireWhileTargetUpdateIsBlocked(blockerPid: number, expiresAt: Date) {
  const transactionStart = await waitForBlockedTargetUpdate(blockerPid);
  assert.ok(Date.now() < expiresAt.getTime(), "the current session must be live once UPDATE is blocked");
  await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 130)));
  assert.ok(Date.now() >= expiresAt.getTime(), "expiry must happen while the target lock remains held");
  return transactionStart;
}

test("USER bulk revoke rolls back target UPDATE and success audit if current session expires during target-row wait", integrationOptions, async () => {
  const user = await createTestUser({ label: "bulk-post-target-expiry" });
  const current = await addSession(user.id);
  const victim = await addSession(user.id);
  const blocked = await holdTargetLock(user.id, victim.session.id);
  let outcome: Promise<{ ok: boolean; error: unknown }> | undefined;
  try {
    const expiresAt = new Date(Date.now() + 2_300);
    await prisma.session.update({ where: { id: current.session.id }, data: { expiresAt } });
    outcome = revokeOthers(user.id, current.session.id).then(
      () => ({ ok: true, error: null }),
      (error: unknown) => ({ ok: false, error })
    );
    await expireWhileTargetUpdateIsBlocked(blocked.blockerPid, expiresAt);
  } finally {
    blocked.release();
    await Promise.allSettled([blocked.holder, outcome]);
  }
  assert.equal((await blocked.holder).ok, true);
  assert.equal((await outcome)?.ok, false, "expiration after UPDATE begins must fail the complete transaction");
  assert.ok((await outcome)?.error instanceof AccountSessionRevocationError,
    "authorization expiry must cause the rejection, not a Prisma transaction timeout");
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: victim.session.id }, select: { revokedAt: true } })).revokedAt, null);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: user.id, eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS" } }), 0);
});

test("single-session action rolls back target UPDATE and success audit if current expires during target-row wait", integrationOptions, async () => {
  const originalPortalHostname = process.env.VIRKI_PORTAL_HOSTNAME;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.example.invalid";
  try {
  const { getAccountSecurityData, revokeAccountSessionAction } = await import("../../../apps/hub/src/app/account/security/actions");
  const user = await createTestUser({ label: "single-post-target-expiry" });
  const current = await addSession(user.id);
  const victim = await addSession(user.id);
  assert.ok(await requestContext("portal.example.invalid", current.token, "https://portal.example.invalid", getAccountSecurityData));
  const blocked = await holdTargetLock(user.id, victim.session.id);
  let outcome: Promise<unknown> | undefined;
  let transactionStartedAt: Date | undefined;
  try {
    const expiresAt = new Date(Date.now() + 2_800);
    await prisma.session.update({ where: { id: current.session.id }, data: { expiresAt } });
    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, createSessionCsrfTokenFor(current.token, "account-security"));
    form.set("sessionId", victim.session.id);
    outcome = requestContext("portal.example.invalid", current.token, "https://portal.example.invalid", () => revokeAccountSessionAction(form)).then(
      () => "resolved",
      (error: unknown) => error
    );
    transactionStartedAt = await expireWhileTargetUpdateIsBlocked(blocked.blockerPid, expiresAt);
  } finally {
    blocked.release();
    await Promise.allSettled([blocked.holder, outcome]);
  }
  assert.equal((await blocked.holder).ok, true);
  const result = await outcome;
  assert.notEqual(result, "resolved");
  assert.match(String(result && typeof result === "object" && "digest" in result ? result.digest : result), /error=session/u,
    "action must fail rather than redirect with status=session");
  assert.ok(transactionStartedAt && Date.now() - transactionStartedAt.getTime() < 4_500,
    "rejection must finish well before Prisma's 5s transaction timeout, not pass on P2028");
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: victim.session.id }, select: { revokedAt: true } })).revokedAt, null);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: user.id, eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS" } }), 0);
  } finally {
    if (originalPortalHostname === undefined) delete process.env.VIRKI_PORTAL_HOSTNAME;
    else process.env.VIRKI_PORTAL_HOSTNAME = originalPortalHostname;
  }
});

test("USER bulk revoke rolls back a completed target UPDATE if the success audit INSERT waits past current expiry", integrationOptions, async () => {
  const user = await createTestUser({ label: "bulk-post-audit-expiry" });
  const current = await addSession(user.id);
  const victim = await addSession(user.id);
  let acquired!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { acquired = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let blockerPid = 0;
  const blocker = prisma.$transaction(async (tx) => {
    [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    await tx.$executeRawUnsafe('LOCK TABLE "AuditLog" IN ACCESS EXCLUSIVE MODE');
    acquired();
    await gate;
  }, { timeout: 10_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );
  let outcome: Promise<{ ok: boolean; error: unknown }> | undefined;
  try {
    await Promise.race([ready, blocker.then((result) => { throw result.error ?? Error("Audit blocker never acquired its table lock"); })]);
    const expiresAt = new Date(Date.now() + 2_300);
    await prisma.session.update({ where: { id: current.session.id }, data: { expiresAt } });
    outcome = revokeOthers(user.id, current.session.id).then(
      () => ({ ok: true, error: null }),
      (error: unknown) => ({ ok: false, error })
    );
    const deadline = Date.now() + 5_000;
    let observed = false;
    while (Date.now() < deadline) {
      const rows = await prisma.$queryRaw<Array<{ count: number }>>`
        SELECT count(*)::int AS count FROM pg_stat_activity
        WHERE wait_event_type = 'Lock'
          AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
          AND query LIKE '%INSERT%AuditLog%'
      `;
      if ((rows[0]?.count ?? 0) > 0) { observed = true; break; }
      await new Promise<void>((resolve) => setTimeout(resolve, 15));
    }
    assert.equal(observed, true, "a real INSERT into AuditLog must be blocked after revoking the target");
    assert.ok(Date.now() < expiresAt.getTime(), "current session must be valid when audit INSERT starts waiting");
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 120)));
    assert.ok(Date.now() >= expiresAt.getTime(), "session must expire while audit INSERT still waits");
  } finally {
    release();
    await Promise.allSettled([blocker, outcome]);
  }
  assert.equal((await blocker).ok, true);
  assert.equal((await outcome)?.ok, false, "post-audit expiry recheck must roll back the prior successful UPDATE");
  assert.ok((await outcome)?.error instanceof AccountSessionRevocationError,
    "expiry after delayed audit INSERT must reject by authorization, not Prisma timeout");
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: victim.session.id }, select: { revokedAt: true } })).revokedAt, null);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: user.id, eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS" } }), 0);
});
