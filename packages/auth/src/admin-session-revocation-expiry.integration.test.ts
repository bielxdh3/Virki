import "next/dist/server/node-environment-baseline";
import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import React from "react";
import { prisma } from "@virki/database";
import { hashSessionToken, SESSION_COOKIE_NAME } from "./index";
import { integrationOptions, createTestUser } from "./integration-fixtures";
import { CSRF_FORM_FIELD_NAME } from "./csrf";
import { createSessionCsrfTokenFor } from "../../../apps/hub/src/lib/session-csrf";

Object.assign(globalThis, { AsyncLocalStorage, React });
after(() => prisma.$disconnect());

async function invokeAdminAction(token: string, form: FormData): Promise<void> {
  const { workAsyncStorage } = await import("next/dist/server/app-render/work-async-storage.external");
  const { workUnitAsyncStorage } = await import("next/dist/server/app-render/work-unit-async-storage.external");
  const { createRequestStoreForAPI } = await import("next/dist/server/async-storage/request-store");
  const { NextRequest } = await import("next/server");
  const { revokeOtherSessionsAction } = await import("../../../apps/hub/src/app/admin/security/actions");
  const pathname = "/admin/security";
  const host = "hub.example.invalid";
  const request = new NextRequest(`https://${host}${pathname}`, {
    method: "POST",
    headers: { host, origin: `https://${host}`, cookie: `${SESSION_COOKIE_NAME}=${token}` }
  });
  const store = createRequestStoreForAPI(request, { pathname }, { tags: [], expirationsByCacheKind: new Map() } as never, undefined, undefined, undefined);
  return workAsyncStorage.run({ route: pathname, incrementalCache: {}, cacheLifeProfiles: {} } as never,
    () => workUnitAsyncStorage.run(store, () => revokeOtherSessionsAction(form)));
}

test("ADMIN bulk revoke denies an actor who expires during target-row UPDATE lock wait", integrationOptions, async () => {
  const oldHost = process.env.VIRKI_HUB_HOSTNAME;
  const oldAccess = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  process.env.VIRKI_HUB_HOSTNAME = "hub.example.invalid";
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false"; // disposable local test only
  try {
    const admin = await createTestUser({ role: "ADMIN", label: "admin-stale-revoke" });
    const otherAdmin = await createTestUser({ role: "ADMIN", label: "admin-stale-foreign" });
    const token = randomBytes(32).toString("base64url");
    const current = await prisma.session.create({
      data: { userId: admin.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 60_000) }
    });
    const victim = await prisma.session.create({
      data: { userId: admin.id, tokenHash: hashSessionToken(randomBytes(32).toString("base64url")), expiresAt: new Date(Date.now() + 60_000) }
    });
    const foreign = await prisma.session.create({
      data: { userId: otherAdmin.id, tokenHash: hashSessionToken(randomBytes(32).toString("base64url")), expiresAt: new Date(Date.now() + 60_000) }
    });
    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, createSessionCsrfTokenFor(token, "admin-security"));
    // Prime Next.js request-context module imports before setting expiry.
    await import("../../../apps/hub/src/app/admin/security/actions");
    const expiry = new Date(Date.now() + 3_200);
    await prisma.session.update({ where: { id: current.id }, data: { expiresAt: expiry } });

    let locked!: () => void;
    let release!: () => void;
    let blockerPid = 0;
    const ready = new Promise<void>((resolve) => { locked = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const holder = prisma.$transaction(async (tx) => {
      [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
      await tx.$queryRaw`SELECT "id" FROM "Session" WHERE "id" = ${victim.id} FOR UPDATE`;
      locked();
      await gate;
    }, { timeout: 15_000 });
    const premature = holder.then(
      () => { throw new Error("Target lock holder completed before confirming lock acquisition"); },
      (error: unknown) => { throw error; }
    );
    void premature.catch(() => {}); // consumed by Promise.race when readiness fails
    let outcome!: Promise<{ kind: "resolved" | "rejected"; detail: string }>;
    try {
      await Promise.race([ready, premature]);
      outcome = invokeAdminAction(token, form).then(
        () => ({ kind: "resolved" as const, detail: "" }),
        (error: unknown) => ({ kind: "rejected" as const, detail: String(error && typeof error === "object" && "digest" in error ? error.digest : error) })
      );
      const deadline = Date.now() + 2_000;
      let observed = false;
      while (!observed && Date.now() < deadline) {
        const blocked = await prisma.$queryRaw<Array<{ count: number }>>`
          SELECT count(*)::integer AS count FROM pg_stat_activity
          WHERE wait_event_type = 'Lock'
            AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        `;
        observed = (blocked[0]?.count ?? 0) > 0;
        if (!observed) await new Promise<void>((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(observed, true, "real ADMIN action UPDATE must wait on independently held Session FOR UPDATE");
      assert.ok(Date.now() < expiry.getTime(), "ADMIN must be valid before waiting, to prove a post-wait expiry race");
      await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiry.getTime() - Date.now() + 120)));
    } finally {
      release();
      await Promise.allSettled([holder]);
    }
    const result = await outcome;
    assert.equal(result.kind, "rejected", "the stale ADMIN action must reject, not return successfully");
    assert.match(result.detail, /Administrative session revocation rejected\./u,
      "the final in-transaction authorization guard must deny, not a Prisma timeout or unrelated error");
    assert.doesNotMatch(result.detail, /NEXT_REDIRECT;[^;]*;\/admin\/security\?status=sessions/u,
      "an expired ADMIN must not complete a successful protected redirect");
    assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: victim.id }, select: { revokedAt: true } })).revokedAt, null,
      "target revocation must roll back after actor expires mid-wait");
    assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: foreign.id }, select: { revokedAt: true } })).revokedAt, null);
    assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.id, eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS" } }), 0,
      "a denied stale ADMIN action must not write a success audit");
  } finally {
    if (oldHost === undefined) delete process.env.VIRKI_HUB_HOSTNAME;
    else process.env.VIRKI_HUB_HOSTNAME = oldHost;
    if (oldAccess === undefined) delete process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
    else process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = oldAccess;
  }
});

test("ADMIN bulk revoke rejects a session revoked by another transaction before acquiring its lock", integrationOptions, async () => {
  const oldHost = process.env.VIRKI_HUB_HOSTNAME;
  const oldAccess = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  process.env.VIRKI_HUB_HOSTNAME = "hub.example.invalid";
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
  try {
    const admin = await createTestUser({ role: "ADMIN", label: "admin-revoke-race" });
    const token = randomBytes(32).toString("base64url");
    const current = await prisma.session.create({ data: { userId: admin.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 60_000) } });
    const other = await prisma.session.create({ data: { userId: admin.id, tokenHash: hashSessionToken(randomBytes(32).toString("base64url")), expiresAt: new Date(Date.now() + 60_000) } });
    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, createSessionCsrfTokenFor(token, "admin-security"));
    await import("../../../apps/hub/src/app/admin/security/actions");
    let ready!: () => void;
    let release!: () => void;
    let blockerPid = 0;
    const started = new Promise<void>((resolve) => { ready = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const holder = prisma.$transaction(async (tx) => {
      [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
      await tx.$queryRaw`SELECT "id" FROM "Session" WHERE "id" = ${current.id} FOR UPDATE`;
      await tx.session.update({ where: { id: current.id }, data: { revokedAt: new Date() } });
      ready();
      await gate;
    }, { timeout: 15_000 });
    const premature = holder.then(
      () => { throw new Error("The current-session revocation holder finished prematurely"); },
      (error: unknown) => { throw error; }
    );
    void premature.catch(() => {});
    let outcome!: Promise<string>;
    try {
      await Promise.race([started, premature]);
      outcome = invokeAdminAction(token, form).then(
        () => "resolved",
        (error: unknown) => String(error && typeof error === "object" && "digest" in error ? error.digest : error)
      );
      const deadline = Date.now() + 6_000;
      let observed = false;
      while (!observed && Date.now() < deadline) {
        const rows = await prisma.$queryRaw<Array<{ count: number }>>`
          SELECT count(*)::integer AS count FROM pg_stat_activity
          WHERE wait_event_type = 'Lock' AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        `;
        observed = (rows[0]?.count ?? 0) > 0;
        if (!observed) await new Promise<void>((resolve) => setTimeout(resolve, 20));
      }
      assert.ok(observed, "actor authorization must wait on its current Session row lock");
    } finally {
      release();
      await Promise.allSettled([holder]);
    }
    const result = await outcome;
    assert.match(result, /Administrative security mutation rejected\./u,
      "revoked-actor lock recheck, not a timeout, must reject the action");
    assert.doesNotMatch(result, /NEXT_REDIRECT;[^;]*;\/admin\/security\?status=sessions/u);
    assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: other.id }, select: { revokedAt: true } })).revokedAt, null,
      "concurrent current-session revocation must win before any other-session write");
    assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.id, eventType: "AUTH_SESSION_REVOKED", result: "SUCCESS" } }), 0);
  } finally {
    if (oldHost === undefined) delete process.env.VIRKI_HUB_HOSTNAME;
    else process.env.VIRKI_HUB_HOSTNAME = oldHost;
    if (oldAccess === undefined) delete process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
    else process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = oldAccess;
  }
});
