import "next/dist/server/node-environment-baseline";
import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import React from "react";
import { prisma } from "@virki/database";
import { hashSessionToken, SESSION_COOKIE_NAME } from "./index";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import { CSRF_FORM_FIELD_NAME } from "./csrf";
import { createSessionCsrfTokenFor } from "../../../apps/hub/src/lib/session-csrf";

Object.assign(globalThis, { AsyncLocalStorage, React });
after(() => prisma.$disconnect());

async function invokeRevokeElevation(token: string, form: FormData): Promise<void> {
  const { workAsyncStorage } = await import("next/dist/server/app-render/work-async-storage.external");
  const { workUnitAsyncStorage } = await import("next/dist/server/app-render/work-unit-async-storage.external");
  const { createRequestStoreForAPI } = await import("next/dist/server/async-storage/request-store");
  const { NextRequest } = await import("next/server");
  const { revokeElevationAction } = await import("../../../apps/hub/src/app/admin/security/actions");
  const pathname = "/admin/security";
  const host = "hub.example.invalid";
  const request = new NextRequest(`https://${host}${pathname}`, {
    method: "POST",
    headers: { host, origin: `https://${host}`, cookie: `${SESSION_COOKIE_NAME}=${token}` }
  });
  const store = createRequestStoreForAPI(request, { pathname }, { tags: [], expirationsByCacheKind: new Map() } as never, undefined, undefined, undefined);
  return workAsyncStorage.run({ route: pathname, incrementalCache: {}, cacheLifeProfiles: {} } as never,
    () => workUnitAsyncStorage.run(store, () => revokeElevationAction(form)));
}

test("ADMIN elevation revocation rolls back mutation and success audit when actor expires waiting for row lock", integrationOptions, async () => {
  const oldHost = process.env.VIRKI_HUB_HOSTNAME;
  const oldAccess = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  process.env.VIRKI_HUB_HOSTNAME = "hub.example.invalid";
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false"; // Disposable test, never production Access.
  try {
    const admin = await createTestUser({ role: "ADMIN", label: "admin-elevation-revoke-expiry" });
    const token = randomBytes(32).toString("base64url");
    const current = await prisma.session.create({
      data: { userId: admin.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 60_000) }
    });
    const elevation = await prisma.securityElevation.create({
      data: {
        userId: admin.id, sessionId: current.id, requestKey: randomBytes(24).toString("base64url"),
        protocolVersion: 1, scope: "ADMIN_CREDENTIAL_CHANGE", challengeHash: "synthetic-local-test",
        status: "ACTIVE", expiresAt: new Date(Date.now() + 60_000)
      }
    });
    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, createSessionCsrfTokenFor(token, "admin-security"));
    form.set("requestKey", elevation.requestKey);
    // Resolve Next request dependencies before starting the short expiry interval.
    await Promise.all([
      import("../../../apps/hub/src/app/admin/security/actions"),
      import("next/dist/server/app-render/work-async-storage.external"),
      import("next/dist/server/app-render/work-unit-async-storage.external"),
      import("next/dist/server/async-storage/request-store"),
      import("next/server")
    ]);
    const expiresAt = new Date(Date.now() + 3_800);
    await prisma.session.update({ where: { id: current.id }, data: { expiresAt } });

    let signalLocked!: () => void;
    let release!: () => void;
    let blockerPid = 0;
    const locked = new Promise<void>((resolve) => { signalLocked = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const holder = prisma.$transaction(async (tx) => {
      [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
      await tx.$queryRaw`SELECT "id" FROM "SecurityElevation" WHERE "id" = ${elevation.id} FOR UPDATE`;
      signalLocked();
      await gate;
    }, { timeout: 15_000 });
    const finishedEarly = holder.then(
      () => { throw new Error("Holder finished before the observed lock wait"); },
      (error: unknown) => { throw error; }
    );
    void finishedEarly.catch(() => {});
    let outcome!: Promise<{ kind: "resolved" | "rejected"; detail: string }>;
    try {
      await Promise.race([locked, finishedEarly]);
      outcome = invokeRevokeElevation(token, form).then(
        () => ({ kind: "resolved" as const, detail: "" }),
        (error: unknown) => ({ kind: "rejected" as const, detail: String(error && typeof error === "object" && "digest" in error ? error.digest : error) })
      );
      const deadline = Date.now() + 2_700;
      let observedWait = false;
      while (!observedWait && Date.now() < deadline) {
        const rows = await prisma.$queryRaw<Array<{ blocked: number }>>`
          SELECT count(*)::integer AS blocked FROM pg_stat_activity
          WHERE wait_event_type = 'Lock'
            AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        `;
        observedWait = (rows[0]?.blocked ?? 0) > 0;
        if (!observedWait) await new Promise<void>((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(observedWait, true, "the real ADMIN action must wait on the elevation's held PostgreSQL lock");
      assert.ok(Date.now() < expiresAt.getTime(), "actor must be valid before waiting, not invalid at entry");
      await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 110)));
    } finally {
      release();
      await Promise.allSettled([holder]);
    }
    const result = await outcome;
    assert.equal(result.kind, "rejected", "expired actor cannot finish a successful ADMIN elevation revocation");
    assert.match(result.detail, /Administrative security mutation rejected\./u,
      "denial must come from the in-transaction authorization guard, not a Prisma timeout");
    assert.doesNotMatch(result.detail, /NEXT_REDIRECT;[^;]*;\/admin\/security\?status=revoked/u);
    assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { id: elevation.id } })).status, "ACTIVE",
      "post-lock expiry rolls back elevation mutation");
    assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.id, eventType: "ADMIN_ELEVATION_REVOKED", result: "SUCCESS" } }), 0,
      "post-lock expiry rolls back success audit");
  } finally {
    if (oldHost === undefined) delete process.env.VIRKI_HUB_HOSTNAME;
    else process.env.VIRKI_HUB_HOSTNAME = oldHost;
    if (oldAccess === undefined) delete process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
    else process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = oldAccess;
  }
});

test("ADMIN elevation revocation still commits exactly one success audit for a valid actor", integrationOptions, async () => {
  const oldHost = process.env.VIRKI_HUB_HOSTNAME;
  const oldAccess = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  process.env.VIRKI_HUB_HOSTNAME = "hub.example.invalid";
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
  try {
    const admin = await createTestUser({ role: "ADMIN", label: "admin-elevation-revoke-valid" });
    const token = randomBytes(32).toString("base64url");
    const current = await prisma.session.create({
      data: { userId: admin.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 60_000) }
    });
    const elevation = await prisma.securityElevation.create({
      data: {
        userId: admin.id, sessionId: current.id, requestKey: randomBytes(24).toString("base64url"),
        protocolVersion: 1, scope: "ADMIN_CREDENTIAL_CHANGE", challengeHash: "synthetic-local-test",
        status: "ACTIVE", expiresAt: new Date(Date.now() + 60_000)
      }
    });
    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, createSessionCsrfTokenFor(token, "admin-security"));
    form.set("requestKey", elevation.requestKey);
    await assert.rejects(invokeRevokeElevation(token, form), (error: unknown) => {
      const digest = error && typeof error === "object" && "digest" in error ? String(error.digest) : "";
      assert.match(digest, /NEXT_REDIRECT;[^;]*;\/admin\/security\?status=revoked#admin-content;/u);
      return true;
    });
    assert.equal((await prisma.securityElevation.findUniqueOrThrow({ where: { id: elevation.id } })).status, "REVOKED");
    assert.equal(await prisma.auditLog.count({ where: { actorUserId: admin.id, eventType: "ADMIN_ELEVATION_REVOKED", result: "SUCCESS" } }), 1);
  } finally {
    if (oldHost === undefined) delete process.env.VIRKI_HUB_HOSTNAME;
    else process.env.VIRKI_HUB_HOSTNAME = oldHost;
    if (oldAccess === undefined) delete process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
    else process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = oldAccess;
  }
});
