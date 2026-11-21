import assert from "node:assert/strict";
import { after, test } from "node:test";
import { NextRequest } from "next/server";
import { createSession, getSessionByToken, hashSessionToken, SESSION_COOKIE_NAME } from "@virki/auth";
import { CSRF_FORM_FIELD_NAME, createCsrfToken } from "@virki/auth/csrf";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "../../../../../../packages/auth/src/integration-fixtures";
import { POST } from "./route";

after(() => prisma.$disconnect());

test("successful logout revokes the persisted session before clearing its host-only cookie", integrationOptions, async () => {
  const previousHostname = process.env.VIRKI_PORTAL_HOSTNAME;
  const previousUrl = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.logout-revocation.invalid";
  process.env.VIRKI_PORTAL_URL = "http://portal.logout-revocation.invalid";

  try {
    const user = await createTestUser({ label: "logout-session-revocation" });
    const session = await createSession(user.id);
    assert.ok(await getSessionByToken(session.token), "the fixture session is active before logout");

    const form = new FormData();
    form.set(CSRF_FORM_FIELD_NAME, createCsrfToken({
      scope: "logout",
      binding: hashSessionToken(session.token)
    }));

    const response = await POST(new NextRequest("http://portal.logout-revocation.invalid/api/logout", {
      method: "POST",
      headers: {
        host: "portal.logout-revocation.invalid",
        origin: "http://portal.logout-revocation.invalid",
        cookie: `${SESSION_COOKIE_NAME}=${session.token}`
      },
      body: form
    }));

    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "http://portal.logout-revocation.invalid/login");
    assert.equal(response.headers.get("cache-control"), "no-store");
    const cleared = response.cookies.get(SESSION_COOKIE_NAME);
    assert.equal(cleared?.value, "");
    assert.equal(cleared?.maxAge, 0);
    assert.equal(await getSessionByToken(session.token), null,
      "the old bearer must stop resolving immediately after the successful logout response");

    const stored = await prisma.session.findUniqueOrThrow({
      where: { tokenHash: hashSessionToken(session.token) },
      select: { revokedAt: true }
    });
    assert.ok(stored.revokedAt, "the database row must be revoked, not merely hidden by cookie deletion");

    const events = await prisma.auditLog.findMany({
      where: { actorUserId: user.id, eventType: { in: ["AUTH_LOGOUT", "AUTH_SESSION_REVOKED"] } },
      select: { eventType: true, result: true }
    });
    assert.deepEqual(events.map((event) => event.eventType).sort(), ["AUTH_LOGOUT", "AUTH_SESSION_REVOKED"]);
    assert.ok(events.every((event) => event.result === "SUCCESS"));
  } finally {
    if (previousHostname === undefined) delete process.env.VIRKI_PORTAL_HOSTNAME;
    else process.env.VIRKI_PORTAL_HOSTNAME = previousHostname;
    if (previousUrl === undefined) delete process.env.VIRKI_PORTAL_URL;
    else process.env.VIRKI_PORTAL_URL = previousUrl;
  }
});
