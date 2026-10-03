import assert from "node:assert/strict";
import test from "node:test";
import { createLoginResponseAfterRequiredAudit, createVerifiedLoginAudit, RequiredLoginAuditError } from "./login-audit";

test("completed login audit records the actor, surface, proof factor, and safe request metadata", () => {
  assert.deepEqual(createVerifiedLoginAudit("user-123", "hub", "totp", {
    source: "hub-login-verification",
    cloudflareAccessPresent: true,
    userAgentHash: "a".repeat(64)
  }), {
    eventType: "AUTH_LOGIN_SUCCESS",
    result: "SUCCESS",
    actorUserId: "user-123",
    resource: "hub",
    message: "Security verification completed; login succeeded.",
    metadata: {
      source: "hub-login-verification",
      cloudflareAccessPresent: true,
      userAgentHash: "a".repeat(64),
      verificationFactor: "totp"
    }
  });
});

for (const { name, cookieName } of [
  { name: "remembered-browser login", cookieName: "bielos-session" },
  { name: "second-factor verification", cookieName: "bielos-session" },
  { name: "password-accepted challenge", cookieName: "bielos-device" }
]) {
  test(`${name} does not build a cookie response when required audit persistence fails`, async () => {
    let responseCookie: string | undefined;

    await assert.rejects(
      createLoginResponseAfterRequiredAudit(
        async () => { throw new Error("synthetic database error"); },
        () => {
          responseCookie = `${cookieName}=synthetic-proof`;
          return { headers: { "set-cookie": responseCookie } };
        }
      ),
      (error: unknown) => {
        assert.ok(error instanceof RequiredLoginAuditError);
        assert.equal(error.message, "Required login audit persistence failed.");
        return true;
      }
    );

    assert.equal(responseCookie, undefined);
  });
}

test("login response cookie is created only after required audit persistence succeeds", async () => {
  const order: string[] = [];

  const response = await createLoginResponseAfterRequiredAudit(
    async () => { order.push("audit"); },
    () => {
      order.push("session-cookie");
      return { cookie: "bielos-session=synthetic-proof" };
    }
  );

  assert.deepEqual(order, ["audit", "session-cookie"]);
  assert.deepEqual(response, { cookie: "bielos-session=synthetic-proof" });
});

test("verification login returns a no-store 503 when its required audit fails", async () => {
  let sessionCookieCreated = false;

  const response = await createLoginResponseAfterRequiredAudit(
    async () => { throw new Error("synthetic database error"); },
    () => {
      sessionCookieCreated = true;
      return new Response("redirect", { status: 303, headers: { "set-cookie": "bielos-session=synthetic-proof" } });
    },
    () => new Response("Service Unavailable", { status: 503, headers: { "cache-control": "no-store" } })
  );

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(sessionCookieCreated, false);
});
