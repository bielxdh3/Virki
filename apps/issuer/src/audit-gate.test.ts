import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { installAuditResponseGate, requireAuditBeforeResponse } from "./audit-gate";

test("OIDC responses wait for required audit persistence and fail closed without leaking response data", async (context) => {
  let finishAudit!: () => void;
  let auditStarted!: () => void;
  const allowAudit = new Promise<void>((resolve) => { finishAudit = resolve; });
  const requestReachedGate = new Promise<void>((resolve) => { auditStarted = resolve; });
  let responseFinished = false;
  const server = createServer((request, response) => {
    installAuditResponseGate(response);
    response.on("finish", () => { responseFinished = true; });

    if (request.url === "/issued") {
      requireAuditBeforeResponse(response, allowAudit);
      auditStarted();
      response.statusCode = 302;
      response.setHeader("location", "https://client.invalid/callback?code=synthetic-code");
      response.setHeader("set-cookie", "oidc=synthetic-session; HttpOnly; Secure");
      response.end();
      return;
    }

    if (request.url === "/withheld") {
      requireAuditBeforeResponse(response, Promise.reject(new Error("synthetic audit storage failure")));
      response.statusCode = 302;
      response.setHeader("location", "https://client.invalid/callback?code=synthetic-code");
      response.setHeader("set-cookie", "oidc=synthetic-session; HttpOnly; Secure");
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ access_token: "synthetic-access-token" }));
      return;
    }

    response.statusCode = 204;
    response.end();
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  context.after(() => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));

  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const issuedResponsePromise = fetch(`${baseUrl}/issued`, { redirect: "manual" });
  await requestReachedGate;
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(responseFinished, false, "the authorization response must wait for its audit write");

  finishAudit();
  const issuedResponse = await issuedResponsePromise;
  assert.equal(issuedResponse.status, 302);
  assert.equal(issuedResponse.headers.get("location"), "https://client.invalid/callback?code=synthetic-code");
  assert.match(issuedResponse.headers.get("set-cookie") ?? "", /oidc=synthetic-session/u);

  const withheldResponse = await fetch(`${baseUrl}/withheld`, { redirect: "manual" });
  assert.equal(withheldResponse.status, 503);
  assert.deepEqual(await withheldResponse.json(), { error: "temporarily_unavailable" });
  assert.equal(withheldResponse.headers.get("location"), null);
  assert.equal(withheldResponse.headers.get("set-cookie"), null);
  assert.equal(withheldResponse.headers.get("cache-control"), "no-store");

  const ordinaryResponse = await fetch(`${baseUrl}/ordinary`, { redirect: "manual" });
  assert.equal(ordinaryResponse.status, 204);
});
