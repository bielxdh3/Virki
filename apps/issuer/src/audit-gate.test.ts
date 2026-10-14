import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { installAuditResponseGate, requireAuditBeforeResponse } from "./audit-gate";
import { setIssuerSecurityHeaders, setIssuerSensitiveResponseCachePolicy } from "./http-security";

test("issuer applies frame, MIME, referrer, and production transport headers", () => {
  const values = new Map<string, string>();
  const response = { setHeader: (name: string, value: string) => values.set(name.toLowerCase(), value) } as never;

  setIssuerSecurityHeaders(response, true);
  assert.match(values.get("content-security-policy") ?? "", /(?:^|; )frame-ancestors 'none'(?:;|$)/u);
  assert.equal(values.get("permissions-policy"), "camera=(), geolocation=(), microphone=()");
  assert.equal(values.get("referrer-policy"), "no-referrer");
  assert.equal(values.get("x-content-type-options"), "nosniff");
  assert.equal(values.get("x-frame-options"), "DENY");
  assert.equal(values.get("strict-transport-security"), "max-age=31536000");

  values.clear();
  setIssuerSecurityHeaders(response, false);
  assert.equal(values.has("strict-transport-security"), false);
  assert.equal(values.get("x-frame-options"), "DENY");
});

test("personalized OIDC authorization and interaction responses are no-store without disabling public metadata caching", async (context) => {
  const server = createServer((request, response) => {
    const pathname = new URL(request.url ?? "/", "http://issuer.invalid").pathname;
    setIssuerSensitiveResponseCachePolicy(response, pathname);
    if (pathname === "/.well-known/openid-configuration" || pathname === "/jwks") {
      response.setHeader("Cache-Control", "public, max-age=300");
    }
    response.statusCode = 303;
    response.setHeader("Location", "/login");
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
  for (const path of ["/auth?state=synthetic-state&nonce=synthetic-nonce", "/interaction/abcdefgh?marker=synthetic-marker"]) {
    const response = await fetch(`${baseUrl}${path}`, { redirect: "manual" });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }

  for (const path of ["/.well-known/openid-configuration", "/jwks"]) {
    const response = await fetch(`${baseUrl}${path}`, { redirect: "manual" });
    assert.equal(response.headers.get("cache-control"), "public, max-age=300");
  }
});

test("OIDC responses wait for required audit persistence and fail closed without leaking response data", async (context) => {
  let finishAudit!: () => void;
  let auditStarted!: () => void;
  let finishWrittenAudit!: () => void;
  let writtenAuditStarted!: () => void;
  const allowAudit = new Promise<void>((resolve) => { finishAudit = resolve; });
  const requestReachedGate = new Promise<void>((resolve) => { auditStarted = resolve; });
  const allowWrittenAudit = new Promise<void>((resolve) => { finishWrittenAudit = resolve; });
  const writtenReachedGate = new Promise<void>((resolve) => { writtenAuditStarted = resolve; });
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

    if (request.url === "/written") {
      requireAuditBeforeResponse(response, allowWrittenAudit);
      response.statusCode = 200;
      response.setHeader("set-cookie", "oidc=synthetic-session; HttpOnly; Secure");
      response.writeHead(200, { "content-type": "text/plain" });
      response.write("issued-");
      response.flushHeaders();
      response.end("token-body");
      writtenAuditStarted();
      return;
    }

    if (request.url === "/written-withheld") {
      requireAuditBeforeResponse(response, Promise.reject(new Error("synthetic audit storage failure")));
      response.writeHead(200, { "content-type": "application/json", location: "https://client.invalid/callback?code=synthetic-code" });
      response.write(JSON.stringify({ access_token: "synthetic-access-token" }));
      response.flushHeaders();
      response.end();
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

  responseFinished = false;
  const writtenResponsePromise = fetch(`${baseUrl}/written`, { redirect: "manual" });
  await writtenReachedGate;
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(responseFinished, false, "write(), writeHead(), and flushHeaders() must not bypass pending audit storage");
  finishWrittenAudit();
  const writtenResponse = await writtenResponsePromise;
  assert.equal(writtenResponse.status, 200);
  assert.equal(await writtenResponse.text(), "issued-token-body");
  assert.match(writtenResponse.headers.get("set-cookie") ?? "", /oidc=synthetic-session/u);

  const writtenWithheldResponse = await fetch(`${baseUrl}/written-withheld`, { redirect: "manual" });
  assert.equal(writtenWithheldResponse.status, 503);
  assert.deepEqual(await writtenWithheldResponse.json(), { error: "temporarily_unavailable" });
  assert.equal(writtenWithheldResponse.headers.get("location"), null);
  assert.equal(writtenWithheldResponse.headers.get("set-cookie"), null);
});
