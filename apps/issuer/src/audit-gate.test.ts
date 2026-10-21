import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import Koa from "koa";
import { installAuditResponseGate, requireAuditBeforeResponse, useNativeOidcResponse } from "./audit-gate";
import { setIssuerSecurityHeaders, setIssuerSensitiveResponseCachePolicy } from "./http-security";

test("each queued audit rejection is observed immediately while earlier writes remain pending", async (context) => {
  const { spawnSync } = await import("node:child_process");
  // A child lets --unhandled-rejections=strict prove there was no transient rejection.
  const result = spawnSync(process.execPath, ["--import", "tsx", "--unhandled-rejections=strict", "--input-type=module", "-e", `
    import { requireAuditBeforeResponse } from './apps/issuer/src/audit-gate.ts';
    const response = {};
    let resolveFirst;
    const first = new Promise(resolve => { resolveFirst = resolve; });
    requireAuditBeforeResponse(response, first);
    requireAuditBeforeResponse(response, Promise.reject(new Error('second audit fails first')));
    requireAuditBeforeResponse(response, Promise.reject(new Error('third audit also fails')));
    await new Promise(resolve => setTimeout(resolve, 30));
    resolveFirst();
    await new Promise(resolve => setImmediate(resolve));
  `], { encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  context.diagnostic("All rejected promises were observed before the first write settled.");
});

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

test("an aborted client connection discards the pending audited response without crashing the issuer", async (context) => {
  let finishAudit!: () => void;
  let reachGate!: () => void;
  const allowAudit = new Promise<void>((resolve) => { finishAudit = resolve; });
  const requestReachedGate = new Promise<void>((resolve) => { reachGate = resolve; });
  const callbackErrors: string[] = [];
  let endCallbackCount = 0;
  const server = createServer((request, response) => {
    installAuditResponseGate(response);
    if (request.url === "/aborted") {
      requireAuditBeforeResponse(response, allowAudit);
      response.statusCode = 302;
      response.setHeader("location", "https://client.invalid/callback?code=private-code");
      response.write("private-", (error) => { if (error) callbackErrors.push(error.message); });
      response.end("response", () => { endCallbackCount++; });
      reachGate();
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
  const request = httpRequest(`http://127.0.0.1:${address.port}/aborted`);
  request.on("error", () => undefined);
  request.end();
  await requestReachedGate;
  request.destroy();
  await new Promise((resolve) => setTimeout(resolve, 10));
  finishAudit();
  await new Promise((resolve) => setTimeout(resolve, 10));

  assert.equal(server.listening, true);
  assert.equal(callbackErrors.length, 1);
  assert.ok(callbackErrors.every((message) => message === "OIDC response closed before required audit persistence completed."));
  assert.equal(endCallbackCount, 1);
  const ordinaryResponse = await fetch(`http://127.0.0.1:${address.port}/ordinary`, { redirect: "manual" });
  assert.equal(ordinaryResponse.status, 204);
});

test("queued duplicate response.end calls cannot crash the issuer or append data after the first end", async (context) => {
  let finishAudit!: () => void;
  let reachGate!: () => void;
  const allowAudit = new Promise<void>((resolve) => { finishAudit = resolve; });
  const requestReachedGate = new Promise<void>((resolve) => { reachGate = resolve; });
  let duplicateEndCallbackCount = 0;
  const server = createServer((request, response) => {
    installAuditResponseGate(response);
    if (request.url === "/duplicate-end") {
      requireAuditBeforeResponse(response, allowAudit);
      response.end("first response", () => undefined);
      response.end("late response", () => { duplicateEndCallbackCount++; });
      reachGate();
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
  const responsePromise = fetch(`http://127.0.0.1:${address.port}/duplicate-end`);
  await requestReachedGate;
  finishAudit();
  const response = await responsePromise;
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "first response");
  assert.equal(duplicateEndCallbackCount, 1);
  assert.equal(server.listening, true);
});

test("invalid response.end chunks fail closed before they enter the bounded audit buffer", async (context) => {
  let finishAudit!: () => void;
  let reachGate!: () => void;
  const allowAudit = new Promise<void>((resolve) => { finishAudit = resolve; });
  const requestReachedGate = new Promise<void>((resolve) => { reachGate = resolve; });
  const callbackErrors: string[] = [];
  let responseErrors = 0;
  const server = createServer((request, response) => {
    response.on("error", (error) => { responseErrors++; callbackErrors.push(error.message); });
    installAuditResponseGate(response);
    if (request.url === "/invalid-end") {
      requireAuditBeforeResponse(response, allowAudit);
      response.statusCode = 200;
      const onEnd = (error?: Error): void => {
        if (error) callbackErrors.push(error.message);
      };
      response.end({ invalid: true } as never, onEnd);
      reachGate();
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
  const responsePromise = fetch(`http://127.0.0.1:${address.port}/invalid-end`, { redirect: "manual" });
  await requestReachedGate;
  finishAudit();
  const response = await responsePromise;
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "temporarily_unavailable" });
  assert.equal(callbackErrors.length, 1);
  assert.match(callbackErrors[0] ?? "", /bounded audit buffer/u);
  assert.equal(responseErrors, 0);
  assert.equal(server.listening, true);
});

test("a required audit registered while the response waits is included before release", async (context) => {
  let finishFirstAudit!: () => void;
  let finishSecondAudit!: () => void;
  let reachGate!: () => void;
  let gatedResponse: import("node:http").ServerResponse | undefined;
  let responseFinished = false;
  const firstAudit = new Promise<void>((resolve) => { finishFirstAudit = resolve; });
  const secondAudit = new Promise<void>((resolve) => { finishSecondAudit = resolve; });
  const requestReachedGate = new Promise<void>((resolve) => { reachGate = resolve; });
  const server = createServer((request, response) => {
    installAuditResponseGate(response);
    response.on("finish", () => { responseFinished = true; });
    if (request.url === "/late-audit") {
      gatedResponse = response;
      requireAuditBeforeResponse(response, firstAudit);
      response.statusCode = 302;
      response.setHeader("location", "https://client.invalid/callback?code=synthetic-code");
      response.end("audited response");
      reachGate();
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
  const responsePromise = fetch(`http://127.0.0.1:${address.port}/late-audit`, { redirect: "manual" });
  await requestReachedGate;
  assert.ok(gatedResponse);
  requireAuditBeforeResponse(gatedResponse, secondAudit);
  finishFirstAudit();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(responseFinished, false);

  finishSecondAudit();
  const response = await responsePromise;
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://client.invalid/callback?code=synthetic-code");
  assert.equal(await response.text(), "audited response");
  assert.equal(responseFinished, true);
});

test("a delayed native OIDC interactionFinished 303 stays complete when Koa automatic responses are disabled", async (context) => {
  let persistAudit!: () => void;
  let interactionFinished!: () => void;
  const audit = new Promise<void>((resolve) => { persistAudit = resolve; });
  const interactionEnded = new Promise<void>((resolve) => { interactionFinished = resolve; });
  const serverErrors: string[] = [];

  const app = new Koa();
  app.use(async (koaContext) => {
    // oidc-provider.interactionFinished() sets these headers and ends the native response.
    requireAuditBeforeResponse(koaContext.res, audit);
    useNativeOidcResponse(koaContext);
    koaContext.res.statusCode = 303;
    koaContext.res.setHeader("location", "/auth/resume");
    koaContext.res.setHeader("content-length", "0");
    koaContext.res.end();
    interactionFinished();
    // The native end is buffered until the audit succeeds; Koa must not emit a second response.
  });
  const koaCallback = app.callback();
  const server = createServer((request, response) => {
    response.on("error", (error) => { serverErrors.push(error.message); });
    installAuditResponseGate(response);
    koaCallback(request, response);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  context.after(() => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));

  const address = server.address() as AddressInfo;
  const result = new Promise<{ complete: boolean; aborted: boolean; status: number; headers: import("node:http").IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const request = httpRequest({ hostname: "127.0.0.1", port: address.port, path: "/interaction", headers: { connection: "close" } }, (response) => {
      const chunks: Buffer[] = [];
      let aborted = false;
      response.on("data", (chunk: Buffer) => { chunks.push(chunk); });
      response.on("aborted", () => { aborted = true; });
      response.on("error", () => undefined);
      response.on("close", () => resolve({ complete: response.complete, aborted, status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.once("error", reject);
    request.end();
  });

  await interactionEnded;
  await new Promise((resolve) => setTimeout(resolve, 25));
  persistAudit();
  const received = await result;
  assert.equal(received.status, 303);
  assert.equal(received.headers.location, "/auth/resume");
  assert.equal(received.headers["content-length"], "0");
  assert.equal(received.body, "");
  assert.equal(received.aborted, false);
  assert.equal(received.complete, true);
  assert.deepEqual(serverErrors, []);
});
