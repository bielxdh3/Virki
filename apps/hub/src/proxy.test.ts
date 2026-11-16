import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { SESSION_COOKIE_NAME } from "@virki/auth/constants";
import { evaluateProxyRequest } from "./proxy";
import { createHubRenderProof } from "./lib/hub-render-provenance";
import { prisma } from "@virki/database";

const env = { VIRKI_HUB_HOSTNAME: "hub.biel.dev.br", VIRKI_PORTAL_HOSTNAME: "portal.biel.dev.br", CLOUDFLARE_ACCESS_JWT_REQUIRED: "true" };

test("ingress replaces spoofed correlation and records Cloudflare denials without forwarding values", async () => {
  const original = prisma.auditLog.create;
  const rows: unknown[] = [];
  prisma.auditLog.create = (async ({ data }: { data: unknown }) => { rows.push(data); return {}; }) as unknown as typeof original;
  try {
    const denied = await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/admin/audit?token=synthetic", { headers: { host: "hub.biel.dev.br", "x-request-id": "spoof", "x-virki-audit-request-id": "spoof", "cf-connecting-ip": "203.0.113.1" } }), { ...env, CLOUDFLARE_ACCESS_AUDIENCE: "test-audience", CLOUDFLARE_TEAM_DOMAIN: "https://access.invalid" });
    assert.equal(denied.status, 403);
    assert.equal(rows.length, 1);
    assert.match(JSON.stringify(rows), /ACCESS_JWT_MISSING/u);
    assert.doesNotMatch(JSON.stringify(rows), /spoof|synthetic|203\.0\.113/u);
    const response = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/login", { headers: { host: "portal.biel.dev.br", "x-virki-audit-request-id": "spoof" } }), env);
    assert.match(response.headers.get("x-middleware-request-x-virki-audit-request-id") ?? "", /^[a-f0-9-]{36}$/u);
    assert.equal(response.headers.get("x-middleware-request-x-virki-audit-route"), "/login");
    assert.equal(response.headers.get("x-middleware-request-x-virki-audit-method"), "GET");
  } finally { prisma.auditLog.create = original; }
});

test("production Hub denies missing and forged Access JWT within the deadline when audit persistence stalls", async () => {
  const original = prisma.auditLog.create;
  let finishWrite: (() => void) | undefined;
  const stalledWrite = new Promise<void>((resolve) => { finishWrite = resolve; });
  prisma.auditLog.create = (async () => { await stalledWrite; return {}; }) as unknown as typeof original;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    const requests = [
      new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br" } }),
      new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "forged" } })
    ];
    const responses = await Promise.race([
      Promise.all(requests.map((request) => evaluateProxyRequest(request, { ...env, NODE_ENV: "production" }))),
      new Promise<never>((_, reject) => { deadline = setTimeout(() => reject(new Error("Hub denial waited for the unavailable audit database.")), 2_500); })
    ]);
    for (const response of responses) assert.equal(response.status, 403);
  } finally {
    if (deadline) clearTimeout(deadline);
    finishWrite?.();
    prisma.auditLog.create = original;
  }
});

test("unknown hosts are denied and the hub requires a valid Access assertion", async () => {
  assert.equal((await evaluateProxyRequest(new NextRequest("https://other.invalid/", { headers: { host: "other.invalid" } }), env)).status, 404);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br" } }), env)).status, 403);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/api/health", { headers: { host: "hub.biel.dev.br" } }), env)).status, 200);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/login", { headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "forged" } }), env)).status, 403);
});

test("portal OIDC endpoints are public to clients while account surfaces still require a session", async () => {
  for (const path of ["/.well-known/openid-configuration", "/auth", "/auth/abcdefghijklmnop", "/token", "/token/revocation", "/jwks", "/me", "/session/end", "/session/end/confirm", "/session/end/success", "/interaction/abcdefghijklmnop"]) {
    assert.equal((await evaluateProxyRequest(new NextRequest(`https://portal.biel.dev.br${path}`, { headers: { host: "portal.biel.dev.br" } }), env)).status, 200, path);
  }
  assert.equal((await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/auth/short/nested", { headers: { host: "portal.biel.dev.br" } }), env)).status, 307);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/auth/abcdefghijklmnop", { headers: { host: "hub.biel.dev.br" } }), env)).status, 403);
  const protectedResponse = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/account/security", { headers: { host: "portal.biel.dev.br" } }), env);
  assert.equal(protectedResponse.status, 307);
  assert.equal(protectedResponse.headers.get("location"), "https://portal.biel.dev.br/login?returnTo=%2Faccount%2Fsecurity");
  const spoofedReturn = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/account/security?tab=mfa", { headers: { host: "portal.biel.dev.br", "x-virki-request-path": "/admin/accounts" } }), env);
  assert.equal(spoofedReturn.headers.get("location"), "https://portal.biel.dev.br/login?returnTo=%2Faccount%2Fsecurity%3Ftab%3Dmfa");
});

test("password-verified backup factor selection reaches the public route without a login session", async () => {
  const response = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/api/login/factor", {
    method: "POST", headers: { host: "portal.biel.dev.br" }
  }), env);
  assert.equal(response.status, 200, "the form must reach the challenge-bound route instead of redirecting to login");
  assert.equal(response.headers.get("x-middleware-request-x-virki-audit-route"), "/api/login/factor");
  assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0, must-revalidate");
});

test("authenticated portal pages receive the no-store policy from the production Proxy boundary", async () => {
  const response = await evaluateProxyRequest(
    new NextRequest("https://portal.biel.dev.br/account/security", {
      headers: { host: "portal.biel.dev.br", cookie: `${SESSION_COOKIE_NAME}=synthetic-session` }
    }),
    { ...env, NODE_ENV: "production" }
  );
  assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0, must-revalidate");
});

test("production login redirects use the canonical portal origin behind an internal request URL", async () => {
  const response = await evaluateProxyRequest(
    new NextRequest("http://hub:3001/account/security?tab=mfa", {
      headers: { host: "portal.biel.dev.br", "x-forwarded-host": "attacker.invalid" }
    }),
    { ...env, NODE_ENV: "production" }
  );
  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "https://portal.biel.dev.br/login?returnTo=%2Faccount%2Fsecurity%3Ftab%3Dmfa");
});

test("hub login and admin routes reject unverified Access assertions", async () => {
  const response = await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "opaque-for-proxy-layer-only" } }), env);
  assert.equal(response.status, 403);
});

test("E2E Access diagnostics expose only a safe reason in development", async () => {
  const request = new NextRequest("https://hub.biel.dev.br/admin/accounts", {
    headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "opaque-for-proxy-layer-only" }
  });
  const diagnosticEnv = {
    ...env,
    NODE_ENV: "development",
    CLOUDFLARE_ACCESS_AUDIENCE: "proxy-test-audience",
    CLOUDFLARE_TEAM_DOMAIN: "https://proxy-test.example.invalid",
    VIRKI_E2E_ACCESS_DIAGNOSTICS: "true"
  };
  const developmentResponse = await evaluateProxyRequest(request, diagnosticEnv);
  assert.equal(developmentResponse.status, 403);
  assert.equal(developmentResponse.headers.get("x-virki-e2e-access-reason"), "invalid-cloudflare-access-jwt");

  const productionResponse = await evaluateProxyRequest(request, { ...diagnosticEnv, NODE_ENV: "production" });
  assert.equal(productionResponse.status, 403);
  assert.equal(productionResponse.headers.has("x-virki-e2e-access-reason"), false);
});

test("production Hub fails closed when the Access requirement flag is missing or false", async () => {
  for (const accessFlag of [undefined, "false"]) {
    const productionEnv = {
      VIRKI_HUB_HOSTNAME: "hub.biel.dev.br",
      VIRKI_PORTAL_HOSTNAME: "portal.biel.dev.br",
      NODE_ENV: "production",
      ...(accessFlag === undefined ? {} : { CLOUDFLARE_ACCESS_JWT_REQUIRED: accessFlag })
    };
    const response = await evaluateProxyRequest(
      new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br" } }),
      productionEnv
    );
    assert.equal(response.status, 403);
  }
});

test("production loopback and Compose host names only reach the health probe", async () => {
  const productionEnv = { ...env, NODE_ENV: "production" };
  for (const host of ["localhost", "127.0.0.1", "hub", "portal"]) {
    for (const path of ["/admin/accounts", "/admin/audit", "/login", "/account/security", "/auth"]) {
      const response = await evaluateProxyRequest(
        new NextRequest(`http://${host}:3001${path}`, { headers: { host: `${host}:3001`, cookie: "virki_session=forged", rsc: "1" } }),
        productionEnv
      );
      assert.equal(response.status, 404, `${host}${path}`);
    }
    const health = await evaluateProxyRequest(new NextRequest(`http://${host}:3001/api/health`, { headers: { host: `${host}:3001` } }), productionEnv);
    assert.equal(health.status, 200, `${host}/api/health`);
  }
});

test("development Hub keeps its explicit local Access opt-out", async () => {
  const response = await evaluateProxyRequest(
    new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br" } }),
    { ...env, NODE_ENV: "development", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false" }
  );
  assert.equal(response.status, 307);
});

test("unauthenticated Hub account-security requests keep a safe ADMIN login return path", async () => {
  const response = await evaluateProxyRequest(
    new NextRequest("https://hub.biel.dev.br/account/security?tab=mfa", { headers: { host: "hub.biel.dev.br" } }),
    { ...env, NODE_ENV: "development", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false" }
  );
  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "https://hub.biel.dev.br/login?returnTo=%2Faccount%2Fsecurity%3Ftab%3Dmfa");
});

const nonceOf = (csp: string) => /'nonce-([A-Za-z0-9+/=]+)'/u.exec(csp)?.[1];

test("every proxy response path carries one nonce CSP with the hardened directives", async () => {
  const requests: Array<[string, Record<string, string>]> = [
    ["https://other.invalid/", { host: "other.invalid" }],
    ["https://hub.biel.dev.br/admin/accounts", { host: "hub.biel.dev.br" }],
    ["https://portal.biel.dev.br/login", { host: "portal.biel.dev.br" }],
    ["https://portal.biel.dev.br/account/security", { host: "portal.biel.dev.br" }],
    ["https://portal.biel.dev.br/account/security", { host: "portal.biel.dev.br", cookie: `${SESSION_COOKIE_NAME}=x` }]
  ];
  for (const [url, headers] of requests) {
    const response = await evaluateProxyRequest(new NextRequest(url, { headers }), { ...env, NODE_ENV: "production" });
    const csp = response.headers.get("content-security-policy") ?? "";
    assert.ok(nonceOf(csp), `${url} nonce`);
    for (const directive of ["default-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "upgrade-insecure-requests", "connect-src 'self'"]) {
      assert.ok(csp.split("; ").includes(directive), `${url} ${directive}`);
    }
    assert.match(csp, /script-src 'self' 'nonce-[^']+' 'strict-dynamic'(?:;|$)/u);
    assert.match(csp, /style-src 'self' 'nonce-[^']+'(?:;|$)/u);
    assert.doesNotMatch(csp, /unsafe-eval|unsafe-inline/u);
  }
});

test("CSP nonces are unique per request, forwarded to the app, and eval is development-only", async () => {
  const make = () => new NextRequest("https://portal.biel.dev.br/login", { headers: { host: "portal.biel.dev.br", "x-nonce": "spoofed" } });
  const first = await evaluateProxyRequest(make(), { ...env, NODE_ENV: "production" });
  const second = await evaluateProxyRequest(make(), { ...env, NODE_ENV: "production" });
  const firstNonce = nonceOf(first.headers.get("content-security-policy") ?? "");
  assert.ok(firstNonce && firstNonce.length >= 22);
  assert.notEqual(firstNonce, nonceOf(second.headers.get("content-security-policy") ?? ""));
  assert.equal(first.headers.get("x-middleware-request-x-nonce"), firstNonce);
  assert.equal(first.headers.get("x-middleware-request-content-security-policy"), first.headers.get("content-security-policy"));

  const development = await evaluateProxyRequest(make(), { ...env, NODE_ENV: "development" });
  const developmentCsp = development.headers.get("content-security-policy") ?? "";
  assert.match(developmentCsp, /'unsafe-eval'/u);
  assert.doesNotMatch(developmentCsp, /upgrade-insecure-requests/u);
  assert.doesNotMatch(first.headers.get("content-security-policy") ?? "", /unsafe-eval/u);
});

test("form-action stays self except on portal login pages that can end in a relying-party redirect", async () => {
  const csp = async (url: string, host: string) => (await evaluateProxyRequest(new NextRequest(url, { headers: { host } }), env)).headers.get("content-security-policy") ?? "";
  assert.match(await csp("https://hub.biel.dev.br/api/health", "hub.biel.dev.br"), /form-action 'self'/u);
  assert.match(await csp("https://portal.biel.dev.br/recover", "portal.biel.dev.br"), /form-action 'self'/u);
  assert.doesNotMatch(await csp("https://portal.biel.dev.br/login", "portal.biel.dev.br"), /form-action/u);
  assert.doesNotMatch(await csp("https://portal.biel.dev.br/login/verify", "portal.biel.dev.br"), /form-action/u);
});

test("issuer-proxied OIDC paths are left to the issuer's own single CSP", async () => {
  for (const path of ["/auth/abcdefghijklmnop", "/token", "/session/end", "/session/end/confirm", "/session/end/success", "/interaction/abcdefghijklmnop", "/.well-known/openid-configuration"]) {
    const response = await evaluateProxyRequest(new NextRequest(`https://portal.biel.dev.br${path}`, { headers: { host: "portal.biel.dev.br" } }), env);
    assert.equal(response.headers.get("content-security-policy"), null, path);
  }
});

test("client-supplied internal request-path header never reaches the app", async () => {
  const forwarded = (response: Response) => response.headers.get("x-middleware-request-x-virki-request-path");
  const spoof = { host: "portal.biel.dev.br", "x-virki-request-path": "/admin/accounts" };

  const publicResponse = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/login", { headers: spoof }), env);
  assert.equal(publicResponse.status, 200);
  assert.equal(forwarded(publicResponse), null);

  const healthResponse = await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/api/health", { headers: { ...spoof, host: "hub.biel.dev.br" } }), env);
  assert.equal(forwarded(healthResponse), null);

  const protectedResponse = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/account/security?tab=mfa", { headers: { ...spoof, cookie: `${SESSION_COOKIE_NAME}=x` } }), env);
  assert.equal(protectedResponse.status, 200);
  assert.equal(forwarded(protectedResponse), "/account/security?tab=mfa");
});

test("proxy binds forwarded host to ingress host, preventing spoofed internal Hub page context", async () => {
  const forwardedHost = (response: Response) => response.headers.get("x-middleware-request-x-forwarded-host");
  for (const host of ["localhost", "portal.biel.dev.br", "hub.biel.dev.br"] as const) {
    const response = await evaluateProxyRequest(new NextRequest(`https://${host}/admin/access`, {
      headers: {
        host,
        "x-forwarded-host": "hub.biel.dev.br",
        "x-virki-request-path": "/admin/access",
        cookie: `${SESSION_COOKIE_NAME}=synthetic`
      }
    }), { ...env, NODE_ENV: "development", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false" });
    assert.equal(response.status, 200);
    assert.equal(forwardedHost(response), host);
    assert.equal(response.headers.get("x-middleware-request-x-virki-request-path"), "/admin/access");
  }
});

test("only a valid session-bound Hub proof survives the loopback internal render boundary", async () => {
  const environment = { ...env, NODE_ENV: "production" as const, VIRKI_CSRF_SIGNING_KEY: "ab".repeat(32) };
  const proof = createHubRenderProof("synthetic", environment);
  assert.ok(proof);
  const request = (value: string) => new NextRequest("http://localhost/admin/access?status=granted", {
    headers: {
      host: "localhost",
      "x-forwarded-host": "hub.biel.dev.br",
      "x-virki-request-path": "/admin/forged",
      "x-virki-hub-render-proof": value,
      cookie: `${SESSION_COOKIE_NAME}=synthetic`
    }
  });
  const permitted = await evaluateProxyRequest(request(proof), environment);
  assert.equal(permitted.status, 200);
  assert.equal(permitted.headers.get("x-middleware-request-x-forwarded-host"), "hub.biel.dev.br");
  assert.equal(permitted.headers.get("x-middleware-request-x-virki-hub-render-proof"), proof);
  assert.equal(permitted.headers.get("x-middleware-request-x-virki-request-path"), "/admin/access?status=granted");
  const refused = await evaluateProxyRequest(request("forged"), environment);
  assert.equal(refused.status, 404);
  assert.equal(refused.headers.get("x-middleware-request-x-virki-hub-render-proof"), null);
});


test("obsolete recovery API requires authentication while real recovery routes stay public", async () => {
  for (const path of ["/recover", "/recover/open"]) assert.equal((await evaluateProxyRequest(new NextRequest(`https://portal.biel.dev.br${path}`, { headers: { host: "portal.biel.dev.br" } }), env)).status, 200);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/api/recover", { headers: { host: "portal.biel.dev.br" } }), env)).status, 307);
});

test("sensitive public authentication responses carry no-store and server-generated correlation", async () => {
  for (const path of ["/login", "/login/verify", "/api/login", "/api/login/verify", "/api/passkeys", "/api/logout", "/recover", "/recover/open"]) {
    const response = await evaluateProxyRequest(new NextRequest(`https://portal.biel.dev.br${path}`, { headers: { host: "portal.biel.dev.br", "x-virki-audit-request-id": "spoof" } }), env);
    assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0, must-revalidate", path);
    const correlation = response.headers.get("x-virki-request-id") ?? "";
    assert.match(correlation, /^[a-f0-9-]{36}$/u, path);
    assert.equal(correlation, response.headers.get("x-middleware-request-x-virki-audit-request-id"), path);
  }
});

test("root and admin audit attribution replace untrusted route headers", async () => {
  for (const [host, path] of [["portal.biel.dev.br", "/"], ["hub.biel.dev.br", "/admin/"]] as const) {
    const response = await evaluateProxyRequest(new NextRequest(`https://${host}${path}`, { headers: { host, cookie: `${SESSION_COOKIE_NAME}=synthetic`, "x-virki-audit-route": "/forged" } }), { ...env, NODE_ENV: "development", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false" });
    assert.equal(response.headers.get("x-middleware-request-x-virki-audit-route"), path === "/" ? "/" : "/admin");
  }
});

test("explicit native Hub mode exposes only login and recovery without granting an ADMIN session", async () => {
  const native = { ...env, NODE_ENV: "production", VIRKI_HUB_PERIMETER_MODE: "native" };
  for (const route of ["/login", "/login/verify", "/recover", "/recover/open"]) {
    const response = await evaluateProxyRequest(new NextRequest(`https://hub.biel.dev.br${route}`, {
      headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "forged" }
    }), native);
    assert.equal(response.status, 200, route);
    assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0, must-revalidate");
    assert.equal(response.headers.get("x-middleware-request-cf-access-jwt-assertion"), null);
  }
  const protectedResponse = await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/admin/accounts", {
    headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "forged" }
  }), native);
  assert.equal(protectedResponse.status, 307);
  assert.equal(protectedResponse.headers.get("location"), "https://hub.biel.dev.br/login?returnTo=%2Fadmin%2Faccounts");
  assert.equal((await evaluateProxyRequest(new NextRequest("https://other.invalid/recover", {
    headers: { host: "other.invalid" }
  }), native)).status, 404);
  for (const value of ["NATIVE", "true", "enabled", "", "access"]) {
    const response = await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/recover", {
      headers: { host: "hub.biel.dev.br" }
    }), { ...native, VIRKI_HUB_PERIMETER_MODE: value });
    assert.equal(response.status, 403, `invalid or default mode: ${value}`);
  }
});
