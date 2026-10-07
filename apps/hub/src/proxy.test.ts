import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { evaluateProxyRequest } from "./proxy";

const env = { VIRKI_HUB_HOSTNAME: "hub.biel.dev.br", VIRKI_PORTAL_HOSTNAME: "portal.biel.dev.br", CLOUDFLARE_ACCESS_JWT_REQUIRED: "true" };

test("unknown hosts are denied and the hub requires a valid Access assertion", async () => {
  assert.equal((await evaluateProxyRequest(new NextRequest("https://other.invalid/", { headers: { host: "other.invalid" } }), env)).status, 404);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br" } }), env)).status, 403);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/api/health", { headers: { host: "hub.biel.dev.br" } }), env)).status, 200);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/login", { headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "forged" } }), env)).status, 403);
});

test("portal OIDC endpoints are public to clients while account surfaces still require a session", async () => {
  for (const path of ["/.well-known/openid-configuration", "/auth", "/auth/abcdefghijklmnop", "/token", "/token/revocation", "/jwks", "/me", "/session/end", "/interaction/abcdefghijklmnop"]) {
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
