import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { evaluateProxyRequest } from "./proxy";

const env = { BIELOS_HUB_HOSTNAME: "hub.biel.dev.br", BIELOS_PORTAL_HOSTNAME: "portal.biel.dev.br", CLOUDFLARE_ACCESS_JWT_REQUIRED: "true" };

test("unknown hosts are denied and the hub requires a valid Access assertion", async () => {
  assert.equal((await evaluateProxyRequest(new NextRequest("https://other.invalid/", { headers: { host: "other.invalid" } }), env)).status, 404);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br" } }), env)).status, 403);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/api/health", { headers: { host: "hub.biel.dev.br" } }), env)).status, 200);
  assert.equal((await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/login", { headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "forged" } }), env)).status, 403);
});

test("portal OIDC endpoints are public to clients while account surfaces still require a session", async () => {
  for (const path of ["/.well-known/openid-configuration", "/auth", "/token", "/token/revocation", "/jwks", "/me", "/session/end", "/interaction/abcdefghijklmnop"]) {
    assert.equal((await evaluateProxyRequest(new NextRequest(`https://portal.biel.dev.br${path}`, { headers: { host: "portal.biel.dev.br" } }), env)).status, 200, path);
  }
  const protectedResponse = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/account/security", { headers: { host: "portal.biel.dev.br" } }), env);
  assert.equal(protectedResponse.status, 307);
  assert.equal(protectedResponse.headers.get("location"), "https://portal.biel.dev.br/login?returnTo=%2Faccount%2Fsecurity");
  const spoofedReturn = await evaluateProxyRequest(new NextRequest("https://portal.biel.dev.br/account/security?tab=mfa", { headers: { host: "portal.biel.dev.br", "x-bielos-request-path": "/admin/accounts" } }), env);
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

test("production Hub fails closed when the Access requirement flag is missing or false", async () => {
  for (const accessFlag of [undefined, "false"]) {
    const productionEnv = {
      BIELOS_HUB_HOSTNAME: "hub.biel.dev.br",
      BIELOS_PORTAL_HOSTNAME: "portal.biel.dev.br",
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

test("development Hub keeps its explicit local Access opt-out", async () => {
  const response = await evaluateProxyRequest(
    new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br" } }),
    { ...env, NODE_ENV: "development", CLOUDFLARE_ACCESS_JWT_REQUIRED: "false" }
  );
  assert.equal(response.status, 307);
});
