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
  assert.equal(protectedResponse.headers.get("location"), "https://portal.biel.dev.br/login");
});

test("hub login and admin routes reject unverified Access assertions", async () => {
  const response = await evaluateProxyRequest(new NextRequest("https://hub.biel.dev.br/admin/accounts", { headers: { host: "hub.biel.dev.br", "cf-access-jwt-assertion": "opaque-for-proxy-layer-only" } }), env);
  assert.equal(response.status, 403);
});
