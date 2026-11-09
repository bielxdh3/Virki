import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { VirkiOidcNodeClient, validateClientOptions, validateIssuerEndpoints, type OidcProtocol } from "./client.js";
import { MemoryTransactionStore } from "./store.js";

const browser1 = randomBytes(32).toString("base64url");
const browser2 = randomBytes(32).toString("base64url");
const fixed = {
  issuer: "https://portal.biel.dev.br",
  redirectUri: "https://project.example.invalid/callback",
  clientId: "biel_confidential",
  clientSecret: "a-secret-only-on-server",
  store: new MemoryTransactionStore()
};

function mockProtocol() {
  let redeems = 0;
  const parameters: URLSearchParams[] = [];
  const protocol: OidcProtocol = {
    authorizationUrl(params) {
      parameters.push(new URLSearchParams(params));
      const url = new URL("https://portal.biel.dev.br/auth");
      url.search = new URLSearchParams(params).toString();
      return url;
    },
    async redeem(_callback, checks) {
      redeems++;
      return {
        claims: {
          iss: fixed.issuer,
          aud: fixed.clientId,
          sub: "user-1",
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 300,
          nonce: checks.expectedNonce,
          amr: ["webauthn"],
          acr: "urn:virki:loa:1"
        },
        accessToken: ["synthetic", "opaque", "access", "token"].join("-")
      };
    },
    async revokeToken() {}
  };
  return { protocol, parameters, get redeems() { return redeems; } };
}

test("requires confidential HTTPS exact issuer/redirect, rejects malformed endpoints", () => {
  assert.equal(validateClientOptions(fixed).issuer, fixed.issuer);
  for (const issuer of ["http://portal.biel.dev.br", "https://portal.biel.dev.br/x", "https://user@portal.biel.dev.br", "https://portal.biel.dev.br?x=y"]) {
    assert.throws(() => validateClientOptions({ ...fixed, issuer }));
  }
  for (const redirectUri of ["http://project.example.invalid/callback", "https://project.example.invalid/callback#fragment", "https://project.example.invalid/callback?query=yes", "https://other@project.example.invalid/callback"]) {
    assert.throws(() => validateClientOptions({ ...fixed, redirectUri }));
  }
  assert.throws(() => validateClientOptions({ ...fixed, clientSecret: "" }));
  assert.throws(() => validateIssuerEndpoints({ issuer: fixed.issuer, authorization_endpoint: "https://evil.example/auth", token_endpoint: "https://portal.biel.dev.br/token", jwks_uri: "https://portal.biel.dev.br/jwks" }, fixed.issuer));
  assert.doesNotThrow(() => validateIssuerEndpoints({ issuer: fixed.issuer, authorization_endpoint: "https://portal.biel.dev.br/auth", token_endpoint: "https://portal.biel.dev.br/token", jwks_uri: "https://portal.biel.dev.br/jwks" }, fixed.issuer));
});

test("optional server-only Access backchannel refuses partial or malformed credential pairs", () => {
  assert.doesNotThrow(() => validateClientOptions(fixed));
  assert.doesNotThrow(() => validateClientOptions({ ...fixed,
    cloudflareAccess: { clientId: "synthetic-access-id", clientSecret: "synthetic-access-secret" }
  }));
  for (const cloudflareAccess of [
    {}, { clientId: "synthetic-access-id" }, { clientSecret: "synthetic-access-secret" },
    { clientId: "", clientSecret: "synthetic-access-secret" },
    { clientId: "synthetic-access-id", clientSecret: "" },
    { clientId: "synthetic-access-id\r\nInjected: yes", clientSecret: "synthetic-access-secret" },
    { clientId: "synthetic-access-id", clientSecret: "synthetic-access-secret\nInjected: yes" },
    { clientId: "synthetic-access-id", clientSecret: "synthetic-access-secret", surprise: "test" }
  ]) {
    assert.throws(() => validateClientOptions({ ...fixed, cloudflareAccess } as never), /Invalid.*OIDC.*configuration/u);
  }
});

test("two tabs share browser binding without overwriting flows, callback consumes once", async () => {
  const mocked = mockProtocol();
  const client = new VirkiOidcNodeClient(fixed, mocked.protocol);
  const first = await client.beginLogin(browser1);
  const second = await client.beginLogin(browser1);
  assert.notEqual(first.url.searchParams.get("state"), second.url.searchParams.get("state"));
  for (const start of [second, first]) {
    const callback = new URL(fixed.redirectUri);
    callback.searchParams.set("state", start.url.searchParams.get("state")!);
    callback.searchParams.set("code", "fake-code");
    const completed = await client.completeCallback(callback, browser1);
    assert.equal(completed.identity.sub, "user-1");
    assert.deepEqual(completed.identity.amr, ["webauthn"]);
    await assert.rejects(client.completeCallback(callback, browser1));
  }
  assert.equal(mocked.redeems, 2);
  assert.equal(mocked.parameters.length, 2);
  for (const params of mocked.parameters) {
    assert.equal(params.get("code_challenge_method"), "S256");
    assert.equal(params.get("scope"), "openid profile email");
    assert.ok(params.get("nonce"));
    assert.ok(params.get("state"));
    assert.ok(params.get("code_challenge"));
    assert.equal(params.has("client_secret"), false);
    assert.equal(params.has("code_verifier"), false);
  }
});

test("wrong browser consumes flow, so attacker cannot retry with stolen state", async () => {
  const mocked = mockProtocol();
  const client = new VirkiOidcNodeClient({ ...fixed, store: new MemoryTransactionStore() }, mocked.protocol);
  const begin = await client.beginLogin(browser1);
  const callback = new URL(fixed.redirectUri);
  callback.searchParams.set("state", begin.url.searchParams.get("state")!);
  callback.searchParams.set("code", "fake-code");
  await assert.rejects(client.completeCallback(callback, browser2));
  await assert.rejects(client.completeCallback(callback, browser1));
  assert.equal(mocked.redeems, 0);
});

test("failed token exchange still burns state; callback redirect and parameter pollution fail closed", async () => {
  const mocked = mockProtocol();
  const client = new VirkiOidcNodeClient({ ...fixed, store: new MemoryTransactionStore() }, {
    ...mocked.protocol,
    async redeem() { throw new Error("secret-containing network failure"); }
  });
  const started = await client.beginLogin(browser1);
  const good = new URL(fixed.redirectUri);
  good.searchParams.set("state", started.url.searchParams.get("state")!);
  good.searchParams.set("code", "fake-code");
  const wrong = new URL(good);
  wrong.pathname = "/wrong-callback";
  await assert.rejects(client.completeCallback(wrong, browser1));
  const duplicate = new URL(good);
  duplicate.searchParams.append("code", "second-code");
  await assert.rejects(client.completeCallback(duplicate, browser1));
  await assert.rejects(client.completeCallback(good, browser1), (error: unknown) => error instanceof Error && !error.message.includes("secret-containing"));
  await assert.rejects(client.completeCallback(good, browser1));
});

test("OAuth error and expired flow are single use and do not redeem code", async () => {
  const mocked = mockProtocol();
  const client = new VirkiOidcNodeClient({ ...fixed, store: new MemoryTransactionStore(), transactionTtlMs: 1000 }, mocked.protocol);
  const started = await client.beginLogin(browser1);
  const callback = new URL(fixed.redirectUri);
  callback.searchParams.set("state", started.url.searchParams.get("state")!);
  callback.searchParams.set("error", "access_denied");
  await assert.rejects(client.completeCallback(callback, browser1));
  callback.searchParams.delete("error");
  callback.searchParams.set("code", "fake-code");
  await assert.rejects(client.completeCallback(callback, browser1));
  assert.equal(mocked.redeems, 0);
});
