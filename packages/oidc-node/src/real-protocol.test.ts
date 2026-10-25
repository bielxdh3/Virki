import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import test from "node:test";
import * as oidc from "openid-client";
import { createOidcProtocol, VirkiOidcNodeClient } from "./client.js";
import { MemoryTransactionStore } from "./store.js";

const issuer = "https://portal.biel.dev.br";
const redirectUri = "https://project.example.invalid/callback";
const clientId = "biel_secure_client";
const clientSecret = ["secret", "just", "for", "disposable", "fixture"].join("-");

type TestTokenMode = "valid" | "tampered" | "unknown-key" | "wrong-alg" | "wrong-issuer" | "wrong-audience" | "wrong-nonce" | "expired";

function fixture() {
  const first = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const rotated = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  let signingKey = first;
  let kid = "fixture-k1";
  let mode: TestTokenMode = "valid";
  let activeNonce = "";
  let tokenExchanges = 0;
  let revocations = 0;
  const assertClientSecretBasic = (header: string | null) => {
    if (!header?.startsWith("Basic ")) throw new Error("client_secret_basic is required; no client_secret_post fallback");
    const credentials = Buffer.from(header.slice(6), "base64").toString("utf8").split(":");
    assert.equal(credentials.length, 2);
    assert.equal(decodeURIComponent(credentials[0]), clientId);
    assert.equal(decodeURIComponent(credentials[1]), clientSecret);
  };
  const publiclyTrusted = [first.publicKey.export({ format: "jwk" }) as Record<string, unknown>, rotated.publicKey.export({ format: "jwk" }) as Record<string, unknown>];
  const settings = { issuer, redirectUri, clientId, clientSecret, store: new MemoryTransactionStore() };

  const config = new oidc.Configuration({
    issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    revocation_endpoint: `${issuer}/token/revocation`,
    userinfo_endpoint: `${issuer}/me`,
    response_types_supported: ["code"],
    id_token_signing_alg_values_supported: ["ES256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"]
  }, clientId, { id_token_signed_response_alg: "ES256", token_endpoint_auth_method: "client_secret_basic" }, oidc.ClientSecretBasic(clientSecret));
  oidc.enableNonRepudiationChecks(config);

  config[oidc.customFetch] = async (input, init) => {
    const request = new Request(input, init as RequestInit);
    const path = new URL(request.url).pathname;
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } });
    if (path === "/jwks") {
      return json({ keys: publiclyTrusted.map((key, index) => ({ ...key, kid: index === 0 ? "fixture-k1" : "fixture-k2", use: "sig", alg: "ES256" })) });
    }
    if (path === "/token/revocation") {
      assertClientSecretBasic(request.headers.get("authorization"));
      revocations++;
      return new Response(null, { status: 200 });
    }
    if (path === "/me") {
      assert.match(request.headers.get("authorization") ?? "", /^Bearer /u);
      return json({ sub: "user-1", email: "user@example.invalid" });
    }
    if (path !== "/token") throw new Error(`Unexpected private fixture endpoint ${path}`);
    tokenExchanges++;
    assert.equal(request.method, "POST");
    assertClientSecretBasic(request.headers.get("authorization"));
    const body = new URLSearchParams(await request.text());
    assert.equal(body.get("redirect_uri"), redirectUri);
    assert.equal(body.get("grant_type"), "authorization_code");
    assert.ok((body.get("code_verifier")?.length ?? 0) >= 43);
    assert.equal(body.has("client_secret"), false);
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: mode === "wrong-issuer" ? "https://evil.example" : issuer,
      sub: "user-1",
      aud: mode === "wrong-audience" ? "another-client" : clientId,
      nonce: mode === "wrong-nonce" ? "wrong-nonce" : activeNonce,
      iat: now,
      exp: mode === "expired" ? now - 60 : now + 300,
      auth_time: now,
      amr: ["webauthn"], acr: "urn:virki:loa:1"
    };
    const header = { alg: mode === "wrong-alg" ? "HS256" : "ES256", typ: "JWT", kid: mode === "unknown-key" ? "unknown" : kid };
    const data = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
    const signature = mode === "wrong-alg"
      ? createHmac("sha256", randomBytes(32)).update(data).digest("base64url")
      : sign("sha256", Buffer.from(data), { key: signingKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    const token = `${data}.${mode === "tampered" ? randomBytes(64).toString("base64url") : signature}`;
    return json({ access_token: ["synthetic", "server", "only", "token"].join("-"), id_token: token, token_type: "Bearer", expires_in: 300 });
  };

  const client = new VirkiOidcNodeClient(settings, createOidcProtocol(config));
  return {
    client,
    setMode(next: TestTokenMode) { mode = next; },
    rotateKey() { signingKey = rotated; kid = "fixture-k2"; },
    get tokenExchanges() { return tokenExchanges; },
    get revocations() { return revocations; },
    async roundTrip() {
      const binding = randomBytes(32).toString("base64url");
      const start = await client.beginLogin(binding);
      activeNonce = start.url.searchParams.get("nonce")!;
      const callback = new URL(redirectUri);
      callback.searchParams.set("code", "fixture-code");
      callback.searchParams.set("state", start.url.searchParams.get("state")!);
      return client.completeCallback(callback, binding);
    }
  };
}

test("real openid-client verifies ES256 JWKS, expected nonce, PKCE exchange, and rotated signing key", async () => {
  const f = fixture();
  const initial = await f.roundTrip();
  assert.equal(initial.identity.sub, "user-1");
  assert.deepEqual(initial.identity.amr, ["webauthn"]);
  assert.equal(initial.serverOnly.accessToken, "synthetic-server-only-token");
  f.rotateKey();
  assert.equal((await f.roundTrip()).identity.sub, "user-1");
  assert.equal(f.tokenExchanges, 2);
  await f.client.revokeAccessToken(initial.serverOnly.accessToken);
  assert.equal(f.revocations, 1);
  const info = await f.client.userInfo(initial.serverOnly.accessToken, "user-1") as { sub: string };
  assert.equal(info.sub, "user-1");
});

test("real JOSE processing rejects unsigned, forged, wrong issuer/audience/nonce and expired ID Tokens", async () => {
  for (const mode of ["tampered", "unknown-key", "wrong-alg", "wrong-issuer", "wrong-audience", "wrong-nonce", "expired"] as const) {
    const f = fixture();
    f.setMode(mode);
    await assert.rejects(f.roundTrip(), (error: unknown) => error instanceof Error && error.message === "OIDC callback rejected.", mode);
    assert.equal(f.tokenExchanges, 1, mode);
  }
});
