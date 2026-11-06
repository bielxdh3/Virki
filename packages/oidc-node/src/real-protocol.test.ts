import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import test from "node:test";
import * as oidc from "openid-client";
import { createOidcProtocol, createVirkiOidcClient, VirkiOidcNodeClient } from "./client.js";
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
  let jwksRequests = 0;
  const publishedKids = new Set(["fixture-k1", "fixture-k2"]);
  const assertClientSecretBasic = (header: string | null) => {
    if (!header?.startsWith("Basic ")) throw new Error("client_secret_basic is required; no client_secret_post fallback");
    const credentials = Buffer.from(header.slice(6), "base64").toString("utf8").split(":");
    assert.equal(credentials.length, 2);
    assert.equal(decodeURIComponent(credentials[0]), clientId);
    assert.equal(decodeURIComponent(credentials[1]), clientSecret);
  };
  const publiclyTrusted = [first.publicKey.export({ format: "jwk" }) as Record<string, unknown>, rotated.publicKey.export({ format: "jwk" }) as Record<string, unknown>];
  const settings = { issuer, redirectUri, clientId, clientSecret, store: new MemoryTransactionStore() };

  const metadata = {
    issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    revocation_endpoint: `${issuer}/token/revocation`,
    userinfo_endpoint: `${issuer}/me`,
    response_types_supported: ["code"],
    id_token_signing_alg_values_supported: ["ES256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"]
  };
  const config = new oidc.Configuration(metadata, clientId, { id_token_signed_response_alg: "ES256", token_endpoint_auth_method: "client_secret_basic" }, oidc.ClientSecretBasic(clientSecret));
  oidc.enableNonRepudiationChecks(config);

  const handleFetch: NonNullable<oidc.Configuration[typeof oidc.customFetch]> = async (input, init) => {
    const request = new Request(input, init as RequestInit);
    const path = new URL(request.url).pathname;
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } });
    if (path === "/jwks") {
      jwksRequests++;
      return json({ keys: publiclyTrusted.map((key, index) => ({ ...key, kid: index === 0 ? "fixture-k1" : "fixture-k2", use: "sig", alg: "ES256" }))
        .filter((key) => publishedKids.has(key.kid)) });
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
  config[oidc.customFetch] = handleFetch;

  const client = new VirkiOidcNodeClient(settings, createOidcProtocol(config));
  return {
    client,
    settings,
    metadata,
    handleFetch,
    setActiveNonce(value: string) { activeNonce = value; },
    setMode(next: TestTokenMode) { mode = next; },
    rotateKey() { signingKey = rotated; kid = "fixture-k2"; },
    useInitialKey() { signingKey = first; kid = "fixture-k1"; },
    publishKey(value: string) { publishedKids.add(value); },
    removeKey(value: string) { publishedKids.delete(value); },
    get jwksRequests() { return jwksRequests; },
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

test("public discovery factory rejects forged signed tokens, not just manually configured protocol adapters", async () => {
  const f = fixture();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    if (new URL(request.url).pathname === "/.well-known/openid-configuration") {
      return new Response(JSON.stringify(f.metadata), { status: 200, headers: { "content-type": "application/json" } });
    }
    return f.handleFetch(request.url, {
      method: request.method,
      headers: Object.fromEntries(request.headers.entries()),
      redirect: "manual",
      body: request.method !== "GET" ? await request.text() : undefined
    });
  };
  try {
    // This is the exact exported production constructor. The mock substitutes
    // only transport and never manually enables JOSE verification on its config.
    const client = await createVirkiOidcClient({ ...f.settings, store: new MemoryTransactionStore() });
    const roundTrip = () => {
      const binding = randomBytes(32).toString("base64url");
      return client.beginLogin(binding).then(async (start) => {
        f.setActiveNonce(start.url.searchParams.get("nonce")!);
        const callback = new URL(redirectUri);
        callback.searchParams.set("state", start.url.searchParams.get("state")!);
        callback.searchParams.set("code", "discovery-fixture-code");
        return client.completeCallback(callback, binding);
      });
    };
    f.setMode("tampered");
    await assert.rejects(roundTrip(), (error: unknown) => error instanceof Error && error.message === "OIDC callback rejected.");
    f.setMode("valid");
    assert.equal((await roundTrip()).identity.sub, "user-1");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("optional Access backchannel authenticates actual discovery, token, JWKS, userinfo and revocation with pinned transport", async () => {
  const f = fixture();
  const accessClientId = "synthetic-access-service-id";
  const accessClientSecret = "synthetic-access-service-secret";
  const visited: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const endpoint = new URL(request.url);
    assert.equal(endpoint.origin, issuer, "Access identity must never reach another origin");
    assert.equal(request.redirect, "manual", "credentialed requests must never auto-follow redirects");
    assert.equal(request.headers.get("cf-access-client-id"), accessClientId);
    assert.equal(request.headers.get("cf-access-client-secret"), accessClientSecret);
    visited.push(endpoint.pathname);
    if (endpoint.pathname === "/.well-known/openid-configuration") {
      return new Response(JSON.stringify(f.metadata), { status: 200, headers: { "content-type": "application/json" } });
    }
    return f.handleFetch(request.url, { method: request.method,
      headers: Object.fromEntries(request.headers.entries()), redirect: "manual",
      body: request.method === "GET" ? undefined : await request.text() });
  };
  try {
    const client = await createVirkiOidcClient({ ...f.settings, store: new MemoryTransactionStore(),
      cloudflareAccess: { clientId: accessClientId, clientSecret: accessClientSecret } });
    const browserBinding = randomBytes(32).toString("base64url");
    const start = await client.beginLogin(browserBinding);
    assert.doesNotMatch(start.url.href, /synthetic-access-service/u);
    f.setActiveNonce(start.url.searchParams.get("nonce")!);
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", "synthetic-access-code");
    callback.searchParams.set("state", start.url.searchParams.get("state")!);
    const verified = await client.completeCallback(callback, browserBinding);
    assert.equal(verified.identity.sub, "user-1", "Real ES256 verification and PKCE still apply with Access");
    assert.equal((await client.userInfo(verified.serverOnly.accessToken, "user-1") as { sub: string }).sub, "user-1");
    await client.revokeAccessToken(verified.serverOnly.accessToken);
    for (const path of ["/.well-known/openid-configuration", "/token", "/jwks", "/me", "/token/revocation"]) {
      assert.ok(visited.includes(path), `${path} must carry the server-only Access identity`);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Access backchannel fails closed on 302 foreign redirects and cannot send credentials to foreign metadata endpoints", async () => {
  const f = fixture();
  const accessClientSecret = "synthetic-access-service-secret";
  const originalFetch = globalThis.fetch;
  const visited: string[] = [];
  const cloudflareAccess = { clientId: "synthetic-access-service-id", clientSecret: accessClientSecret };
  try {
    globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      visited.push(request.url);
      assert.equal(request.redirect, "manual");
      assert.equal(request.headers.get("cf-access-client-secret"), accessClientSecret);
      return new Response(null, { status: 302,
        headers: { location: "https://cross-origin.example.invalid/collect?request=synthetic" } });
    };
    await assert.rejects(createVirkiOidcClient({ ...f.settings, store: new MemoryTransactionStore(), cloudflareAccess }),
      (error: unknown) => error instanceof Error && !error.message.includes(accessClientSecret));
    assert.deepEqual(visited, [`${issuer}/.well-known/openid-configuration`], "No redirect target is ever requested");

    visited.length = 0;
    globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      visited.push(request.url);
      assert.equal(request.headers.get("cf-access-client-secret"), accessClientSecret);
      const metadata = { ...f.metadata, jwks_uri: "https://cross-origin.example.invalid/jwks" };
      return new Response(JSON.stringify(metadata), { status: 200, headers: { "content-type": "application/json" } });
    };
    await assert.rejects(createVirkiOidcClient({ ...f.settings, store: new MemoryTransactionStore(), cloudflareAccess }),
      /Untrusted OIDC issuer metadata/u);
    assert.deepEqual(visited, [`${issuer}/.well-known/openid-configuration`]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Access backchannel refuses token-endpoint redirects and consumes the authorization state", async () => {
  const f = fixture();
  const originalFetch = globalThis.fetch;
  const visited: string[] = [];
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    assert.equal(request.redirect, "manual");
    assert.equal(request.headers.get("cf-access-client-id"), "synthetic-access-id");
    const endpoint = new URL(request.url);
    assert.equal(endpoint.origin, issuer);
    visited.push(endpoint.pathname);
    if (endpoint.pathname === "/.well-known/openid-configuration") {
      return new Response(JSON.stringify(f.metadata), { status: 200, headers: { "content-type": "application/json" } });
    }
    assert.equal(endpoint.pathname, "/token");
    return new Response(null, { status: 302, headers: { location: "https://foreign.invalid/collect" } });
  };
  try {
    const client = await createVirkiOidcClient({ ...f.settings, store: new MemoryTransactionStore(),
      cloudflareAccess: { clientId: "synthetic-access-id", clientSecret: "synthetic-access-secret" } });
    const binding = randomBytes(32).toString("base64url");
    const started = await client.beginLogin(binding);
    const callback = new URL(redirectUri);
    callback.searchParams.set("state", started.url.searchParams.get("state")!);
    callback.searchParams.set("code", "synthetic-redirect-code");
    await assert.rejects(client.completeCallback(callback, binding), /OIDC callback rejected\./u);
    await assert.rejects(client.completeCallback(callback, binding), /OIDC callback rejected\./u);
    assert.deepEqual(visited, ["/.well-known/openid-configuration", "/token"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public factory caches pinned JWKS, rejects fresh unknown kid, and refreshes after rotation cooldown", async () => {
  const f = fixture();
  f.removeKey("fixture-k2"); // K2 is NOT prepublished at client startup.
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  let clockAdvance = 0;
  Date.now = () => originalNow() + clockAdvance;
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    assert.equal(new URL(request.url).origin, issuer, "Discovery, token exchange and JWKS must remain on the pinned issuer");
    if (new URL(request.url).pathname === "/.well-known/openid-configuration") {
      return new Response(JSON.stringify(f.metadata), { status: 200, headers: { "content-type": "application/json" } });
    }
    return f.handleFetch(request.url, {
      method: request.method,
      headers: Object.fromEntries(request.headers.entries()),
      redirect: "manual",
      body: request.method !== "GET" ? await request.text() : undefined
    });
  };
  try {
    const client = await createVirkiOidcClient({ ...f.settings, store: new MemoryTransactionStore() });
    const callback = async () => {
      const binding = randomBytes(32).toString("base64url");
      const start = await client.beginLogin(binding);
      f.setActiveNonce(start.url.searchParams.get("nonce")!);
      const returnUrl = new URL(redirectUri);
      returnUrl.searchParams.set("code", "rotation-fixture-code");
      returnUrl.searchParams.set("state", start.url.searchParams.get("state")!);
      return client.completeCallback(returnUrl, binding);
    };
    assert.equal((await callback()).identity.sub, "user-1");
    assert.equal(f.jwksRequests, 1, "The initial JWKS contains only K1");
    f.publishKey("fixture-k2");
    f.rotateKey();
    await assert.rejects(callback(), /OIDC callback rejected\./u, "A freshly cached K1-only JWKS cannot authorize a newly introduced K2");
    assert.equal(f.jwksRequests, 1, "No unsafe JWKS cooldown bypass or alternate endpoint fallback");
    clockAdvance = 61_000;
    assert.equal((await callback()).identity.sub, "user-1", "New K2 accepted only after trusted issuer JWKS refresh");
    assert.equal(f.jwksRequests, 2, "Unknown kid causes bounded JWKS refetch after cooldown");
    f.removeKey("fixture-k1");
    f.useInitialKey();
    // Removing a key at the issuer is NOT an instant distributed token revocation:
    // an already cached JWKS may still contain K1 within its bounded lifetime.
    assert.equal((await callback()).identity.sub, "user-1", "K1 remains cached within the documented JWKS freshness window");
    clockAdvance = 362_000; // >300 seconds since the issuer JWKS cache was refreshed.
    await assert.rejects(callback(), /OIDC callback rejected\./u, "Removed K1 is denied after issuer JWKS cache expiry and refresh");
    assert.equal(f.jwksRequests, 3, "Retired K1 never causes JWKS refresh from an unpinned authority");
  } finally {
    globalThis.fetch = originalFetch;
    Date.now = originalNow;
  }
});

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
