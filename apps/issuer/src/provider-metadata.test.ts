import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { once } from "node:events";
import test from "node:test";
import Provider from "oidc-provider";
import { OIDC_DISCOVERY_CONFIGURATION, OIDC_PROVIDER_CLAIMS, OIDC_SUPPORTED_ACR_VALUES } from "./authorization-policy";
import { OIDC_PROVIDER_SECURITY_CONFIGURATION } from "./provider-security-config";
import { issuerCorsResponsePolicyMiddleware, issuerSensitiveResponseCachePolicyMiddleware } from "./http-security";

test("OIDC discovery advertises supported ACR values and essential claims", async () => {
  assert.equal(OIDC_PROVIDER_SECURITY_CONFIGURATION.features.requestObjects.enabled, false);
  assert.equal(OIDC_PROVIDER_SECURITY_CONFIGURATION.pkce.required(), true);
  const provider = new Provider("https://issuer.example.test", {
    ...OIDC_DISCOVERY_CONFIGURATION,
    ...OIDC_PROVIDER_SECURITY_CONFIGURATION,
    scopes: ["openid", "profile", "email"],
    clientDefaults: {
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      id_token_signed_response_alg: "ES256"
    },
    features: {
      ...OIDC_PROVIDER_SECURITY_CONFIGURATION.features,
      ...OIDC_DISCOVERY_CONFIGURATION.features,
      devInteractions: { enabled: false }
    },
    pkce: OIDC_PROVIDER_SECURITY_CONFIGURATION.pkce,
    claims: OIDC_PROVIDER_CLAIMS,
    jwks: { keys: [] }
  });
  provider.use(issuerCorsResponsePolicyMiddleware);
  provider.use(issuerSensitiveResponseCachePolicyMiddleware);
  const server = provider.listen(0, "127.0.0.1");
  await once(server, "listening");

  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("OIDC test server did not bind a TCP address");
    const origin = "https://attacker.example";
    const response = await fetch(`http://127.0.0.1:${address.port}/.well-known/openid-configuration`, { headers: { Origin: origin } });
    assert.equal(response.status, 200);
    const metadata = await response.json() as {
      acr_values_supported?: unknown;
      claims_parameter_supported?: unknown;
      claims_supported?: unknown;
      code_challenge_methods_supported?: unknown;
      request_parameter_supported?: unknown;
      request_uri_parameter_supported?: unknown;
      response_types_supported?: unknown;
      grant_types_supported?: unknown;
      jwks_uri?: string;
      userinfo_endpoint?: string;
    };

    assert.deepEqual(metadata.acr_values_supported, [...OIDC_SUPPORTED_ACR_VALUES]);
    assert.equal(metadata.claims_parameter_supported, true);
    assert.ok(Array.isArray(metadata.claims_supported));
    assert.ok(metadata.claims_supported.includes("acr"));
    assert.ok(metadata.claims_supported.includes("amr"));
    assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(metadata.response_types_supported, ["code"]);
    assert.deepEqual(metadata.grant_types_supported, ["authorization_code"]);
    assert.equal(response.headers.get("access-control-allow-origin"), "*");
    assert.equal(response.headers.get("access-control-allow-credentials"), null);
    assert.equal(metadata.request_parameter_supported, undefined);
    assert.equal(metadata.request_uri_parameter_supported, false);

    assert.ok(metadata.jwks_uri);
    const jwks = await fetch(`http://127.0.0.1:${address.port}${new URL(metadata.jwks_uri).pathname}`, { headers: { Origin: origin } });
    assert.equal(jwks.status, 200);
    assert.equal(jwks.headers.get("access-control-allow-origin"), "*");
    assert.equal(jwks.headers.get("access-control-allow-credentials"), null);
    const jwksPreflight = await fetch(`http://127.0.0.1:${address.port}${new URL(metadata.jwks_uri).pathname}`, {
      method: "OPTIONS", headers: { Origin: origin, "Access-Control-Request-Method": "GET" }
    });
    assert.equal(jwksPreflight.status, 204);
    assert.equal(jwksPreflight.headers.get("access-control-allow-origin"), "*");
    assert.equal(jwksPreflight.headers.get("access-control-allow-credentials"), null);

    assert.ok(metadata.userinfo_endpoint);
    const userinfo = await fetch(`http://127.0.0.1:${address.port}${new URL(metadata.userinfo_endpoint).pathname}`, {
      headers: { Origin: origin, Authorization: "Bearer invalid" }
    });
    assert.equal(userinfo.status, 401);
    assert.equal(userinfo.headers.get("access-control-allow-origin"), null);
    assert.equal(userinfo.headers.get("access-control-allow-credentials"), null);
    assert.equal(userinfo.headers.get("cache-control"), "no-store");
    const userinfoPreflight = await fetch(`http://127.0.0.1:${address.port}${new URL(metadata.userinfo_endpoint).pathname}`, {
      method: "OPTIONS",
      headers: { Origin: origin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization" }
    });
    assert.equal(userinfoPreflight.status, 204);
    assert.equal(userinfoPreflight.headers.get("access-control-allow-origin"), origin);
    assert.equal(userinfoPreflight.headers.get("access-control-allow-credentials"), null);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("registered OIDC client CORS enforces redirect-origin policy and never allows credentials", async () => {
  const clientId = "registered-cors-client";
  const clientSecret = randomBytes(24).toString("base64url");
  const redirectUri = "https://project.integration.invalid/callback";
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const provider = new Provider("https://issuer.example.test", {
    ...OIDC_DISCOVERY_CONFIGURATION,
    ...OIDC_PROVIDER_SECURITY_CONFIGURATION,
    clients: [{
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      id_token_signed_response_alg: "ES256"
    }],
    clientDefaults: {
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      id_token_signed_response_alg: "ES256"
    },
    scopes: ["openid", "profile", "email"],
    claims: OIDC_PROVIDER_CLAIMS,
    features: {
      ...OIDC_PROVIDER_SECURITY_CONFIGURATION.features,
      ...OIDC_DISCOVERY_CONFIGURATION.features,
      devInteractions: { enabled: false },
      clientCredentials: { enabled: false },
      registration: { enabled: false },
      registrationManagement: { enabled: false },
      deviceFlow: { enabled: false },
      introspection: { enabled: false },
      revocation: { enabled: true }
    },
    pkce: OIDC_PROVIDER_SECURITY_CONFIGURATION.pkce,
    ttl: { AuthorizationCode: 90, AccessToken: 300 },
    cookies: { keys: [randomBytes(32).toString("base64url")] },
    jwks: { keys: [{ ...jwk, kid: "cors-test", use: "sig", alg: "ES256" }] },
    findAccount: async (_context, id) => ({ accountId: id, claims: async () => ({ sub: id }) })
  });
  provider.proxy = true;
  provider.use(issuerCorsResponsePolicyMiddleware);
  provider.use(issuerSensitiveResponseCachePolicyMiddleware);
  provider.on("server_error", () => undefined);
  const server = provider.listen(0, "127.0.0.1");
  await once(server, "listening");

  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("OIDC test server did not bind a TCP address");
    const client = await provider.Client.find(clientId);
    assert.ok(client, "the static client is registered in oidc-provider");
    const accountId = "cors-integration-user";
    const grant = new provider.Grant({ accountId, clientId });
    grant.addOIDCScope("openid");
    const grantId = await grant.save();
    const code = await new provider.AuthorizationCode({
      accountId,
      client,
      grantId,
      gty: "authorization_code",
      redirectUri,
      scope: "openid",
      codeChallenge: challenge,
      codeChallengeMethod: "S256"
    }).save();
    const tokenResponse = await fetch(`http://127.0.0.1:${address.port}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`
      },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier })
    });
    assert.equal(tokenResponse.status, 200);
    assert.equal(tokenResponse.headers.get("cache-control"), "no-store");
    assert.equal(tokenResponse.headers.get("pragma"), "no-cache");
    const token = (await tokenResponse.json() as { access_token?: string }).access_token;
    assert.ok(token, "the registered client receives a real opaque access token");

    const allowedOrigin = "https://project.integration.invalid";
    const allowed = await fetch(`http://127.0.0.1:${address.port}/me`, {
      headers: { Origin: allowedOrigin, Authorization: `Bearer ${token}` }
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers.get("access-control-allow-origin"), allowedOrigin);
    assert.equal(allowed.headers.get("access-control-allow-credentials"), null);
    assert.match(allowed.headers.get("vary") ?? "", /(?:^|,\s*)Origin(?:,|$)/iu);
    assert.equal(allowed.headers.get("cache-control"), "no-store");

    const attackerOrigin = "https://attacker.example";
    const denied = await fetch(`http://127.0.0.1:${address.port}/me`, {
      headers: { Origin: attackerOrigin, Authorization: `Bearer ${token}` }
    });
    assert.equal(denied.status, 400);
    assert.equal(denied.headers.get("access-control-allow-origin"), null);
    assert.equal(denied.headers.get("access-control-allow-credentials"), null);

    const preflight = await fetch(`http://127.0.0.1:${address.port}/me`, {
      method: "OPTIONS",
      headers: {
        Origin: attackerOrigin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization"
      }
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), attackerOrigin);
    assert.equal(preflight.headers.get("access-control-allow-credentials"), null);

    const invalid = await fetch(`http://127.0.0.1:${address.port}/me`, {
      headers: { Origin: attackerOrigin, Authorization: "Bearer invalid" }
    });
    assert.equal(invalid.status, 401);
    assert.equal(invalid.headers.get("access-control-allow-origin"), null);
    assert.equal(invalid.headers.get("access-control-allow-credentials"), null);

    const opaqueOrigin = await fetch(`http://127.0.0.1:${address.port}/me`, {
      headers: { Origin: "null", Authorization: `Bearer ${token}` }
    });
    assert.equal(opaqueOrigin.status, 400);
    assert.equal(opaqueOrigin.headers.get("access-control-allow-origin"), null);
    assert.equal(opaqueOrigin.headers.get("access-control-allow-credentials"), null);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("token endpoint CORS is limited to registered public clients and their redirect origins", async () => {
  const confidentialClientId = "confidential-token-cors-client";
  const publicClientId = "public-token-cors-client";
  const clientSecret = randomBytes(24).toString("base64url");
  const redirectUri = "https://project.token-cors.invalid/callback";
  const allowedOrigin = new URL(redirectUri).origin;
  const attackerOrigin = "https://attacker.example";
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const provider = new Provider("https://issuer.example.test", {
    ...OIDC_DISCOVERY_CONFIGURATION,
    ...OIDC_PROVIDER_SECURITY_CONFIGURATION,
    clients: [
      {
        client_id: confidentialClientId,
        client_secret: clientSecret,
        redirect_uris: [redirectUri],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic",
        id_token_signed_response_alg: "ES256"
      },
      {
        client_id: publicClientId,
        redirect_uris: [redirectUri],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        id_token_signed_response_alg: "ES256"
      }
    ],
    clientDefaults: {
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      id_token_signed_response_alg: "ES256"
    },
    scopes: ["openid", "profile", "email"],
    claims: OIDC_PROVIDER_CLAIMS,
    features: {
      ...OIDC_PROVIDER_SECURITY_CONFIGURATION.features,
      ...OIDC_DISCOVERY_CONFIGURATION.features,
      devInteractions: { enabled: false },
      clientCredentials: { enabled: false },
      registration: { enabled: false },
      registrationManagement: { enabled: false },
      deviceFlow: { enabled: false },
      introspection: { enabled: false },
      revocation: { enabled: true }
    },
    pkce: OIDC_PROVIDER_SECURITY_CONFIGURATION.pkce,
    ttl: { AuthorizationCode: 90, AccessToken: 300 },
    cookies: { keys: [randomBytes(32).toString("base64url")] },
    jwks: { keys: [{ ...jwk, kid: "token-cors-test", use: "sig", alg: "ES256" }] },
    findAccount: async (_context, id) => ({ accountId: id, claims: async () => ({ sub: id }) })
  });
  provider.proxy = true;
  provider.use(issuerCorsResponsePolicyMiddleware);
  provider.use(issuerSensitiveResponseCachePolicyMiddleware);
  provider.on("server_error", () => undefined);
  const server = provider.listen(0, "127.0.0.1");
  await once(server, "listening");

  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("OIDC test server did not bind a TCP address");
    const port = address.port;

    async function issueCode(clientId: string) {
      const client = await provider.Client.find(clientId);
      assert.ok(client, `${clientId} is registered`);
      const accountId = `token-cors-${clientId}`;
      const grant = new provider.Grant({ accountId, clientId });
      grant.addOIDCScope("openid");
      const grantId = await grant.save();
      return new provider.AuthorizationCode({
        accountId, client, grantId, gty: "authorization_code", redirectUri,
        scope: "openid", codeChallenge: challenge, codeChallengeMethod: "S256"
      }).save();
    }

    async function exchange(clientId: string, code: string, origin: string, confidential: boolean) {
      const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier });
      const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", Origin: origin };
      if (confidential) headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
      else body.set("client_id", clientId);
      return fetch(`http://127.0.0.1:${port}/token`, { method: "POST", headers, body });
    }

    const publicAllowed = await exchange(publicClientId, await issueCode(publicClientId), allowedOrigin, false);
    assert.equal(publicAllowed.status, 200);
    assert.equal(publicAllowed.headers.get("access-control-allow-origin"), allowedOrigin);
    assert.equal(publicAllowed.headers.get("access-control-allow-credentials"), null);
    assert.match(publicAllowed.headers.get("vary") ?? "", /(?:^|,\s*)Origin(?:,|$)/iu);
    assert.equal(publicAllowed.headers.get("cache-control"), "no-store");

    const publicDenied = await exchange(publicClientId, await issueCode(publicClientId), attackerOrigin, false);
    assert.equal(publicDenied.status, 400);
    assert.equal(publicDenied.headers.get("access-control-allow-origin"), null);
    assert.equal(publicDenied.headers.get("access-control-allow-credentials"), null);
    assert.equal(publicDenied.headers.get("cache-control"), "no-store");
    assert.equal(publicDenied.headers.get("pragma"), "no-cache");

    const confidentialDenied = await exchange(confidentialClientId, await issueCode(confidentialClientId), allowedOrigin, true);
    assert.equal(confidentialDenied.status, 400);
    assert.equal(confidentialDenied.headers.get("access-control-allow-origin"), null);
    assert.equal(confidentialDenied.headers.get("access-control-allow-credentials"), null);
    assert.equal(confidentialDenied.headers.get("cache-control"), "no-store");
    assert.equal(confidentialDenied.headers.get("pragma"), "no-cache");
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
