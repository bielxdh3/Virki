import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import Provider from "oidc-provider";
import { OIDC_DISCOVERY_CONFIGURATION, OIDC_PROVIDER_CLAIMS, OIDC_SUPPORTED_ACR_VALUES } from "./authorization-policy";
import { OIDC_PROVIDER_SECURITY_CONFIGURATION } from "./provider-security-config";

test("OIDC discovery advertises supported ACR values and essential claims", async () => {
  assert.equal(OIDC_PROVIDER_SECURITY_CONFIGURATION.features.requestObjects.enabled, false);
  assert.equal(OIDC_PROVIDER_SECURITY_CONFIGURATION.pkce.required(), true);
  const provider = new Provider("https://issuer.example.test", {
    ...OIDC_DISCOVERY_CONFIGURATION,
    features: {
      ...OIDC_PROVIDER_SECURITY_CONFIGURATION.features,
      ...OIDC_DISCOVERY_CONFIGURATION.features,
      devInteractions: { enabled: false }
    },
    pkce: OIDC_PROVIDER_SECURITY_CONFIGURATION.pkce,
    claims: OIDC_PROVIDER_CLAIMS,
    jwks: { keys: [] }
  });
  const server = provider.listen(0, "127.0.0.1");
  await once(server, "listening");

  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const response = await fetch(`http://127.0.0.1:${address.port}/.well-known/openid-configuration`);
    assert.equal(response.status, 200);
    const metadata = await response.json() as {
      acr_values_supported?: unknown;
      claims_parameter_supported?: unknown;
      claims_supported?: unknown;
      code_challenge_methods_supported?: unknown;
      request_parameter_supported?: unknown;
      request_uri_parameter_supported?: unknown;
      response_types_supported?: unknown;
    };

    assert.deepEqual(metadata.acr_values_supported, [...OIDC_SUPPORTED_ACR_VALUES]);
    assert.equal(metadata.claims_parameter_supported, true);
    assert.ok(Array.isArray(metadata.claims_supported));
    assert.ok(metadata.claims_supported.includes("acr"));
    assert.ok(metadata.claims_supported.includes("amr"));
    assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(metadata.response_types_supported, ["code"]);
    assert.equal(metadata.request_parameter_supported, undefined);
    assert.equal(metadata.request_uri_parameter_supported, false);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
