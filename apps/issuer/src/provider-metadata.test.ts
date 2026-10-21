import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import Provider from "oidc-provider";
import { OIDC_DISCOVERY_CONFIGURATION, OIDC_PROVIDER_CLAIMS, OIDC_SUPPORTED_ACR_VALUES } from "./authorization-policy";

test("OIDC discovery advertises supported ACR values and essential claims", async () => {
  const provider = new Provider("https://issuer.example.test", {
    ...OIDC_DISCOVERY_CONFIGURATION,
    features: {
      ...OIDC_DISCOVERY_CONFIGURATION.features,
      devInteractions: { enabled: false }
    },
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
    };

    assert.deepEqual(metadata.acr_values_supported, [...OIDC_SUPPORTED_ACR_VALUES]);
    assert.equal(metadata.claims_parameter_supported, true);
    assert.ok(Array.isArray(metadata.claims_supported));
    assert.ok(metadata.claims_supported.includes("acr"));
    assert.ok(metadata.claims_supported.includes("amr"));
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
