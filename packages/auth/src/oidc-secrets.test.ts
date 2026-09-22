import assert from "node:assert/strict";
import test from "node:test";
import { decryptOidcClientSecret, decryptOidcPayload, encryptOidcClientSecret, encryptOidcPayload, hashOidcIdentifier } from "./oidc-secrets";

const key = "12".repeat(32);

test("OIDC client secrets and artifact payloads are authenticated encrypted values", () => {
  const secret = "one-time-project-secret";
  const ciphertext = encryptOidcClientSecret(secret, { BIELOS_OIDC_ADAPTER_KEY: key });
  assert.equal(ciphertext.includes(secret), false);
  assert.equal(decryptOidcClientSecret(ciphertext, { BIELOS_OIDC_ADAPTER_KEY: key }), secret);
  const payload = JSON.stringify({ code: "one-time-auth-code", clientId: "client-a" });
  const encrypted = encryptOidcPayload(payload, { BIELOS_OIDC_ADAPTER_KEY: key });
  assert.equal(encrypted.includes("one-time-auth-code"), false);
  assert.equal(decryptOidcPayload(encrypted, { BIELOS_OIDC_ADAPTER_KEY: key }), payload);
  assert.throws(() => decryptOidcPayload(encrypted, { BIELOS_OIDC_ADAPTER_KEY: "34".repeat(32) }));
});

test("OIDC identifiers are irreversibly indexed with SHA-256", () => {
  assert.match(hashOidcIdentifier("client-secret"), /^[a-f0-9]{64}$/u);
  assert.notEqual(hashOidcIdentifier("client-secret"), "client-secret");
});
