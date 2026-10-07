import assert from "node:assert/strict";
import test from "node:test";
import { decryptOidcClientSecret, decryptOidcPayload, encryptOidcClientSecret, encryptOidcPayload, hashOidcIdentifier } from "./oidc-secrets";

const key = "12".repeat(32);

test("OIDC client secrets and artifact payloads are authenticated encrypted values", () => {
  const secret = "one-time-project-secret";
  const ciphertext = encryptOidcClientSecret(secret, { VIRKI_OIDC_ADAPTER_KEY: key });
  assert.equal(ciphertext.includes(secret), false);
  assert.equal(decryptOidcClientSecret(ciphertext, { VIRKI_OIDC_ADAPTER_KEY: key }), secret);
  const payload = JSON.stringify({ code: "one-time-auth-code", clientId: "client-a" });
  const encrypted = encryptOidcPayload(payload, { VIRKI_OIDC_ADAPTER_KEY: key });
  assert.equal(encrypted.includes("one-time-auth-code"), false);
  assert.equal(decryptOidcPayload(encrypted, { VIRKI_OIDC_ADAPTER_KEY: key }), payload);
  assert.throws(() => decryptOidcPayload(encrypted, { VIRKI_OIDC_ADAPTER_KEY: "34".repeat(32) }));
});

test("OIDC identifiers are irreversibly indexed with SHA-256", () => {
  assert.match(hashOidcIdentifier("client-secret"), /^[a-f0-9]{64}$/u);
  assert.notEqual(hashOidcIdentifier("client-secret"), "client-secret");
});


test("OIDC encrypted values remain readable during one-key rotation overlap", () => {
  const previousKey = "34".repeat(32);
  const currentKey = "56".repeat(32);
  const oldSecret = encryptOidcClientSecret("legacy-secret", { VIRKI_OIDC_ADAPTER_KEY: previousKey });
  const oldPayload = encryptOidcPayload("{\"legacy\":true}", { VIRKI_OIDC_ADAPTER_KEY: previousKey });
  const rotatingEnv = {
    VIRKI_OIDC_ADAPTER_KEY: currentKey,
    VIRKI_OIDC_ADAPTER_KEY_PREVIOUS: previousKey
  };

  assert.equal(decryptOidcClientSecret(oldSecret, rotatingEnv), "legacy-secret");
  assert.equal(decryptOidcPayload(oldPayload, rotatingEnv), "{\"legacy\":true}");

  const newSecret = encryptOidcClientSecret("current-secret", rotatingEnv);
  assert.equal(decryptOidcClientSecret(newSecret, { VIRKI_OIDC_ADAPTER_KEY: currentKey }), "current-secret");
  assert.throws(() => decryptOidcClientSecret(oldSecret, { VIRKI_OIDC_ADAPTER_KEY: currentKey }));
  assert.throws(() => decryptOidcPayload(oldPayload, {
    VIRKI_OIDC_ADAPTER_KEY: currentKey,
    VIRKI_OIDC_ADAPTER_KEY_PREVIOUS: "not-a-valid-key"
  }));
});
