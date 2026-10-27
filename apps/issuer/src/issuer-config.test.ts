import assert from "node:assert/strict";
import test from "node:test";
import { readIssuer, readSigningJwks } from "./issuer-config";
import { exportJWK, generateKeyPair } from "jose";

const env = (value: Record<string, string>) => value as unknown as NodeJS.ProcessEnv;

test("production fails closed without an issuer", () => {
  assert.throws(() => readIssuer(env({ NODE_ENV: "production" })), /required in production/u);
  assert.throws(() => readIssuer(env({ NODE_ENV: "production", VIRKI_OIDC_ISSUER: "  " })), /required in production/u);
});

test("non-production keeps the fallback", () => {
  assert.equal(readIssuer(env({ NODE_ENV: "development" })), "https://portal.biel.dev.br");
});

test("issuer validation is preserved", () => {
  assert.equal(readIssuer(env({ NODE_ENV: "production", VIRKI_OIDC_ISSUER: "https://portal.example.test" })), "https://portal.example.test");
  assert.throws(() => readIssuer(env({ NODE_ENV: "production", VIRKI_OIDC_ISSUER: "http://portal.example.test" })), /HTTPS/u);
  assert.throws(() => readIssuer(env({ VIRKI_OIDC_ISSUER: "https://portal.example.test/path" })), /invalid/u);
});

test("signing JWKS accepts distinct valid ES256 private keys for rotation", async () => {
  const first = await exportJWK((await generateKeyPair("ES256", { extractable: true })).privateKey);
  const second = await exportJWK((await generateKeyPair("ES256", { extractable: true })).privateKey);
  const keys = [{ ...first, kid: "old", alg: "ES256", use: "sig" }, { ...second, kid: "new", alg: "ES256", use: "sig" }];
  assert.deepEqual(readSigningJwks(JSON.stringify({ keys })), { keys });
});

test("signing JWKS fails closed when two different key IDs alias the same private key", async () => {
  const key = await exportJWK((await generateKeyPair("ES256", { extractable: true })).privateKey);
  const active = { ...key, kid: "active", alg: "ES256", use: "sig" };
  const alias = { ...active, kid: "replacement" };
  assert.throws(
    () => readSigningJwks(JSON.stringify({ keys: [active, alias] })),
    /OIDC.*key/u,
    "rotation must not pretend two kid values identify independent signing material"
  );
});

test("signing JWKS rejects duplicate IDs and malformed private EC coordinates", async () => {
  const jwk = await exportJWK((await generateKeyPair("ES256", { extractable: true })).privateKey);
  const valid = { ...jwk, kid: "current", alg: "ES256", use: "sig" };
  for (const keys of [
    [valid, valid],
    [{ ...valid, x: undefined }],
    [{ ...valid, y: undefined }],
    [{ ...valid, d: undefined }],
    [{ ...valid, x: "not-base64url!" }],
    [{ ...valid, x: Buffer.from(new Uint8Array(32)).toString("base64url") }],
    [{ ...valid, y: "AA" }],
    [{ ...valid, d: "AA" }],
    [{ ...valid, kid: " " }],
    [{ ...valid, kid: 42 }],
    [{ ...valid, crv: "P-384" }],
    [{ ...valid, alg: "none" }]
  ]) assert.throws(() => readSigningJwks(JSON.stringify({ keys })), /OIDC.*key/u);
});
