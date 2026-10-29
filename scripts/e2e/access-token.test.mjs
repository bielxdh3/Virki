import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { registerSigningKey } from "./access-token.mts";

const TEST_ISSUER = "http://127.0.0.1:3010";
const PUBLIC_FIELDS = ["kty", "kid", "alg", "use", "n", "e"];

function fixture(t, transformJwk = (jwk) => jwk) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-access-jwk-egress-"));
  const file = path.join(directory, "signing-key.json");
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
  const publicJwk = {
    ...publicKey.export({ format: "jwk" }),
    kid: "synthetic-e2e-rsa-kid",
    alg: "RS256",
    use: "sig",
  };
  const payload = {
    kid: publicJwk.kid,
    privateKey: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicJwk: transformJwk(publicJwk),
  };
  writeFileSync(file, JSON.stringify(payload), { flag: "wx", mode: 0o600 });
  const priorFile = process.env.VIRKI_E2E_ACCESS_SIGNING_KEY_FILE;
  const priorToken = process.env.VIRKI_E2E_JWKS_REGISTRATION_TOKEN;
  const priorFetch = globalThis.fetch;
  process.env.VIRKI_E2E_ACCESS_SIGNING_KEY_FILE = file;
  process.env.VIRKI_E2E_JWKS_REGISTRATION_TOKEN = "synthetic-registration-token";
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), method: options.method, body: options.body });
    return { ok: true };
  };
  t.after(() => {
    globalThis.fetch = priorFetch;
    if (priorFile === undefined) delete process.env.VIRKI_E2E_ACCESS_SIGNING_KEY_FILE;
    else process.env.VIRKI_E2E_ACCESS_SIGNING_KEY_FILE = priorFile;
    if (priorToken === undefined) delete process.env.VIRKI_E2E_JWKS_REGISTRATION_TOKEN;
    else process.env.VIRKI_E2E_JWKS_REGISTRATION_TOKEN = priorToken;
    rmSync(directory, { recursive: true, force: true });
  });
  return { calls, publicJwk };
}

test("synthetic signing registration projects only six public RSA fields before egress", async (t) => {
  const forbidden = {
    d: "SYNTHETIC_PRIVATE_D",
    p: "SYNTHETIC_PRIVATE_P",
    q: "SYNTHETIC_PRIVATE_Q",
    dp: "SYNTHETIC_PRIVATE_DP",
    dq: "SYNTHETIC_PRIVATE_DQ",
    qi: "SYNTHETIC_PRIVATE_QI",
    oth: [{ d: "SYNTHETIC_OTHER_PRIVATE_D", r: "SYNTHETIC_OTHER_R" }],
    unexpectedSecret: { nested: "SYNTHETIC_ARBITRARY_SECRET" },
    constructor: "SYNTHETIC_CONSTRUCTOR_OVERRIDE",
    toJSON: "SYNTHETIC_CUSTOM_JSON_FIELD",
  };
  const { calls, publicJwk } = fixture(t, (jwk) => ({ ...jwk, ...forbidden }));
  const registered = await registerSigningKey(TEST_ISSUER);
  assert.equal(registered.kid, publicJwk.kid);
  assert.equal(registered.privateKey.asymmetricKeyType, "rsa");
  assert.equal(calls.length, 1, "registration must not retry or contact an external server");
  assert.equal(calls[0].url, TEST_ISSUER + "/__test__/keys");
  assert.equal(calls[0].method, "POST");
  const request = JSON.parse(calls[0].body);
  assert.deepEqual(Object.keys(request), PUBLIC_FIELDS,
    "SECURITY_EGRESS: only public JWK fields may reach the outgoing request body");
  assert.deepEqual(request, Object.fromEntries(PUBLIC_FIELDS.map((field) => [field, publicJwk[field]])));
  for (const secret of Object.values(forbidden)) {
    assert.equal(calls[0].body.includes(typeof secret === "string" ? secret : JSON.stringify(secret)), false,
      "private JWK components and arbitrary fixture data must never be transmitted");
  }
});

test("valid synthetic RSA key registration keeps the existing public JWK contract", async (t) => {
  const { calls, publicJwk } = fixture(t);
  const registered = await registerSigningKey(TEST_ISSUER);
  assert.equal(registered.kid, publicJwk.kid);
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].body), Object.fromEntries(PUBLIC_FIELDS.map((field) => [field, publicJwk[field]])));
});

test("invalid JWK identity, algorithm and modulus fields fail before registration", async (t) => {
  for (const [name, mutation] of [
    ["kid", { kid: "unrelated-kid" }],
    ["alg", { alg: "HS256" }],
    ["kty", { kty: "EC" }],
    ["use", { use: "enc" }],
    ["n", { n: "" }],
    ["e", { e: "" }],
  ]) {
    await t.test(name, async (child) => {
      const { calls } = fixture(child, (jwk) => ({ ...jwk, ...mutation }));
      await assert.rejects(registerSigningKey(TEST_ISSUER),
        /Synthetic E2E Cloudflare Access signing key is invalid/u);
      assert.equal(calls.length, 0, "invalid JWK must not be transmitted");
    });
  }
});
