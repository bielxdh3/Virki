import assert from "node:assert/strict";
import test from "node:test";
import { readIssuer } from "./issuer-config";

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
