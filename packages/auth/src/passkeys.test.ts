import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  passkeysEnabledForRequest,
  expectedPasskeyRP,
  hashPasskeyChallenge,
  readClientChallenge,
  validatePasskeyName
} from "./passkeys";

test("WebAuthn cannot expand the USER origin to the ADMIN subdomain", () => {
  const env = { NODE_ENV: "production", VIRKI_PASSKEYS_ENABLED: "true" };
  assert.deepEqual(expectedPasskeyRP(env), { rpID: "portal.biel.dev.br", origin: "https://portal.biel.dev.br" });
  assert.equal(passkeysEnabledForRequest("portal", "portal.biel.dev.br", env), true);
  for (const [surface, host] of [["hub", "hub.biel.dev.br"], ["local", "localhost"], ["portal", "evil.portal.biel.dev.br"]]) {
    assert.equal(passkeysEnabledForRequest(surface, host, env), false);
  }
  assert.equal(passkeysEnabledForRequest("portal", "portal.biel.dev.br", { ...env, VIRKI_PASSKEYS_ENABLED: "false" }), false);
});

test("clientData only supplies an exact, bounded challenge; stored digest matches original", () => {
  const challenge = "f".repeat(43);
  const data = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: "https://portal.biel.dev.br" })).toString("base64url");
  assert.equal(readClientChallenge(data, "webauthn.get"), challenge);
  assert.equal(readClientChallenge(data, "webauthn.create"), null);
  assert.equal(readClientChallenge("!", "webauthn.get"), null);
  assert.equal(readClientChallenge(Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: "x" })).toString("base64url"), "webauthn.get"), null);
  assert.equal(hashPasskeyChallenge(challenge), createHash("sha256").update(challenge).digest("hex"));
});

test("passkey labels are bounded and cannot carry control characters", () => {
  assert.equal(validatePasskeyName("  Meu celular  "), "Meu celular");
  assert.equal(validatePasskeyName("\nmalicioso"), null);
  assert.equal(validatePasskeyName("x".repeat(81)), null);
});
