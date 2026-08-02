import assert from "node:assert/strict";
import test from "node:test";
import {
  createTotpSecret,
  decryptTotpSecret,
  encryptTotpSecret,
  hashDeviceToken,
  verifyTotpCode
} from "./security";

test("TOTP secrets are encrypted and never returned from ciphertext", () => {
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret, { NODE_ENV: "test" });
  assert.notEqual(encrypted, secret);
  assert.equal(decryptTotpSecret(encrypted, { NODE_ENV: "test" }), secret);
  assert.match(hashDeviceToken("opaque-device-token"), /^[a-f0-9]{64}$/);
});

test("TOTP confirmation accepts the RFC vector and rejects same-window replay", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const now = new Date(0);
  assert.equal(verifyTotpCode(secret, "282760", now, null), 0);
  assert.equal(verifyTotpCode(secret, "282760", now, 0), null);
  assert.equal(verifyTotpCode(secret, "000000", now, null), null);
});
