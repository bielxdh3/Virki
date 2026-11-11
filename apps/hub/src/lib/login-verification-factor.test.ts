import assert from "node:assert/strict";
import test from "node:test";
import { displayedLoginFactor } from "./login-verification-factor";

test("invalid or expired challenges never display a client-supplied backup form", () => {
  assert.equal(displayedLoginFactor(null, "backup"), null);
  assert.equal(displayedLoginFactor(null, "totp"), null);
  assert.equal(displayedLoginFactor(null, "email"), null);
  assert.equal(displayedLoginFactor(null, "recovery"), null);
});

test("only a server-bound backup challenge can display the non-destructive backup form", () => {
  assert.equal(displayedLoginFactor("backup", "email"), "backup");
  assert.equal(displayedLoginFactor("backup", "totp"), "backup");
  assert.equal(displayedLoginFactor("backup", "recovery"), "backup");
  assert.equal(displayedLoginFactor("totp", "backup"), "totp");
  assert.equal(displayedLoginFactor("email", "backup"), "email");
});

test("existing TOTP recovery stays an explicit sub-flow, not an alternative to a bound backup code", () => {
  assert.equal(displayedLoginFactor("totp", "recovery"), "recovery");
  assert.equal(displayedLoginFactor("totp", "totp"), "totp");
  assert.equal(displayedLoginFactor("email", "recovery"), "email");
});
