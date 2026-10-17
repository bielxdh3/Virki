import assert from "node:assert/strict";
import test from "node:test";
import { isAcceptableRecoveryPassword } from "./security";

test("recovery password rules respect role minimums and reject control characters", () => {
  assert.equal(isAcceptableRecoveryPassword("USER", "u".repeat(11)), false);
  assert.equal(isAcceptableRecoveryPassword("USER", "u".repeat(12)), true);
  assert.equal(isAcceptableRecoveryPassword("ADMIN", "a".repeat(15)), false);
  assert.equal(isAcceptableRecoveryPassword("ADMIN", "a".repeat(16)), true);
  assert.equal(isAcceptableRecoveryPassword("USER", `valid\n${"x".repeat(8)}`), false);
  assert.equal(isAcceptableRecoveryPassword("ADMIN", `valid\u0085${"x".repeat(12)}`), false);
  assert.equal(isAcceptableRecoveryPassword("ADMIN", "a".repeat(257)), false);
});
