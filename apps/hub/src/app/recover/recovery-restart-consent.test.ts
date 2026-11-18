import assert from "node:assert/strict";
import { test } from "node:test";
import { hasRecoveryRestartConsent } from "./recovery-restart-consent";

test("accepts only one explicit canonical or React FormData-prefixed acknowledgement", () => {
  for (const field of ["confirmRecoveryRestart", "_0_confirmRecoveryRestart", "_12_confirmRecoveryRestart"]) {
    const data = new FormData();
    data.set(field, "yes");
    assert.equal(hasRecoveryRestartConsent(data), true, field);
  }
  for (const [field, value] of [
    ["confirmRecoveryRestart", "no"], ["_0_confirmRecoveryRestart", "on"],
    ["0_confirmRecoveryRestart", "yes"], ["_foo_confirmRecoveryRestart", "yes"],
    ["_0_confirmRecoveryRestart_extra", "yes"], ["_0_confirmRecoveryRestart", " yes"]
  ]) {
    const data = new FormData();
    data.set(field, value);
    assert.equal(hasRecoveryRestartConsent(data), false, field);
  }
  const duplicated = new FormData();
  duplicated.append("confirmRecoveryRestart", "yes");
  duplicated.append("_0_confirmRecoveryRestart", "yes");
  assert.equal(hasRecoveryRestartConsent(duplicated), false);
  const contradictory = new FormData();
  contradictory.append("_0_confirmRecoveryRestart", "yes");
  contradictory.append("_1_confirmRecoveryRestart", "no");
  assert.equal(hasRecoveryRestartConsent(contradictory), false);
  assert.equal(hasRecoveryRestartConsent(new FormData()), false);
});
