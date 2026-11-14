import assert from "node:assert/strict";
import test from "node:test";
import { verifyPasskeyBrowserGate } from "./verify-passkey-browser-gate.mjs";

const passedLine = "  ✓  6 e2e/recovery-multimethod-browser.spec.mts:734:1 › USER PASSKEY_ADMIN: signed Portal passkey, independent Hub approval";
const good = `Running 6 tests using 1 worker\n${passedLine}\n  6 passed (2.8m)\n`;

test("accepts one physically passed USER Portal passkey test and a full green Playwright summary", () => {
  assert.equal(verifyPasskeyBrowserGate(good), 6);
  assert.equal(verifyPasskeyBrowserGate(`\x1b[32m${passedLine}\x1b[0m\n  6 passed (2.8m)\n`), 6);
});

test("rejects real Playwright skipped/failed lines that do not have timing parentheses", () => {
  for (const status of ["skipped", "failed", "flaky", "interrupted", "did not run"]) {
    assert.throws(() => verifyPasskeyBrowserGate(`${good}  1 ${status}\n`), /non-PASS result/u, status);
  }
});

test("rejects absent or listed-only named test, zero tests and ambiguous summaries", () => {
  for (const output of [
    "", "  6 passed (2.8m)\n", `  -  6 e2e/spec.mts:1:1 › ${passedLine.split("› ")[1]} (skipped)\n  5 passed (2.8m)\n  1 skipped\n`,
    passedLine, `${passedLine}\n  0 passed (0.0s)\n`, `${good}  6 passed (2.8m)\n`,
    `Running 6 tests using 1 worker\n${passedLine.replace("PASSKEY_ADMIN", "PASSKEY_EMAIL")}\n  6 passed (2.8m)\n`
  ]) {
    assert.throws(() => verifyPasskeyBrowserGate(output), /missing|did not physically PASS|summary/u);
  }
});
