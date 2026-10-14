import assert from "node:assert/strict";
import test from "node:test";
import { createSessionCsrfTokenFor, validateSessionCsrfTokenFor } from "./session-csrf";

test("session CSRF tokens are bound to the session cookie", () => {
  const minted = createSessionCsrfTokenFor("cookie-a", "admin-accounts");

  assert.equal(validateSessionCsrfTokenFor("cookie-a", minted, "admin-accounts"), true);
  assert.equal(validateSessionCsrfTokenFor("cookie-b", minted, "admin-accounts"), false);
  assert.equal(validateSessionCsrfTokenFor("cookie-a", minted, "logout"), false);
  assert.equal(validateSessionCsrfTokenFor(undefined, minted, "admin-accounts"), false);
  assert.equal(validateSessionCsrfTokenFor("cookie-a", "", "admin-accounts"), false);
});

test("minting a session CSRF token without a session throws", () => {
  assert.throws(() => createSessionCsrfTokenFor(undefined, "logout"));
  assert.throws(() => createSessionCsrfTokenFor("", "logout"));
});
