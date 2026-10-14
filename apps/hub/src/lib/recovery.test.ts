import assert from "node:assert/strict";
import test from "node:test";
import { getRecoveryCookieName, getRecoveryCookieOptions, LEGACY_RECOVERY_COOKIE } from "./recovery";

test("production recovery cookie satisfies the __Host- prefix rules", () => {
  const env = { NODE_ENV: "production" };
  const options = getRecoveryCookieOptions(new Date(0), env);
  assert.equal(getRecoveryCookieName(env), "__Host-virki_recovery");
  assert.equal(options.secure, true);
  assert.equal(options.path, "/");
  assert.equal("domain" in options, false);
  assert.equal(options.httpOnly, true);
});

test("development keeps a plain cookie name usable over http and expires the legacy path-scoped cookie", () => {
  const env = { NODE_ENV: "development" };
  assert.equal(getRecoveryCookieName(env), "virki_recovery");
  assert.equal(getRecoveryCookieOptions(new Date(0), env).secure, false);
  assert.deepEqual(LEGACY_RECOVERY_COOKIE, { name: "virki_recovery", path: "/recover" });
});
