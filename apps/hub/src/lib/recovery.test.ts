import assert from "node:assert/strict";
import test from "node:test";
import { NextResponse } from "next/server";
import { getRecoveryCookieName, getRecoveryCookieOptions, LEGACY_RECOVERY_COOKIE, requiresRecoveryRequestSwitch } from "./recovery";
import { clearRecoveryCookie, setRecoveryCookie } from "../app/recover/recovery-cookie";

test("production recovery cookie satisfies the __Host- prefix rules", () => {
  const env = { NODE_ENV: "production" };
  const options = getRecoveryCookieOptions(new Date(0), env);
  assert.equal(getRecoveryCookieName(env), "__Host-virki_recovery");
  assert.equal(options.secure, true);
  assert.equal(options.path, "/");
  assert.equal("domain" in options, false);
  assert.equal(options.httpOnly, true);
});

test("development uses a distinct plain cookie name for safe legacy expiry over http", () => {
  const env = { NODE_ENV: "development" };
  assert.equal(getRecoveryCookieName(env), "virki_recovery_v2");
  assert.equal(getRecoveryCookieOptions(new Date(0), env).secure, false);
  assert.deepEqual(LEGACY_RECOVERY_COOKIE, { name: "virki_recovery", path: "/recover" });
});

test("reopening the same recovery request does not prompt to switch links", () => {
  assert.equal(requiresRecoveryRequestSwitch(null, "request-123"), false);
  assert.equal(requiresRecoveryRequestSwitch("request-123", "request-123"), false);
  assert.equal(requiresRecoveryRequestSwitch("request-456", "request-123"), true);
});

test("Next.js serializes __Host- recovery cookie expiration with Secure and root path", () => {
  const response = new NextResponse();
  clearRecoveryCookie(response.cookies, { NODE_ENV: "production" });
  const headers = response.headers.getSetCookie();
  const active = headers.find((header) => header.startsWith("__Host-virki_recovery="));
  assert.ok(active);
  assert.match(active, /(?:^|; )Secure(?:;|$)/u);
  assert.match(active, /(?:^|; )Path=\/(?:;|$)/u);
  assert.match(active, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/u);
  assert.doesNotMatch(active, /Domain=/u);
});

test("Next.js expires legacy recovery cookies at /recover before creating the __Host- cookie", () => {
  const response = new NextResponse();
  setRecoveryCookie(response.cookies, "opaque-key", new Date("2030-01-01T00:00:00.000Z"), { NODE_ENV: "production" });
  const headers = response.headers.getSetCookie();
  assert.equal(headers.length, 2);
  const legacy = headers.find((header) => header.startsWith("virki_recovery="));
  assert.ok(legacy);
  assert.match(legacy, /(?:^|; )Path=\/recover(?:;|$)/u);
  assert.match(legacy, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/u);
  const active = headers.find((header) => header.startsWith("__Host-virki_recovery="));
  assert.ok(active);
  assert.match(active, /(?:^|; )Secure(?:;|$)/u);
  assert.match(active, /(?:^|; )Path=\/(?:;|$)/u);
});

test("Next.js preserves both a legacy /recover deletion and new root cookie in development", () => {
  const env = { NODE_ENV: "development" };
  const response = new NextResponse();
  setRecoveryCookie(response.cookies, "opaque-key", new Date("2030-01-01T00:00:00.000Z"), env);
  const headers = response.headers.getSetCookie();
  assert.equal(headers.length, 2, "different cookie names preserve both Set-Cookie headers");
  const legacy = headers.find((header) => header.startsWith("virki_recovery="));
  const current = headers.find((header) => header.startsWith("virki_recovery_v2="));
  assert.ok(legacy);
  assert.match(legacy, /(?:^|; )Path=\/recover(?:;|$)/u);
  assert.match(legacy, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/u);
  assert.ok(current);
  assert.match(current, /(?:^|; )Path=\/(?:;|$)/u);
  assert.doesNotMatch(current, /(?:^|; )Secure(?:;|$)/u);

  const completed = new NextResponse();
  clearRecoveryCookie(completed.cookies, env);
  const clearHeaders = completed.headers.getSetCookie();
  assert.equal(clearHeaders.length, 2);
  const activeClear = clearHeaders.find((header) => header.startsWith("virki_recovery_v2="));
  assert.ok(activeClear);
  assert.match(activeClear, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/u);
});
