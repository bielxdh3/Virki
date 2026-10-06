import assert from "node:assert/strict";
import { after, test } from "node:test";

import {
  getExpiredSessionCookieOptions,
  getSessionCookieOptions
} from "./index";
import { getDeviceCookieName, getSessionCookieName } from "./constants";

const originalNodeEnv = process.env.NODE_ENV;

after(() => {
  restoreNodeEnv(originalNodeEnv);
});

test("session cookies are HttpOnly, SameSite=Lax, and Secure in production", () => {
  setNodeEnv("production");
  const active = getSessionCookieOptions(new Date("2026-07-14T13:00:00.000Z"));
  const expired = getExpiredSessionCookieOptions();

  assert.equal(active.httpOnly, true);
  assert.equal(active.sameSite, "lax");
  assert.equal(active.secure, true);
  assert.equal(active.path, "/");
  assert.equal(expired.httpOnly, true);
  assert.equal(expired.sameSite, "lax");
  assert.equal(expired.secure, true);
  assert.equal(expired.maxAge, 0);
});

test("session cookies omit Secure only outside production", () => {
  setNodeEnv("test");

  assert.equal(
    getSessionCookieOptions(new Date("2026-07-14T13:00:00.000Z")).secure,
    false
  );
  assert.equal(getExpiredSessionCookieOptions().secure, false);
});

test("production authentication cookie names enforce host-only prefix requirements", () => {
  assert.equal(getSessionCookieName({ NODE_ENV: "production" }), "__Host-bielos_session");
  assert.equal(getDeviceCookieName({ NODE_ENV: "production" }), "__Host-bielos_device");
  assert.equal(getSessionCookieName({ NODE_ENV: "test" }), "bielos_session");
  assert.equal(getDeviceCookieName({ NODE_ENV: "test" }), "bielos_device");

  setNodeEnv("production");
  const options = getSessionCookieOptions(new Date("2026-07-14T13:00:00.000Z"));
  assert.equal(options.secure, true);
  assert.equal(options.path, "/");
  assert.equal("domain" in options, false);
});

function restoreNodeEnv(value: string | undefined): void {
  const name = "NODE_ENV";

  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}

function setNodeEnv(value: string): void {
  const name = "NODE_ENV";
  process.env[name] = value;
}
