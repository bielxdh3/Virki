import assert from "node:assert/strict";
import test from "node:test";
import { isTokenEndpoint, parseBasicClientId, selectAuthRateLimits, selectTokenRateLimits } from "./rate-limit-policy";

const basic = (value: string) => `Basic ${Buffer.from(value).toString("base64")}`;

test("distinct cookies on one IP get independent buckets under the same ceiling", () => {
  const a = selectAuthRateLimits("203.0.113.5", "cookie-a");
  const b = selectAuthRateLimits("203.0.113.5", "cookie-b");
  assert.notEqual(a[1].identifier, b[1].identifier);
  assert.equal(a[0].identifier, "oidc-auth-source:203.0.113.5");
  assert.equal(a[0].identifier, b[0].identifier);
  assert.deepEqual([a[0].maxAttempts, a[1].maxAttempts], [300, 30]);
  assert.ok(!a[1].identifier.includes("cookie-a"));
});

test("no cookie shares the anonymous per-IP bucket and the ceiling is always present", () => {
  const anonymous = selectAuthRateLimits("203.0.113.5", null);
  assert.equal(anonymous[1].identifier, "oidc-source:203.0.113.5");
  assert.equal(anonymous[0].identifier, "oidc-auth-source:203.0.113.5");
  assert.equal(selectAuthRateLimits("2001:db8::1", "x")[0].identifier, "oidc-auth-source:2001:db8::1");
});

test("client id is parsed from Basic and malformed input becomes invalid", () => {
  assert.equal(parseBasicClientId(basic("my-client:secret")), "my-client");
  assert.equal(parseBasicClientId(basic("my%40client:se:cret")), "my@client");
  for (const bad of [undefined, "", "Bearer abc", "Basic !!!", basic("nocolon"), basic(":secret"), basic(`${"a".repeat(300)}:s`), `Basic ${"A".repeat(3000)}`, basic("%E0%A4%A:x")]) {
    assert.equal(parseBasicClientId(bad), "invalid");
  }
});

test("token buckets are per address and per client under a per-address ceiling", () => {
  const client = (address: string, header: string) => selectTokenRateLimits(address, header)[1];
  const [ceiling, rp] = selectTokenRateLimits("198.51.100.1", basic("rp:s"));
  assert.notEqual(rp.identifier, client("198.51.100.2", basic("rp:s")).identifier);
  assert.notEqual(rp.identifier, client("198.51.100.1", basic("other:s")).identifier);
  assert.equal(rp.identifier, client("198.51.100.1", basic("rp:different")).identifier);
  assert.equal(rp.maxAttempts, 600);
  assert.ok(!rp.identifier.includes("rp:s"));
  // Rotating client_id values from one address still hits the same ceiling bucket.
  assert.equal(ceiling.identifier, selectTokenRateLimits("198.51.100.1", basic("rotated:s"))[0].identifier);
  assert.equal(ceiling.maxAttempts, 2000);
});

test("only POST /token and /token/revocation are limited", () => {
  assert.equal(isTokenEndpoint("POST", "/token"), true);
  assert.equal(isTokenEndpoint("POST", "/token/revocation"), true);
  assert.equal(isTokenEndpoint("GET", "/token"), false);
  assert.equal(isTokenEndpoint("POST", "/token/x"), false);
});
