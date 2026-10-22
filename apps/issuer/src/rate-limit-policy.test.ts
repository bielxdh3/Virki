import assert from "node:assert/strict";
import test from "node:test";
import { getPublicOidcRateLimitEndpoint, isInteractionPath, isNonCanonicalOidcEndpointPath, isTokenEndpoint, parseBasicClientId, selectAuthRateLimits, selectInteractionRateLimits, selectPublicOidcRateLimits, selectRateLimitAudit, selectTokenRateLimits } from "./rate-limit-policy";

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

test("token limiter matches the provider router's case and trailing-slash aliases", () => {
  assert.equal(isTokenEndpoint("POST", "/TOKEN"), true);
  assert.equal(isTokenEndpoint("POST", "/token/"), true);
  assert.equal(isTokenEndpoint("POST", "/TOKEN/REVOCATION/"), true);
  assert.equal(isTokenEndpoint("POST", "/token//"), false);
  assert.equal(isTokenEndpoint("GET", "/TOKEN/"), false);
});

test("public OIDC endpoints with database-backed work have source and browser quotas", () => {
  assert.equal(getPublicOidcRateLimitEndpoint("GET", "/me"), "userinfo");
  assert.equal(getPublicOidcRateLimitEndpoint("POST", "/me"), "userinfo");
  assert.equal(getPublicOidcRateLimitEndpoint("HEAD", "/me"), "userinfo");
  assert.equal(getPublicOidcRateLimitEndpoint("POST", "/session/end/confirm"), "session-end");
  assert.equal(getPublicOidcRateLimitEndpoint("GET", "/session/end/success"), "session-end");
  assert.equal(getPublicOidcRateLimitEndpoint("HEAD", "/session/end/success"), "session-end");
  assert.equal(getPublicOidcRateLimitEndpoint("HEAD", "/session/end/confirm"), null);
  assert.equal(getPublicOidcRateLimitEndpoint("GET", "/session/end"), "session-end");
  assert.equal(getPublicOidcRateLimitEndpoint("GET", "/auth/abcdefgh"), "auth-action");
  assert.equal(getPublicOidcRateLimitEndpoint("GET", "/auth/short"), null);
  assert.equal(getPublicOidcRateLimitEndpoint("PUT", "/me"), null);
  assert.equal(getPublicOidcRateLimitEndpoint("GET", "/unknown"), null);

  const checks = selectPublicOidcRateLimits("203.0.113.11", "browser-secret", "userinfo");
  assert.equal(checks[0].identifier, "oidc-public-source:userinfo:203.0.113.11");
  assert.equal(checks[0].maxAttempts, 300);
  assert.match(checks[1].identifier, /^oidc-public-userinfo-browser:[a-f0-9]{64}$/u);
  assert.equal(checks[1].maxAttempts, 30);
  assert.equal(checks[1].identifier.includes("browser-secret"), false);
  const tokenA = selectPublicOidcRateLimits("203.0.113.11", null, "userinfo", "Bearer token-for-client-a");
  const tokenB = selectPublicOidcRateLimits("203.0.113.11", null, "userinfo", "Bearer token-for-client-b");
  assert.equal(tokenA[0].identifier, tokenB[0].identifier, "shared IP ceiling must survive token rotation");
  assert.notEqual(tokenA[1].identifier, tokenB[1].identifier, "independent RP tokens must not collide in an anonymous bucket");
  assert.match(tokenA[1].identifier, /^oidc-public-userinfo-bearer:[a-f0-9]{64}$/u);
  assert.equal(tokenA[1].identifier.includes("token-for-client-a"), false);
  assert.equal(tokenA[1].maxAttempts, 30);
  assert.equal(selectPublicOidcRateLimits("203.0.113.11", null, "userinfo", "Bearer bad")[1].identifier,
    "oidc-public-userinfo-anonymous:203.0.113.11");
  assert.notEqual(tokenA[1].identifier,
    selectPublicOidcRateLimits("203.0.113.11", null, "userinfo")[1].identifier);
  assert.notEqual(
    selectPublicOidcRateLimits("203.0.113.11", null, "session-end")[1].identifier,
    selectPublicOidcRateLimits("203.0.113.11", null, "auth-action")[1].identifier
  );
});

test("noncanonical OIDC endpoint aliases are detectable before provider routing", () => {
  for (const alias of ["/AUTH", "/auth/", "/AUTH/", "/TOKEN", "/token/", "/ME/", "/SESSION/END/", "/SESSION/END/CONFIRM", "/session/end/confirm/", "/SESSION/END/SUCCESS", "/session/end/success/", "/Interaction/abcdefgh", "/interaction/abcdefgh/", "/.WELL-KNOWN/openid-configuration", "/.well-known/openid-configuration/"]) {
    assert.equal(isNonCanonicalOidcEndpointPath(alias), true, alias);
  }
  for (const canonical of ["/auth", "/token", "/token/revocation", "/me", "/session/end", "/auth/abcdefgh", "/unknown"]) {
    assert.equal(isNonCanonicalOidcEndpointPath(canonical), false, canonical);
  }
  assert.equal(isNonCanonicalOidcEndpointPath("/AUTH/abcdefgh"), true);
  assert.equal(isNonCanonicalOidcEndpointPath(`/auth/${"a".repeat(81)}`), true,
    "provider UID lengths admitted by the proxy must not bypass issuer route constraints");
  assert.equal(isNonCanonicalOidcEndpointPath(`/AUTH/${"a".repeat(160)}`), true);
});

test("interaction routes are matched and have bounded source and browser rate buckets", () => {
  assert.equal(isInteractionPath("/interaction/abcdefgh"), true);
  assert.equal(isInteractionPath("/interaction/short"), false);
  assert.equal(isInteractionPath("/interaction/abcdefgh/extra"), false);

  const checks = selectInteractionRateLimits("203.0.113.9", "browser-cookie");
  assert.equal(checks[0].identifier, "oidc-interaction-source:203.0.113.9");
  assert.equal(checks[0].maxAttempts, 300);
  assert.match(checks[1].identifier, /^oidc-interaction-browser:[a-f0-9]{64}$/u);
  assert.equal(checks[1].maxAttempts, 30);
  assert.equal(checks[1].identifier.includes("browser-cookie"), false);
});

test("rate-limit denial audit uses one fixed per-source window bucket", () => {
  assert.deepEqual(selectRateLimitAudit("203.0.113.9"), {
    identifier: "oidc-rate-limit-audit:203.0.113.9",
    maxAttempts: 1
  });
});
