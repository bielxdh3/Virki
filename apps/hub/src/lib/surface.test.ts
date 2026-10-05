import assert from "node:assert/strict";
import test from "node:test";
import { getSurface, getSurfaceBaseUrl, hasSameOrigin, requestHost, safeReturnTo, sameOriginFailureReason } from "./surface";

test("surfaces use the verified Host header and exact configured hostnames", () => {
  const headers = new Headers({ host: "portal.biel.dev.br", "x-forwarded-host": "hub.biel.dev.br" });
  assert.equal(requestHost(headers), "portal.biel.dev.br");
  assert.equal(getSurface(headers), "portal");
  assert.equal(getSurface(new Headers({ host: "hub.biel.dev.br" })), "hub");
  assert.equal(getSurface(new Headers({ host: "portal.biel.dev.br.attacker.invalid" })), "unknown");
});

test("return targets remain relative and reject protocol-relative or auth-loop destinations", () => {
  assert.equal(safeReturnTo("/interaction/abcdefgh?x=1"), "/interaction/abcdefgh?x=1");
  assert.equal(safeReturnTo("/interaction/abcdefgh?bielos_auth_request=opaque.marker", "portal", "USER"), "/interaction/abcdefgh?bielos_auth_request=opaque.marker");
  for (const value of ["https://attacker.invalid", "//attacker.invalid", "/\\attacker.invalid", "/api/logout", "/login", "/a\u0000b", "/" + "x".repeat(2048)]) assert.equal(safeReturnTo(value), null);
});

test("return targets are scoped to the selected surface and role", () => {
  assert.equal(safeReturnTo("/admin/accounts", "hub", "ADMIN"), "/admin/accounts");
  assert.equal(safeReturnTo("/admin/accounts", "portal", "USER"), null);
  assert.equal(safeReturnTo("/interaction/abcdefgh", "hub", "ADMIN"), null);
  assert.equal(safeReturnTo("/interaction/abcdefgh", "portal", "USER"), "/interaction/abcdefgh");
  assert.equal(safeReturnTo("/admin/accounts", "local", "USER"), null);
});

test("same-origin form checks compare the complete host and require a secure origin", () => {
  assert.equal(hasSameOrigin(new Headers({ host: "portal.biel.dev.br", origin: "https://portal.biel.dev.br" })), true);
  assert.equal(hasSameOrigin(new Headers({ host: "portal.biel.dev.br", origin: "https://attacker.invalid" })), false);
  assert.equal(hasSameOrigin(new Headers({ host: "portal.biel.dev.br:8443", origin: "https://portal.biel.dev.br" })), false);
  assert.equal(hasSameOrigin(new Headers({ host: "portal.biel.dev.br" })), false);
});

test("same-origin rejection diagnostics expose only stable reason codes", () => {
  assert.equal(sameOriginFailureReason(new Headers({ host: "portal.localhost:3001", origin: "https://portal.localhost:3001" })), null);
  assert.equal(sameOriginFailureReason(new Headers({ host: "127.0.0.1:3001", origin: "https://portal.localhost:3001" })), "hostname-mismatch");
  assert.equal(sameOriginFailureReason(new Headers({ host: "portal.localhost", origin: "https://portal.localhost:3001" })), "port-mismatch");
  assert.equal(sameOriginFailureReason(new Headers({ host: "portal.localhost:3001" })), "missing-origin");
  assert.equal(sameOriginFailureReason(new Headers({ origin: "https://portal.localhost:3001" })), "missing-host");
  assert.equal(sameOriginFailureReason(new Headers({ host: "portal.localhost:3001", origin: "not-an-origin" })), "malformed-origin");
  assert.equal(sameOriginFailureReason(new Headers({ host: "portal.localhost:3001", origin: "ftp://attacker.invalid" })), "disallowed-protocol");
});

test("production redirect origins use canonical surface hosts, never the internal request URL", () => {
  const headers = new Headers({ host: "portal.biel.dev.br", "x-forwarded-host": "attacker.invalid" });
  const base = getSurfaceBaseUrl(headers, "http://hub:3001/login", {
    NODE_ENV: "production",
    BIELOS_PORTAL_HOSTNAME: "portal.biel.dev.br"
  });
  assert.equal(base?.origin, "https://portal.biel.dev.br");
  assert.equal(getSurfaceBaseUrl(headers, "http://hub:3001/login", {
    NODE_ENV: "production",
    BIELOS_PORTAL_HOSTNAME: "portal.biel.dev.br",
    BIELOS_PORTAL_URL: "https://attacker.invalid"
  }), null);
  assert.equal(getSurfaceBaseUrl(headers, "http://hub:3001/login", {
    NODE_ENV: "production",
    BIELOS_PORTAL_HOSTNAME: "portal.biel.dev.br/path"
  }), null);
});
