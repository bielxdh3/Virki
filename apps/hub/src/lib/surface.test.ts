import assert from "node:assert/strict";
import test from "node:test";
import { getSurface, requestHost, safeReturnTo } from "./surface";

test("surfaces use the verified Host header and exact configured hostnames", () => {
  const headers = new Headers({ host: "portal.biel.dev.br", "x-forwarded-host": "hub.biel.dev.br" });
  assert.equal(requestHost(headers), "portal.biel.dev.br");
  assert.equal(getSurface(headers), "portal");
  assert.equal(getSurface(new Headers({ host: "hub.biel.dev.br" })), "hub");
  assert.equal(getSurface(new Headers({ host: "portal.biel.dev.br.attacker.invalid" })), "unknown");
});

test("return targets remain relative and reject protocol-relative or auth-loop destinations", () => {
  assert.equal(safeReturnTo("/interaction/abcdefgh?x=1"), "/interaction/abcdefgh?x=1");
  for (const value of ["https://attacker.invalid", "//attacker.invalid", "/\\attacker.invalid", "/api/logout", "/login", "/a\u0000b", "/" + "x".repeat(2048)]) assert.equal(safeReturnTo(value), null);
});
