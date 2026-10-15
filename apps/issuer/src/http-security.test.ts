import assert from "node:assert/strict";
import test from "node:test";
import { issuerContentSecurityPolicy, setIssuerSecurityHeaders } from "./http-security";

function headersFor(url: string | undefined, production = true) {
  const values = new Map<string, string>();
  const response = { req: { url }, setHeader: (name: string, value: string) => values.set(name.toLowerCase(), value) } as never;
  setIssuerSecurityHeaders(response, production);
  return values;
}

test("issuer CSP denies everything by default and allows no scripts, objects, framing or base rewriting", () => {
  const csp = headersFor("/interaction/abcdefghijklmnop").get("content-security-policy") ?? "";
  const directives = csp.split("; ");
  for (const directive of ["default-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"]) assert.ok(directives.includes(directive), directive);
  assert.ok(directives.includes("style-src 'unsafe-inline'"), "provider error/logout pages ship one inline style block");
  assert.doesNotMatch(csp, /script-src|unsafe-eval|\*|https?:/u);
});

test("logout confirmation may redirect to the relying party, other paths keep form-action self", () => {
  assert.doesNotMatch(issuerContentSecurityPolicy("/session/end"), /form-action/u);
  assert.doesNotMatch(issuerContentSecurityPolicy("/session/end/confirm"), /form-action/u);
  assert.match(issuerContentSecurityPolicy("/session/end-evil"), /form-action 'self'/u);
  assert.match(issuerContentSecurityPolicy("/token"), /form-action 'self'/u);
  assert.doesNotMatch(headersFor("/session/end/confirm?x=1").get("content-security-policy") ?? "", /form-action/u);
  assert.match(headersFor(undefined).get("content-security-policy") ?? "", /form-action 'self'/u);
});

test("issuer keeps the other hardening headers", () => {
  const production = headersFor("/jwks");
  assert.equal(production.get("x-frame-options"), "DENY");
  assert.equal(production.get("x-content-type-options"), "nosniff");
  assert.equal(production.get("referrer-policy"), "no-referrer");
  assert.equal(production.get("strict-transport-security"), "max-age=31536000");
  assert.equal(headersFor("/jwks", false).has("strict-transport-security"), false);
});

test("authorization responses allow the provider's hashed form_post script and the post to the registered redirect URI", () => {
  for (const path of ["/auth", "/auth/abcdefghijklmnop"]) {
    const csp = issuerContentSecurityPolicy(path);
    assert.match(csp, /script-src 'self'/u);
    assert.doesNotMatch(csp, /form-action|unsafe-inline'[^;]*script|unsafe-eval/u);
    assert.match(csp, /default-src 'none'/u);
  }
  assert.doesNotMatch(issuerContentSecurityPolicy("/authx"), /script-src/u);
});
