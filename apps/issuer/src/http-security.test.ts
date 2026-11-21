import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import test from "node:test";
import { issuerContentSecurityPolicy, issuerCorsResponsePolicyMiddleware, setIssuerSecurityHeaders, setIssuerSensitiveResponseCachePolicy } from "./http-security";

const require = createRequire(import.meta.url);
const formPostModule = require("../../../node_modules/oidc-provider/lib/response_modes/form_post.js") as {
  default: (context: never, redirectUri: string, params: Record<string, string>) => void;
};
const formPost = formPostModule.default;

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

test("oidc-provider form_post hashes its exact inline script into the issuer authorization CSP", () => {
  const headers = new Map([["content-security-policy", issuerContentSecurityPolicy("/auth")]]);
  const context = {
    status: 200,
    response: { get: (name: string) => headers.get(name.toLowerCase()) ?? "" },
    set: (name: string, value: string) => headers.set(name.toLowerCase(), value)
  };
  formPost(context as never, "https://relying-party.example/callback", { code: "synthetic-code" });
  const html = (context as unknown as { body: string }).body;
  // oidc-provider emits literal lowercase tags; search the original string so
  // the UTF-16 offsets remain valid even if earlier HTML contains Unicode.
  const scriptStart = html.indexOf("<script>");
  const scriptContentStart = scriptStart + "<script>".length;
  const scriptEnd = html.indexOf("</script>", scriptContentStart);
  const script = scriptStart >= 0 && scriptEnd >= scriptContentStart
    ? html.slice(scriptContentStart, scriptEnd)
    : undefined;
  assert.ok(script, "form_post emits its auto-submit script");
  const digest = createHash("sha256").update(script).digest("base64");
  assert.ok(headers.get("content-security-policy")?.includes(`'sha256-${digest}'`), "CSP permits the exact emitted script only by hash");
  assert.match(html, /action="https:\/\/relying-party\.example\/callback"/u);
  assert.doesNotMatch(headers.get("content-security-policy") ?? "", /unsafe-inline'[^;]*script|unsafe-eval/u);
});

test("issuer authorization and interaction HTML responses are never cacheable", () => {
  const policyFor = (pathname: string) => {
    const headers = new Map<string, string>();
    setIssuerSensitiveResponseCachePolicy({ setHeader: (name: string, value: string | number | readonly string[]) => {
      headers.set(name.toLowerCase(), String(value));
    } } as never, pathname);
    return headers.get("cache-control");
  };
  assert.equal(policyFor("/auth"), "no-store");
  assert.equal(policyFor("/interaction/abcdefghijklmnop"), "no-store");
  assert.equal(policyFor("/token"), "no-store");
  assert.equal(policyFor("/token/revocation"), "no-store");
  assert.equal(policyFor("/me"), "no-store");
  assert.equal(policyFor("/interaction/short"), undefined);
});

test("token responses include the RFC 6749 no-store and no-cache directives", () => {
  const headers = new Map<string, string>();
  setIssuerSensitiveResponseCachePolicy({ setHeader: (name: string, value: string | number | readonly string[]) => {
    headers.set(name.toLowerCase(), String(value));
  } } as never, "/token");
  assert.equal(headers.get("cache-control"), "no-store");
  assert.equal(headers.get("pragma"), "no-cache");
});

test("OIDC CORS keeps only authenticated client origins, uses wildcard for public routes and never allows credentials", async () => {
  async function apply(route: string, method: string, client: unknown, initialOrigin: string, endResponse = false) {
    const values = new Map<string, string>([
      ["access-control-allow-origin", initialOrigin],
      ["access-control-allow-credentials", "true"]
    ]);
    const response = {
      headerSent: false,
      remove(name: string) {
        if (!this.headerSent) values.delete(name.toLowerCase());
      }
    };
    const context = {
      method,
      oidc: { route, client },
      response,
      res: {
        setHeader: (name: string, value: string) => values.set(name.toLowerCase(), value),
        removeHeader: (name: string) => values.delete(name.toLowerCase())
      }
    };
    await issuerCorsResponsePolicyMiddleware(context, async () => {
      if (endResponse) response.headerSent = true;
    });
    return values;
  }

  const authenticated = await apply("userinfo", "GET", { clientId: "registered" }, "https://client.example");
  assert.equal(authenticated.get("access-control-allow-origin"), "https://client.example");
  assert.equal(authenticated.has("access-control-allow-credentials"), false);

  const unauthenticated = await apply("userinfo", "GET", undefined, "https://attacker.example");
  assert.equal(unauthenticated.has("access-control-allow-origin"), false);
  assert.equal(unauthenticated.has("access-control-allow-credentials"), false);

  const preflight = await apply("cors.userinfo", "OPTIONS", undefined, "https://attacker.example");
  assert.equal(preflight.get("access-control-allow-origin"), "https://attacker.example");
  assert.equal(preflight.has("access-control-allow-credentials"), false);

  for (const route of ["discovery", "jwks", "openid_credential_issuer"]) {
    const publicMetadata = await apply(route, "GET", undefined, "https://attacker.example");
    assert.equal(publicMetadata.get("access-control-allow-origin"), "*");
    assert.equal(publicMetadata.has("access-control-allow-credentials"), false);
  }

  const directResponse = await apply("token", "POST", { clientId: "registered" }, "https://client.example", true);
  assert.equal(directResponse.has("access-control-allow-credentials"), false);
});
