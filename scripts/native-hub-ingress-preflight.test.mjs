import assert from "node:assert/strict";
import test from "node:test";
import { checkNativeHubIngress } from "./native-hub-ingress-preflight.mjs";
import { isCanonicalNativeAdminRedirect } from "./lib/native-hub-login-redirect.mjs";

const base = "https://hub-staging.example.test";
const routeHeaders = {
  "x-virki-request-id": "test-generated-id",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
  "cache-control": "private, no-store, max-age=0",
  "strict-transport-security": "max-age=31536000",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff"
};
const fixtureCsrf = (scope) => `v2.${"a".repeat(64)}.1790000000000.${"A".repeat(32)}.${Buffer.from(scope).toString("base64url")}.${"A".repeat(43)}`;
const publicLogin = `<main><h1 id="login-title">Entrar</h1><form action="/api/login" method="post"><input name="csrfToken" value="${fixtureCsrf("login")}"/><input name="password"/><input name="email"/></form></main>`;
const publicRecovery = `<main><h1 id="recover-title">Recuperar acesso administrativo</h1><form><input name="csrfToken" value="${fixtureCsrf("recovery-admin-request")}"/><input name="email"/><input name="method"/></form></main>`;

test("native ADMIN login redirects accept canonical absolute and relative Locations", () => {
  const origin = "https://hub.biel.dev.br";
  const path = "/admin/accounts";
  assert.equal(isCanonicalNativeAdminRedirect("/login?returnTo=%2Fadmin%2Faccounts", origin, path), true);
  assert.equal(isCanonicalNativeAdminRedirect(`${origin}/login?returnTo=%2Fadmin%2Faccounts`, origin, path), true);
});

test("native ADMIN login redirects reject external origins, wrong destinations, and extra parameters", () => {
  const origin = "https://hub.biel.dev.br";
  const path = "/admin/accounts";
  for (const location of [
    null, "", "//evil.example.test/login?returnTo=%2Fadmin%2Faccounts",
    "https://evil.example.test/login?returnTo=%2Fadmin%2Faccounts",
    "https://user@hub.biel.dev.br/login?returnTo=%2Fadmin%2Faccounts",
    "/login?returnTo=%2Fadmin%2Faudit", "/login?returnTo=%2Fadmin%2Faccounts&next=evil",
    "/login?returnTo=%2Fadmin%2Faccounts#fragment", "/admin/accounts"
  ]) assert.equal(isCanonicalNativeAdminRedirect(location, origin, path), false, String(location));
});

function responseFor(path) {
  if (path === "/login" || path === "/recover") return new Response(path === "/login" ? publicLogin : publicRecovery, { status: 200, headers: routeHeaders });
  if (["/admin/accounts", "/admin/audit", "/admin/security", "/admin/access", "/admin/connections"].includes(path)) return new Response(null, {
    status: 307,
    headers: { ...routeHeaders, location: `${base}/login?returnTo=${encodeURIComponent(path)}` }
  });
  throw new Error(`Unexpected request path ${path}`);
}

function fakeFetch(overrides = {}) {
  const paths = [];
  return {
    paths,
    fetch: async (url, options) => {
      assert.equal(options.redirect, "manual", "must never follow an external identity redirect");
      assert.equal(options.method, "GET");
      if (paths.length === 7) {
        assert.equal(options.headers.Cookie, "__Host-virki_session=forged", "the final probe must use the actual production cookie name");
      } else {
        assert.equal(options.headers.Cookie, undefined, "ordinary anonymous probes must never send a session cookie");
      }
      assert.equal(options.headers["cf-access-jwt-assertion"], paths.length >= 8 ? "forged" : undefined,
        "only the final negative probes may supply a forged Cloudflare Access assertion");
      const parsed = new URL(url);
      assert.equal(parsed.origin, base);
      paths.push(parsed.pathname);
      // A repeated HTTPS probe receives a fresh HTTP body, unlike a reused Response stream.
      return (overrides[parsed.pathname] ?? responseFor(parsed.pathname)).clone();
    }
  };
}

test("native Hub ingress allows anonymous login and recovery, while privileged routes redirect to Virki login", async () => {
  const client = fakeFetch();
  const result = await checkNativeHubIngress(base, client.fetch);
  assert.deepEqual(result, { origin: base, checked: ["/login", "/recover", "/admin/accounts", "/admin/audit", "/admin/security", "/admin/access", "/admin/connections", "/admin/accounts (forged cookie)", "/login (forged Access JWT)", "/admin/accounts (forged Access JWT)"] });
  assert.deepEqual(client.paths, ["/login", "/recover", "/admin/accounts", "/admin/audit", "/admin/security", "/admin/access", "/admin/connections", "/admin/accounts", "/login", "/admin/accounts"]);
});

test("native HTTPS ingress rejects a forged Cloudflare Access assertion as a substitute for native login", async () => {
  const client = fakeFetch();
  await assert.rejects(checkNativeHubIngress(base, async (url, options) => {
    const expected = await client.fetch(url, options);
    if (options.headers["cf-access-jwt-assertion"] && new URL(url).pathname === "/login") {
      return new Response("Forbidden", { status: 403, headers: routeHeaders });
    }
    return expected;
  }), /login.*HTTP 403.*native/i);
});

test("native HTTPS ingress never accepts a forged Cloudflare Access JWT as ADMIN authorization", async () => {
  const client = fakeFetch();
  await assert.rejects(checkNativeHubIngress(base, async (url, options) => {
    const expected = await client.fetch(url, options);
    if (options.headers["cf-access-jwt-assertion"] && new URL(url).pathname === "/admin/accounts") {
      return new Response("ADMIN data", { status: 200, headers: routeHeaders });
    }
    return expected;
  }), /admin\/accounts.*HTTP 200.*unauthenticated/i);
});

test("Cloudflare Access interstitial redirect prevents staging acceptance", async () => {
  const client = fakeFetch({ "/login": new Response(null, { status: 302, headers: { location: "https://team.cloudflareaccess.com/cdn-cgi/access/login" } }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*HTTP 302.*native/i);
  assert.deepEqual(client.paths, ["/login"]);
});

test("Cloudflare Access denies login, so staging cannot be marked ready", async () => {
  const client = fakeFetch({ "/login": new Response("Forbidden", { status: 403 }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*HTTP 403.*native/i);
});

test("an arbitrary HTTP 200 page does not impersonate Virki login", async () => {
  const client = fakeFetch({ "/login": new Response("fake login", { status: 200 }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*Virki request identity/i);
});

test("HTTP 200 with forged Virki request/CSP headers must not substitute a real native login form", async () => {
  const client = fakeFetch({ "/login": new Response("<html>Single Sign-On waiting room</html>", { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*(form|CSRF|password)/i);
});

test("HTTP 200 with Virki headers cannot hide an unavailable ADMIN recovery form", async () => {
  const client = fakeFetch({ "/recover": new Response("<html><h1>Reset unavailable</h1></html>", { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /recover.*(form|CSRF|ADMIN)/i);
});

test("login and recovery forms without scoped structurally intact CSRF tokens are not accepted", async () => {
  for (const [path, badMarkup] of [
    ["/login", publicLogin.replace(fixtureCsrf("login"), "v2.fake")],
    ["/recover", publicRecovery.replace(fixtureCsrf("recovery-admin-request"), fixtureCsrf("login"))],
  ]) {
    const client = fakeFetch({ [path]: new Response(badMarkup, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /CSRF/i);
  }
});

test("a native login or protected ADMIN redirect without anti-cache, HSTS and clickjacking headers is NO-GO", async () => {
  for (const path of ["/login", "/admin/accounts"]) {
    for (const header of ["cache-control", "strict-transport-security", "x-frame-options", "x-content-type-options"]) {
      const badHeaders = { ...routeHeaders };
      delete badHeaders[header];
      if (path === "/admin/accounts") badHeaders.location = `${base}/login?returnTo=%2Fadmin%2Faccounts`;
      const mocked = new Response(path === "/login" ? publicLogin : null, { status: path === "/login" ? 200 : 307, headers: badHeaders });
      const client = fakeFetch({ [path]: mocked });
      await assert.rejects(checkNativeHubIngress(base, client.fetch), /security headers/i, `${path} missing ${header}`);
    }
  }
});

test("a nominal CSP missing frame-ancestors, base-uri or object-src is not native staging acceptance", async () => {
  for (const missing of ["frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"]) {
    const headers = { ...routeHeaders, "content-security-policy": routeHeaders["content-security-policy"].replace(missing, "") };
    const client = fakeFetch({ "/recover": new Response(publicRecovery, { status: 200, headers }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /security headers/i);
  }
});

test("explicit weaker or duplicated CSP directives and ambiguous HSTS cannot pass staging acceptance", async () => {
  const unsafeHeaders = [
    { "content-security-policy": "default-src 'none'; object-src 'self'; frame-ancestors 'none'; base-uri 'none'" },
    { "content-security-policy": `${routeHeaders["content-security-policy"]}; object-src 'self'` },
    { "content-security-policy": `frame-ancestors 'self'; ${routeHeaders["content-security-policy"]}` },
    { "content-security-policy": `base-uri 'self'; ${routeHeaders["content-security-policy"]}` },
    { "strict-transport-security": "max-age=0; max-age=31536000" },
    { "strict-transport-security": "max-age=31536000; max-age=0" }
  ];
  for (const override of unsafeHeaders) {
    const client = fakeFetch({ "/login": new Response(publicLogin, { status: 200, headers: { ...routeHeaders, ...override } }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /security headers/i, JSON.stringify(override));
  }
});

test("external Tunnel HSTS with thirty-day max-age remains acceptable while zero-age is rejected", async () => {
  const valid = fakeFetch({ "/login": new Response(publicLogin, {
    status: 200, headers: { ...routeHeaders, "strict-transport-security": "max-age=2592000" }
  }) });
  await assert.doesNotReject(checkNativeHubIngress(base, valid.fetch));
  const weak = fakeFetch({ "/login": new Response(publicLogin, {
    status: 200, headers: { ...routeHeaders, "strict-transport-security": "max-age=0" }
  }) });
  await assert.rejects(checkNativeHubIngress(base, weak.fetch), /security headers/i);
});

test("unauthenticated privileged content being returned directly is a critical failure", async () => {
  const client = fakeFetch({ "/admin/accounts": new Response("ADMIN data", { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /admin\/accounts.*HTTP 200.*unauthenticated/i);
});

test("audit and security routes must reject anonymous requests before revealing privileged data", async () => {
  for (const path of ["/admin/audit", "/admin/security", "/admin/access", "/admin/connections"]) {
    const client = fakeFetch({ [path]: new Response("sensitive", { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /unauthenticated ADMIN/i);
  }
});

test("a forged Virki session cookie is never accepted as ADMIN", async () => {
  const calls = [];
  const client = async (url, options) => {
    const path = new URL(url).pathname;
    calls.push({ path, cookie: options.headers.Cookie });
    if (options.headers.Cookie) return new Response("stolen ADMIN data", { status: 200, headers: routeHeaders });
    return responseFor(path);
  };
  await assert.rejects(checkNativeHubIngress(base, client), /forged.*ADMIN|unauthenticated ADMIN/i);
  assert.equal(calls.at(-1)?.cookie, "__Host-virki_session=forged");
});

test("privileged redirects must remain on the same origin and point to the intended Virki login", async () => {
  const client = fakeFetch({ "/admin/accounts": new Response(null, { status: 307, headers: { ...routeHeaders, location: "https://team.cloudflareaccess.com/login" } }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /admin\/accounts.*canonical Virki login/i);
});

test("rejects unsafe input rather than probing HTTP or credentials-bearing URLs", async () => {
  for (const invalid of ["http://hub-staging.example.test", "https://user:password@hub-staging.example.test", "https://hub-staging.example.test/private", "https://hub-staging.example.test?token=secret"]) {
    await assert.rejects(checkNativeHubIngress(invalid, fakeFetch().fetch), /HTTPS origin/i);
  }
});
