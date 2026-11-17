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
const publicRecovery = `<main><h1 id="recover-title">Recuperar acesso administrativo</h1>
  <form action="javascript:throw new Error('React form unexpectedly submitted')"><input name="csrfToken" value="${fixtureCsrf("recovery-admin-request")}"/><input name="email"/><input name="method"/></form>
  <form action="" encType="multipart/form-data" method="POST"><input name="$ACTION_ID_${"a".repeat(40)}"/><input name="csrfToken" value="${fixtureCsrf("recovery-admin-request")}"/><input name="email"/></form>
</main>`;

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

test("a fabricated native login assembled from unrelated forms must not pass preflight", async () => {
  const counterfeit = `<main><h1 id="login-title">Entrar</h1>
    <form action="/api/login" method="post"><input name="email"></form>
    <form action="/other" method="post"><input name="password"><input name="csrfToken" value="${fixtureCsrf("login")}"></form>
  </main>`;
  const client = fakeFetch({ "/login": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*(form|CSRF)/i,
    "a POST action, credentials and CSRF must belong to the SAME usable login form");
});

test("data-* attributes cannot masquerade as actionable login form attributes", async () => {
  const counterfeit = `<main><h1 id="login-title">Entrar</h1>
    <form data-action="/api/login" data-method="post">
      <input data-name="email"><input data-name="password">
      <input data-name="csrfToken" data-value="${fixtureCsrf("login")}">
    </form></main>`;
  const client = fakeFetch({ "/login": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*(form|CSRF)/i,
    "lookalike data attributes are not browser-submitted login fields");
});

test("data-* attributes cannot impersonate both ADMIN recovery forms", async () => {
  const counterfeit = `<main><h1 id="recover-title">Recuperar acesso administrativo</h1>
    <form><input data-name="email"><input data-name="method">
      <input data-name="csrfToken" data-value="${fixtureCsrf("recovery-admin-request")}"></form>
    <form data-method="POST"><input data-name="$ACTION_ID_${"a".repeat(40)}">
      <input data-name="email"><input data-name="csrfToken" data-value="${fixtureCsrf("recovery-admin-request")}"></form>
    </main>`;
  const client = fakeFetch({ "/recover": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /recover.*(form|CSRF)/i,
    "lookalike data attributes are not real recovery fields or submission methods");
});

test("HTML comments and inert templates cannot impersonate a live login form", async () => {
  for (const hiddenMarkup of [
    `<!-- ${publicLogin} -->`,
    `<template>${publicLogin}</template>`,
    `<script type="text/plain">${publicLogin}</script>`
  ]) {
    const markup = `<h1 id="login-title">Entrar</h1>${hiddenMarkup}`;
    const client = fakeFetch({ "/login": new Response(markup, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*(form|CSRF)/i,
      "inert HTML must not satisfy the login form contract");
  }
});

test("RCDATA/RAWTEXT elements cannot impersonate operative login or ADMIN recovery forms", async () => {
  for (const tag of ["title", "xmp", "iframe", "noembed"]) {
    const login = `<html><head><${tag}>${publicLogin}</${tag}></head></html>`;
    const loginFetch = fakeFetch({ "/login": new Response(login, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, loginFetch.fetch), /login.*(form|CSRF)/i,
      `${tag} contains no operable browser form`);
    const recovery = `<html><head><${tag}>${publicRecovery}</${tag}></head></html>`;
    const recoverFetch = fakeFetch({ "/recover": new Response(recovery, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, recoverFetch.fetch), /recover.*(form|CSRF)/i,
      `${tag} contains no operable recovery forms`);
  }
});

test("form-decoy and input-decoy custom tags cannot impersonate native forms", async () => {
  const bogus = `<h1 id="login-title">Entrar</h1><form-decoy action="/api/login" method="post">
    <input-decoy name="email"><input-decoy name="password">
    <input-decoy name="csrfToken" value="${fixtureCsrf("login")}"></form>`;
  const client = fakeFetch({ "/login": new Response(bogus, { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*(form|CSRF)/i,
    "custom elements are not HTML forms or inputs");
});

test("HTML fragments quoted inside a harmless attribute are not operative forms", async () => {
  for (const [path, content] of [["/login", publicLogin], ["/recover", publicRecovery]]) {
    const counterfeit = `<div data-fixture='${content}'></div>`;
    const client = fakeFetch({ [path]: new Response(counterfeit, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /form|CSRF/i,
      `${path}: the browser keeps quoted tags in an attribute, not the DOM`);
  }
});

test("disabled, foreign-form and disabled-fieldset inputs are not usable login controls", async () => {
  for (const counterfeit of [
    publicLogin.replace('name="email"', 'name="email" disabled'),
    publicLogin.replace('name="password"', 'name="password" form="other-form"'),
    publicLogin.replace('<input name="email"/>', '<fieldset disabled><input name="email"/></fieldset>')
  ]) {
    const client = fakeFetch({ "/login": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*(form|CSRF)/i);
  }
});

test("disabled and unowned inputs cannot fabricate either ADMIN recovery stage", async () => {
  for (const counterfeit of [
    publicRecovery.replace('name="email"', 'name="email" disabled'),
    publicRecovery.replace('name="email"', 'name="email" form="other-form"'),
    publicRecovery.replace('<input name="email"/>', '<fieldset disabled><input name="email"/></fieldset>')
  ]) {
    const client = fakeFetch({ "/recover": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /recover.*(form|CSRF)/i);
  }
});

test("forms inside disabled ancestor fieldsets are not operable", async () => {
  for (const [path, markup] of [["/login", publicLogin], ["/recover", publicRecovery]]) {
    const counterfeit = `<fieldset disabled>${markup}</fieldset>`;
    const client = fakeFetch({ [path]: new Response(counterfeit, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /form|CSRF/i,
      `${path}: controls inside a disabled ancestor fieldset cannot be submitted`);
  }
});

test("hidden and readonly credential fields do not make a usable login screen", async () => {
  for (const counterfeit of [
    publicLogin.replace('name="email"', 'type="hidden" name="email" value="fixed"'),
    publicLogin.replace('name="password"', 'type="hidden" name="password" value="fixed"'),
    publicLogin.replace('name="email"', 'name="email" readonly')
  ]) {
    const client = fakeFetch({ "/login": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /login.*(form|CSRF)/i);
  }
});

test("hidden and readonly recovery email controls cannot fake a recovery UI", async () => {
  for (const counterfeit of [
    publicRecovery.replace('name="email"', 'type="hidden" name="email" value="fixed"'),
    publicRecovery.replace('name="email"', 'name="email" readonly')
  ]) {
    const client = fakeFetch({ "/recover": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
    await assert.rejects(checkNativeHubIngress(base, client.fetch), /recover.*(form|CSRF)/i);
  }
});

test("a GET-only recovery-looking form must not count as a working ADMIN recovery entrypoint", async () => {
  const counterfeit = `<main><h1 id="recover-title">Recuperar acesso administrativo</h1>
    <form action="/sso" method="get"><input name="email"><input name="method">
      <input name="csrfToken" value="${fixtureCsrf("recovery-admin-request")}"></form>
  </main>`;
  const client = fakeFetch({ "/recover": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /recover.*(form|CSRF)/i,
    "a read-only GET form cannot submit ADMIN recovery");
});

test("a single POST form impersonating both ADMIN recovery stages cannot pass native ingress", async () => {
  const counterfeit = `<main><h1 id="recover-title">Recuperar acesso administrativo</h1>
    <form method="post"><input name="email"><input name="method">
      <input name="$ACTION_ID_${"a".repeat(40)}">
      <input name="csrfToken" value="${fixtureCsrf("recovery-admin-request")}">
    </form>
  </main>`;
  const client = fakeFetch({ "/recover": new Response(counterfeit, { status: 200, headers: routeHeaders }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /recover.*(form|CSRF)/i,
    "both recovery stages must have distinct independently rendered forms");
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
