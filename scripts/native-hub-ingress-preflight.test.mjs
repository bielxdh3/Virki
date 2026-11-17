import assert from "node:assert/strict";
import test from "node:test";
import { checkNativeHubIngress } from "./native-hub-ingress-preflight.mjs";
import { isCanonicalNativeAdminRedirect } from "./lib/native-hub-login-redirect.mjs";

const base = "https://hub-staging.example.test";
const routeHeaders = { "x-virki-request-id": "test-generated-id", "content-security-policy": "default-src 'self'" };

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
  if (path === "/login" || path === "/recover") return new Response("Virki", { status: 200, headers: routeHeaders });
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
      return overrides[parsed.pathname] ?? responseFor(parsed.pathname);
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
