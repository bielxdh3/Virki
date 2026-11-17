import assert from "node:assert/strict";
import test from "node:test";
import { checkNativeHubIngress } from "./native-hub-ingress-preflight.mjs";

const base = "https://hub-staging.example.test";
const routeHeaders = { "x-virki-request-id": "test-generated-id", "content-security-policy": "default-src 'self'" };

function responseFor(path) {
  if (path === "/login" || path === "/recover") return new Response("Virki", { status: 200, headers: routeHeaders });
  if (path === "/admin/accounts") return new Response(null, {
    status: 307,
    headers: { ...routeHeaders, location: `${base}/login?returnTo=%2Fadmin%2Faccounts` }
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
      assert.equal(options.headers.Cookie, undefined, "never send a session cookie in the anonymous probe");
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
  assert.deepEqual(result, { origin: base, checked: ["/login", "/recover", "/admin/accounts"] });
  assert.deepEqual(client.paths, ["/login", "/recover", "/admin/accounts"]);
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

test("privileged redirects must remain on the same origin and point to the intended Virki login", async () => {
  const client = fakeFetch({ "/admin/accounts": new Response(null, { status: 307, headers: { ...routeHeaders, location: "https://team.cloudflareaccess.com/login" } }) });
  await assert.rejects(checkNativeHubIngress(base, client.fetch), /admin\/accounts.*canonical Virki login/i);
});

test("rejects unsafe input rather than probing HTTP or credentials-bearing URLs", async () => {
  for (const invalid of ["http://hub-staging.example.test", "https://user:password@hub-staging.example.test", "https://hub-staging.example.test/private", "https://hub-staging.example.test?token=secret"]) {
    await assert.rejects(checkNativeHubIngress(invalid, fakeFetch().fetch), /HTTPS origin/i);
  }
});
