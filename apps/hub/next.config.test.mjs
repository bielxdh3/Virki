import assert from "node:assert/strict";
import test from "node:test";

test("OIDC rewrites default to Compose DNS for builds and allow loopback for direct development", async () => {
  const previousIssuer = process.env.VIRKI_OIDC_PROXY_URL;
  const previousPortal = process.env.VIRKI_PORTAL_HOSTNAME;
  const previousNodeEnv = process.env.NODE_ENV;
  delete process.env.VIRKI_OIDC_PROXY_URL;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.example.test";

  try {
    const { default: config } = await import("./next.config.mjs");
    const { default: publicConfig } = await import("../public-site/next.config.mjs");
    const getDiscoveryRewrite = async () => (await config.rewrites()).find((route) => route.source === "/.well-known/:path*");
    const getAuthorizationRewrites = async () => (await config.rewrites()).filter((route) => route.source === "/auth" || route.source === "/auth/:uid");

    const buildDefaultRewrite = await getDiscoveryRewrite();
    assert.equal(buildDefaultRewrite.destination, "http://oidc-issuer:3003/.well-known/:path*");
    assert.deepEqual(buildDefaultRewrite.has, [{ type: "host", value: "portal.example.test" }]);

    const authorizationRewrites = await getAuthorizationRewrites();
    assert.deepEqual(authorizationRewrites.map((route) => route.source), ["/auth", "/auth/:uid"]);
    for (const route of authorizationRewrites) {
      assert.equal(route.destination, `http://oidc-issuer:3003${route.source}`);
      assert.deepEqual(route.has, [{ type: "host", value: "portal.example.test" }]);
    }

    process.env.VIRKI_OIDC_PROXY_URL = "http://127.0.0.1:3003";
    const localRewrite = await getDiscoveryRewrite();
    assert.equal(localRewrite.destination, "http://127.0.0.1:3003/.well-known/:path*");

    process.env.VIRKI_OIDC_PROXY_URL = "http://oidc-issuer:3003";
    const composeRewrite = await getDiscoveryRewrite();
    assert.equal(composeRewrite.destination, "http://oidc-issuer:3003/.well-known/:path*");

    process.env.NODE_ENV = "production";
    for (const [surfaceConfig, expectedReferrerPolicy] of [[config, "strict-origin"], [publicConfig, "no-referrer"]]) {
      const routeHeaders = (await surfaceConfig.headers()).find((route) => route.source === "/:path*").headers;
      const headerMap = Object.fromEntries(routeHeaders.map(({ key, value }) => [key.toLowerCase(), value]));
      if (surfaceConfig === config) {
        // The hub CSP carries a per-request nonce and is set by src/proxy.ts; a static one here would be a duplicate.
        assert.equal(headerMap["content-security-policy"], undefined);
      } else {
        const csp = headerMap["content-security-policy"];
        assert.equal(
          csp,
          "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        );
        assert.doesNotMatch(csp, /unsafe-eval/u);
      }
      assert.equal(headerMap["permissions-policy"], "camera=(), geolocation=(), microphone=()");
      assert.equal(headerMap["referrer-policy"], expectedReferrerPolicy);
      assert.equal(headerMap["x-content-type-options"], "nosniff");
      assert.equal(headerMap["x-frame-options"], "DENY");
      assert.equal(headerMap["strict-transport-security"], "max-age=31536000");
    }
    process.env.NODE_ENV = "development";
    const developmentHeaders = (await publicConfig.headers()).find((route) => route.source === "/:path*").headers;
    const developmentCsp = developmentHeaders.find(({ key }) => key === "Content-Security-Policy").value;
    assert.match(developmentCsp, /script-src 'self' 'unsafe-inline' 'unsafe-eval'/u);
    assert.doesNotMatch(developmentCsp, /upgrade-insecure-requests/u);
  } finally {
    if (previousIssuer === undefined) delete process.env.VIRKI_OIDC_PROXY_URL;
    else process.env.VIRKI_OIDC_PROXY_URL = previousIssuer;
    if (previousPortal === undefined) delete process.env.VIRKI_PORTAL_HOSTNAME;
    else process.env.VIRKI_PORTAL_HOSTNAME = previousPortal;
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
  }
});
