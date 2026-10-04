import assert from "node:assert/strict";
import test from "node:test";

test("OIDC rewrites default to Compose DNS for builds and allow loopback for direct development", async () => {
  const previousIssuer = process.env.BIELOS_OIDC_PROXY_URL;
  const previousPortal = process.env.BIELOS_PORTAL_HOSTNAME;
  const previousNodeEnv = process.env.NODE_ENV;
  delete process.env.BIELOS_OIDC_PROXY_URL;
  process.env.BIELOS_PORTAL_HOSTNAME = "portal.example.test";

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

    process.env.BIELOS_OIDC_PROXY_URL = "http://127.0.0.1:3003";
    const localRewrite = await getDiscoveryRewrite();
    assert.equal(localRewrite.destination, "http://127.0.0.1:3003/.well-known/:path*");

    process.env.BIELOS_OIDC_PROXY_URL = "http://oidc-issuer:3003";
    const composeRewrite = await getDiscoveryRewrite();
    assert.equal(composeRewrite.destination, "http://oidc-issuer:3003/.well-known/:path*");

    process.env.NODE_ENV = "production";
    for (const surfaceConfig of [config, publicConfig]) {
      const routeHeaders = (await surfaceConfig.headers()).find((route) => route.source === "/:path*").headers;
      const headerMap = Object.fromEntries(routeHeaders.map(({ key, value }) => [key.toLowerCase(), value]));
      assert.equal(headerMap["content-security-policy"], "frame-ancestors 'none'");
      assert.equal(headerMap["permissions-policy"], "camera=(), geolocation=(), microphone=()");
      assert.equal(headerMap["referrer-policy"], "no-referrer");
      assert.equal(headerMap["x-content-type-options"], "nosniff");
      assert.equal(headerMap["x-frame-options"], "DENY");
      assert.equal(headerMap["strict-transport-security"], "max-age=31536000");
    }
  } finally {
    if (previousIssuer === undefined) delete process.env.BIELOS_OIDC_PROXY_URL;
    else process.env.BIELOS_OIDC_PROXY_URL = previousIssuer;
    if (previousPortal === undefined) delete process.env.BIELOS_PORTAL_HOSTNAME;
    else process.env.BIELOS_PORTAL_HOSTNAME = previousPortal;
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
  }
});
