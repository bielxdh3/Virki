import assert from "node:assert/strict";
import test from "node:test";
import { classifyLow05NavigationError, classifyLow05Url, describeLow05Response, isLow05ProtectedDocumentCacheControl, summarizeLow05ProxyBoundary } from "./low05-diagnostics.mjs";

const portalUrl = "https://portal.localhost:3001";

test("LOW-05 history document requires exact no-store in production and permits only Next dev's known override", () => {
  const productionHeader = "private, no-store, max-age=0, must-revalidate";
  const nextDevHeader = "no-cache, must-revalidate";
  assert.equal(isLow05ProtectedDocumentCacheControl(productionHeader, "production"), true);
  assert.equal(isLow05ProtectedDocumentCacheControl(nextDevHeader, "production"), false);
  assert.equal(isLow05ProtectedDocumentCacheControl(productionHeader, "development"), true);
  assert.equal(isLow05ProtectedDocumentCacheControl(nextDevHeader, "development"), true);
  for (const invalid of ["", "no-cache", "no-store", "private, max-age=0, must-revalidate", "public, no-cache, must-revalidate", "no-cache, must-revalidate, max-age=60"]) {
    assert.equal(isLow05ProtectedDocumentCacheControl(invalid, "development"), false, invalid);
    assert.equal(isLow05ProtectedDocumentCacheControl(invalid, "production"), false, invalid);
  }
  assert.equal(isLow05ProtectedDocumentCacheControl(nextDevHeader, "unknown"), false);
});

test("LOW-05 URL diagnostics preserve only allowlisted route and returnTo categories", () => {
  assert.deepEqual(
    classifyLow05Url("https://portal.localhost:3001/login?returnTo=%2Faccount%2Fsecurity&token=synthetic-token", portalUrl),
    { origin: "portal", route: "login", returnTo: "account-security" }
  );
  assert.deepEqual(
    classifyLow05Url("https://attacker.example/login?returnTo=%2Faccount%2Fsecurity", portalUrl),
    { origin: "other", route: "other", returnTo: "other" }
  );
  assert.deepEqual(
    classifyLow05Url("/account/security?user=synthetic-user", portalUrl),
    { origin: "portal", route: "account-security", returnTo: "absent" }
  );
});

test("LOW-05 response summary records status and safe header categories without raw values", () => {
  const response = {
    status: 307,
    url: "https://portal.localhost:3001/account/security?token=synthetic-query-secret",
    headers: {
      location: "https://portal.localhost:3001/login?returnTo=%2Faccount%2Fsecurity&state=synthetic-state-secret",
      "content-type": "text/html; charset=utf-8",
      "cache-control": "private, no-store, max-age=0, must-revalidate",
      "x-virki-request-id": "synthetic-request-id-secret"
    }
  };
  const summary = describeLow05Response(response, response.url, portalUrl);

  assert.deepEqual(summary, {
    route: { origin: "portal", route: "account-security", returnTo: "absent" },
    status: 307,
    location: { origin: "portal", route: "login", returnTo: "account-security" },
    contentType: "html",
    cacheControl: "private-no-store",
    requestIdPresent: true
  });
  const serialized = JSON.stringify(summary);
  for (const secret of ["synthetic-query-secret", "synthetic-state-secret", "synthetic-request-id-secret"]) {
    assert.equal(serialized.includes(secret), false);
  }
});

test("LOW-05 response summary supports the Playwright Response method API", () => {
  const response = {
    status: () => 302,
    url: () => "https://portal.localhost:3001/account/security?token=synthetic-query-secret",
    headers: () => ({
      location: "https://portal.localhost:3001/login?returnTo=%2Faccount%2Fsecurity&state=synthetic-state-secret",
      "content-type": "text/html; charset=utf-8",
      "cache-control": "private, no-store, max-age=0, must-revalidate",
      "x-virki-request-id": "synthetic-request-id-secret"
    })
  };
  const summary = describeLow05Response(response, response.url(), portalUrl);

  assert.deepEqual(summary, {
    route: { origin: "portal", route: "account-security", returnTo: "absent" },
    status: 302,
    location: { origin: "portal", route: "login", returnTo: "account-security" },
    contentType: "html",
    cacheControl: "private-no-store",
    requestIdPresent: true
  });
  const serialized = JSON.stringify(summary);
  for (const secret of ["synthetic-query-secret", "synthetic-state-secret", "synthetic-request-id-secret"]) {
    assert.equal(serialized.includes(secret), false);
  }
});

test("LOW-05 HTTPS proxy boundary summary redacts cookies, header values, and unrecognized routes", () => {
  const summary = summarizeLow05ProxyBoundary({
    request: {
      method: "GET",
      url: "/account/security?token=synthetic-query-secret",
      headers: {
        host: "portal.localhost:3001",
        cookie: "virki_session=synthetic-cookie-secret; csrf=synthetic-csrf-secret",
        "x-forwarded-host": "portal.localhost:3001",
        "x-forwarded-proto": "https",
        "cf-connecting-ip": "203.0.113.7"
      },
      socket: { encrypted: true }
    },
    response: {
      statusCode: 307,
      headers: {
        location: "https://portal.localhost:3001/login?returnTo=%2Faccount%2Fsecurity&state=synthetic-state-secret",
        "content-type": "text/html",
        "cache-control": "no-store",
        "x-virki-request-id": "synthetic-request-id-secret"
      }
    },
    environment: {
      NODE_ENV: "production",
      VIRKI_E2E_HUB_MODE: "production",
      VIRKI_PORTAL_HOSTNAME: "portal.localhost",
      VIRKI_PORTAL_URL: portalUrl
    },
    portalUrl
  });

  assert.deepEqual(summary, {
    boundary: "https-proxy-to-next",
    request: {
      method: "GET",
      route: "account-security",
      origin: "portal",
      scheme: "https",
      host: "portal",
      hostHasExplicitPort: true,
      encrypted: true,
      sessionCookiePresent: true,
      forwardedHost: "portal",
      forwardedHostHasExplicitPort: true,
      forwardedProto: "https",
      forwardedClientAddressPresent: true
    },
    environment: {
      production: true,
      productionHubMode: true,
      portalHostConfigured: true,
      portalUrlConfigured: true,
      portalUrlHasExplicitPort: true
    },
    response: {
      route: { origin: "portal", route: "account-security", returnTo: "absent" },
      status: 307,
      location: { origin: "portal", route: "login", returnTo: "account-security" },
      contentType: "html",
      cacheControl: "no-store",
      requestIdPresent: true
    }
  });

  const serialized = JSON.stringify(summary);
  for (const secret of [
    "synthetic-query-secret",
    "synthetic-cookie-secret",
    "synthetic-csrf-secret",
    "synthetic-state-secret",
    "synthetic-request-id-secret",
    "203.0.113.7"
  ]) {
    assert.equal(serialized.includes(secret), false);
  }
});

test("LOW-05 navigation errors are reduced to safe diagnostic categories", () => {
  assert.equal(classifyLow05NavigationError(new Error("net::ERR_CERT_AUTHORITY_INVALID at https://portal.localhost/private?token=secret")), "tls");
  assert.equal(classifyLow05NavigationError(new Error("net::ERR_NAME_NOT_RESOLVED")), "host-resolution");
  assert.equal(classifyLow05NavigationError(new Error("net::ERR_CONNECTION_REFUSED")), "connection");
  assert.equal(classifyLow05NavigationError(new Error("Timeout 5000ms exceeded")), "timeout");
  assert.equal(classifyLow05NavigationError(new Error("unrecognized private error with secret-value")), "navigation-error");
});
