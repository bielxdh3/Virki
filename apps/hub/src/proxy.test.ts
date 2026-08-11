import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";

import { handlePageShow } from "./app/session-history-guard";
import { evaluateProxyRequest, proxy } from "./proxy";

test("logout requests reach origin validation before session routing", () => {
  const response = evaluateProxyRequest(
    new NextRequest("http://hub.example.invalid/api/logout", {
      method: "POST"
    }),
    {}
  );

  assert.equal(response.headers.get("x-middleware-next"), "1");
  assert.equal(response.headers.get("location"), null);
});

test("protected pages without a session still redirect to login", () => {
  const response = evaluateProxyRequest(
    new NextRequest("http://hub:3001/core/projects"),
    {
      NODE_ENV: "production",
      NEXT_PUBLIC_HUB_URL: "https://hub.example.invalid"
    }
  );

  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "https://hub.example.invalid/login");
});

test("login verification routes are reachable before a session exists", () => {
  for (const pathname of ["/login/verify", "/api/login/verify"]) {
    const response = evaluateProxyRequest(
      new NextRequest(`http://hub:3001${pathname}`),
      { NODE_ENV: "production", NEXT_PUBLIC_HUB_URL: "https://hub.example.invalid" }
    );

    assert.equal(response.headers.get("x-middleware-next"), "1");
    assert.equal(response.headers.get("location"), null);
  }
});

test("protected pages without a required Access assertion fail before session routing", () => {
  const response = evaluateProxyRequest(
    new NextRequest("http://hub:3001/core/projects"),
    {
      NODE_ENV: "production",
      NEXT_PUBLIC_HUB_URL: "https://hub.example.invalid",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "true"
    }
  );

  assert.equal(response.status, 403);
  assert.equal(response.headers.get("location"), null);
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("a present required Access assertion passes the early gate before session routing", () => {
  const response = evaluateProxyRequest(
    new NextRequest("http://hub:3001/core/projects", {
      headers: {
        "cf-access-jwt-assertion": "synthetic-unverified-value"
      }
    }),
    {
      NODE_ENV: "production",
      NEXT_PUBLIC_HUB_URL: "https://hub.example.invalid",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "true"
    }
  );

  assert.equal(response.headers.get("x-middleware-next"), "1");
  assert.equal(response.headers.get("location"), null);
  assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0, must-revalidate");
});

test("the framework event argument cannot replace the runtime environment", () => {
  const previousValue = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";

  try {
    const frameworkProxy = proxy as unknown as (
      request: NextRequest,
      event: object
    ) => Response;
    const response = frameworkProxy(
      new NextRequest("http://hub:3001/core/projects"),
      {}
    );

    assert.equal(response.status, 403);
    assert.equal(response.headers.get("location"), null);
  } finally {
    if (previousValue === undefined) {
      delete process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
    } else {
      process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = previousValue;
    }
  }
});

test("protected pages fail closed when production redirect configuration is invalid", () => {
  const response = evaluateProxyRequest(
    new NextRequest("http://hub:3001/core/projects"),
    { NODE_ENV: "production" }
  );

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("location"), null);
  assert.equal(response.headers.get("location")?.includes("hub:3001") ?? false, false);
});

test("reloads a page restored from the browser back-forward cache", () => {
  let reloads = 0;

  handlePageShow({ persisted: true }, () => {
    reloads += 1;
  });

  assert.equal(reloads, 1);
});

test("does not reload a normally loaded page", () => {
  let reloads = 0;

  handlePageShow({ persisted: false }, () => {
    reloads += 1;
  });

  assert.equal(reloads, 0);
});
