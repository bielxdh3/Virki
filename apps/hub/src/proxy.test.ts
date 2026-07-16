import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
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
