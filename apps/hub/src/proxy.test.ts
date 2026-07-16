import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { proxy } from "./proxy";

test("logout requests reach origin validation before session routing", () => {
  const response = proxy(
    new NextRequest("http://hub.example.invalid/api/logout", {
      method: "POST"
    })
  );

  assert.equal(response.headers.get("x-middleware-next"), "1");
  assert.equal(response.headers.get("location"), null);
});

test("protected pages without a session still redirect to login", () => {
  const response = proxy(
    new NextRequest("http://hub:3001/core/projects"),
    {
      NODE_ENV: "production",
      NEXT_PUBLIC_HUB_URL: "https://hub.example.invalid"
    }
  );

  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "https://hub.example.invalid/login");
});

test("protected pages fail closed when production redirect configuration is invalid", () => {
  const response = proxy(
    new NextRequest("http://hub:3001/core/projects"),
    { NODE_ENV: "production" }
  );

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("location"), null);
  assert.equal(response.headers.get("location")?.includes("hub:3001") ?? false, false);
});
