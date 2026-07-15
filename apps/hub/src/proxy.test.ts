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
  const response = proxy(new NextRequest("http://hub.example.invalid/core/projects"));

  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "http://hub.example.invalid/login");
});
