import assert from "node:assert/strict";
import test from "node:test";

import { createHubRedirectUrl } from "./hub-redirect";

test("uses the configured public hub origin instead of the internal request origin", () => {
  const url = createHubRedirectUrl(
    "/login",
    "https://localhost:3001/api/logout",
    { NEXT_PUBLIC_HUB_URL: "https://hub.example.invalid" }
  );

  assert.equal(url.href, "https://hub.example.invalid/login");
});

test("falls back to the request origin when the configured value is absent or unsafe", () => {
  assert.equal(
    createHubRedirectUrl("/", "http://hub.example.invalid/api/login", {}).href,
    "http://hub.example.invalid/"
  );
  assert.equal(
    createHubRedirectUrl("/", "http://hub.example.invalid/api/login", {
      NEXT_PUBLIC_HUB_URL: "javascript:private-detail"
    }).href,
    "http://hub.example.invalid/"
  );
  assert.equal(
    createHubRedirectUrl("/", "http://hub.example.invalid/api/login", {
      NEXT_PUBLIC_HUB_URL: "https://user:private-detail@hub.example.invalid"
    }).href,
    "http://hub.example.invalid/"
  );
});
