import assert from "node:assert/strict";
import test from "node:test";

import { createHubRedirectUrl, type HubRedirectPath } from "./hub-redirect";

const productionEnvironment = {
  NODE_ENV: "production",
  NEXT_PUBLIC_HUB_URL: "https://hub.example.invalid"
};

test("uses the configured public hub origin instead of the internal request origin", () => {
  const url = createHubRedirectUrl(
    "/login",
    "https://localhost:3001/api/logout",
    productionEnvironment
  );

  assert.equal(url.href, "https://hub.example.invalid/login");
});

test("allows an explicit HTTP origin outside production and a local fallback when absent", () => {
  assert.equal(
    createHubRedirectUrl("/", "http://localhost:3001/api/login", {
      NODE_ENV: "development",
      NEXT_PUBLIC_HUB_URL: "http://localhost:3001"
    }).href,
    "http://localhost:3001/"
  );
  assert.equal(
    createHubRedirectUrl("/login", "http://localhost:3001/api/logout", {
      NODE_ENV: "test"
    }).href,
    "http://localhost:3001/login"
  );
});

test("trims spaces and normalizes hostname case and the default HTTPS port", () => {
  assert.equal(
    createHubRedirectUrl("/login", "http://localhost:3001/api/logout", {
      NODE_ENV: "production",
      NEXT_PUBLIC_HUB_URL: "  https://HUB.EXAMPLE.INVALID:443/  "
    }).href,
    "https://hub.example.invalid/login"
  );
});

test("fails closed for missing or unsafe production configuration", () => {
  const rejectedValues: Array<string | undefined> = [
    undefined,
    "",
    "   ",
    "http://hub.example.invalid",
    "javascript:private-detail",
    "data:text/plain,private-detail",
    "file:///private-detail",
    "https://user:private-detail@hub.example.invalid",
    "https://hub.example.invalid/private",
    "https://hub.example.invalid?private=1",
    "https://hub.example.invalid#private",
    "not a url",
    "//attacker.example",
    "https://hub.example.invalid/\n"
  ];

  for (const value of rejectedValues) {
    assert.throws(
      () => createHubRedirectUrl("/", "http://hub:3001/api/login", {
        NODE_ENV: "production",
        NEXT_PUBLIC_HUB_URL: value
      }),
      (error: Error) => {
        assert.equal(error.message, "Invalid hub redirect configuration.");
        if (value?.trim()) {
          assert.equal(error.message.includes(value), false);
        }
        assert.equal(error.message.includes("hub:3001"), false);
        return true;
      }
    );
  }
});

test("rejects an unsafe configured value outside production instead of falling back", () => {
  assert.throws(
    () => createHubRedirectUrl("/", "http://localhost:3001/api/login", {
      NODE_ENV: "development",
      NEXT_PUBLIC_HUB_URL: "javascript:private-detail"
    }),
    /Invalid hub redirect configuration\./
  );
});

test("rejects every destination outside the narrow same-origin contract", () => {
  const uncheckedCreate = createHubRedirectUrl as (
    pathname: string,
    requestUrl: string,
    env: Readonly<Record<string, string | undefined>>
  ) => URL;
  const rejectedPaths = [
    "",
    "//attacker.example",
    "\\\\attacker.example",
    "https://attacker.example",
    "javascript:private-detail",
    "/login\nLocation: https://attacker.example",
    "/%2f%2fattacker.example",
    "/%5c%5cattacker.example"
  ];

  for (const pathname of rejectedPaths) {
    assert.throws(
      () => uncheckedCreate(pathname, "http://hub:3001/api/login", productionEnvironment),
      (error: Error) => {
        assert.equal(error.message, "Invalid hub redirect destination.");
        if (pathname) {
          assert.equal(error.message.includes(pathname), false);
        }
        return true;
      }
    );
  }

  for (const pathname of ["/", "/login"] satisfies HubRedirectPath[]) {
    assert.equal(
      createHubRedirectUrl(pathname, "http://hub:3001/api/login", productionEnvironment).origin,
      "https://hub.example.invalid"
    );
  }
});
