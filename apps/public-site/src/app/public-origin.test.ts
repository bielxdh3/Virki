import assert from "node:assert/strict";
import test from "node:test";
import { readPublicOrigin } from "./public-origin";
import sitemap from "./sitemap";

test("public metadata shares a validated origin and falls back for unsafe configuration", () => {
  assert.equal(readPublicOrigin({ PUBLIC_SITE_URL: "https://www.example.test/" }), "https://www.example.test");
  for (const value of [undefined, "not-a-url", "http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test/?x=1"]) {
    assert.equal(readPublicOrigin({ PUBLIC_SITE_URL: value }), "https://biel.dev.br", String(value));
  }
});

test("sitemap uses the validated public origin instead of the raw environment value", () => {
  const previous = process.env.PUBLIC_SITE_URL;
  try {
    process.env.PUBLIC_SITE_URL = "https://www.example.test/";
    assert.deepEqual(sitemap(), [{ url: "https://www.example.test" }]);
    process.env.PUBLIC_SITE_URL = "https://www.example.test/path";
    assert.deepEqual(sitemap(), [{ url: "https://biel.dev.br" }]);
  } finally {
    if (previous === undefined) delete process.env.PUBLIC_SITE_URL;
    else process.env.PUBLIC_SITE_URL = previous;
  }
});
