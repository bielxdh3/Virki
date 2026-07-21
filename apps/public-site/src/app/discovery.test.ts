import assert from "node:assert/strict";
import test from "node:test";
import { PUBLIC_SITE_ORIGIN, PUBLIC_SITE_URL, PUBLIC_SITEMAP_URL, publicSiteMetadata } from "./discovery";
import robots from "./robots";
import sitemap from "./sitemap";

const privateDiscoveryPattern = /hub\.biel\.dev\.br|\/api\/health|\/core|\/gymforge|l-vault|root\.ark|h-vault/i;

test("publishes only the canonical public URL in the sitemap", () => {
  const entries = sitemap();

  assert.deepEqual(entries.map((entry) => entry.url), [PUBLIC_SITE_URL]);
  assert.equal(privateDiscoveryPattern.test(JSON.stringify(entries)), false);
});

test("allows the public root and references only the canonical sitemap", () => {
  const result = robots();

  assert.deepEqual(result.rules, { userAgent: "*", allow: "/" });
  assert.equal(result.sitemap, PUBLIC_SITEMAP_URL);
  assert.equal(result.host, PUBLIC_SITE_ORIGIN);
  assert.equal(privateDiscoveryPattern.test(JSON.stringify(result)), false);
});

test("uses the public origin for canonical metadata", () => {
  assert.equal(publicSiteMetadata.metadataBase?.toString(), PUBLIC_SITE_URL);
  assert.deepEqual(publicSiteMetadata.alternates, { canonical: "/" });
});
