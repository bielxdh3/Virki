import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const productionCompose = readFileSync(path.join(repositoryRoot, "infra", "docker-compose.prod.yml"), "utf8");
const cloudflareCompose = readFileSync(path.join(repositoryRoot, "infra", "docker-compose.cloudflare.yml"), "utf8");
const cloudflareTemplate = readFileSync(path.join(repositoryRoot, "infra", "cloudflare", "config.example.yml"), "utf8");

function serviceBlock(compose, service) {
  const match = compose.match(new RegExp(`\\n  ${service}:\\n([\\s\\S]*?)(?=\\n  [a-z0-9-]+:\\n|\\nvolumes:|$)`, "u"));
  assert.ok(match, `Missing Compose service: ${service}`);
  return match[1];
}

test("production exposes only the public site and loopback application surfaces", () => {
  for (const service of ["public-site", "hub"]) {
    assert.match(serviceBlock(productionCompose, service), /127\.0\.0\.1:/u);
  }
  for (const service of ["oidc-issuer", "session-cleanup", "email-worker", "postgres", "migrate"]) {
    assert.doesNotMatch(serviceBlock(productionCompose, service), /ports:/u);
  }
  assert.doesNotMatch(productionCompose, /^\x20{2}intake:/mu);
  assert.doesNotMatch(productionCompose, /BIELOS_INTAKE|apps\/intake/iu);
});

test("hub keeps Cloudflare Access mandatory and OIDC secrets outside shared environment", () => {
  const hub = serviceBlock(productionCompose, "hub");
  const issuer = serviceBlock(productionCompose, "oidc-issuer");
  assert.match(hub, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*"true"/u);
  assert.match(hub, /CLOUDFLARE_ACCESS_AUDIENCE:\s*\$\{CLOUDFLARE_ACCESS_AUDIENCE:\?/u);
  assert.match(hub, /CLOUDFLARE_TEAM_DOMAIN:\s*\$\{CLOUDFLARE_TEAM_DOMAIN:\?/u);
  for (const block of [hub, issuer]) {
    assert.match(block, /path: \.\.\/\.env\.oidc/u);
    assert.match(block, /required: false/u);
  }
  assert.doesNotMatch(productionCompose, /BIELOS_OIDC_SIGNING_JWKS:\s*\$\{/u);
  assert.doesNotMatch(hub, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*\$\{/u);
});

test("portal host reaches the hub OIDC proxy and Cloudflare tunnel uses no www alias", () => {
  assert.match(serviceBlock(productionCompose, "hub"), /BIELOS_PORTAL_HOSTNAME:.*portal\.biel\.dev\.br/u);
  assert.match(cloudflareCompose, /- oidc-issuer/u);
  assert.match(cloudflareTemplate, /hostname: portal\.biel\.dev\.br\s+service: http:\/\/hub:3001/u);
  assert.doesNotMatch(cloudflareTemplate, /hostname: www\./u);
});

test("production workers and database retain restart policy without published ports", () => {
  for (const service of ["oidc-issuer", "session-cleanup", "email-worker", "postgres"]) {
    const block = serviceBlock(productionCompose, service);
    assert.match(block, /restart:\s*unless-stopped/u);
    assert.doesNotMatch(block, /ports:/u);
  }
  assert.match(serviceBlock(productionCompose, "postgres"), /bielos_postgres_data:\/var\/lib\/postgresql\/data/u);
});
