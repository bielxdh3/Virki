import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const productionCompose = readFileSync(
  path.join(repositoryRoot, "infra", "docker-compose.prod.yml"),
  "utf8"
);

test("production Compose requires complete Cloudflare Access configuration and enables JWT validation", () => {
  assert.match(productionCompose, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*"true"/u);
  assert.match(
    productionCompose,
    /CLOUDFLARE_ACCESS_AUDIENCE:\s*\$\{CLOUDFLARE_ACCESS_AUDIENCE:\?/u
  );
  assert.match(
    productionCompose,
    /CLOUDFLARE_TEAM_DOMAIN:\s*\$\{CLOUDFLARE_TEAM_DOMAIN:\?/u
  );
  assert.doesNotMatch(productionCompose, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*\$\{/u);
});
