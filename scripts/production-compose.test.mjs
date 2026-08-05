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
const developmentCompose = readFileSync(
  path.join(repositoryRoot, "infra", "docker-compose.yml"),
  "utf8"
);

function serviceBlock(compose, service) {
  const match = compose.match(
    new RegExp(`\\n  ${service}:\\n([\\s\\S]*?)(?=\\n  [a-z0-9-]+:\\n|\\nvolumes:|$)`, "u")
  );
  assert.ok(match, `Missing Compose service: ${service}`);
  return match[1];
}

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

test("Compose keeps Intake restricted and fail-closed", () => {
  for (const compose of [developmentCompose, productionCompose]) {
    const intake = serviceBlock(compose, "intake");
    assert.doesNotMatch(intake, /env_file:/u);
    assert.match(intake, /BIELOS_INTAKE_ENABLED:\s*\$\{BIELOS_INTAKE_ENABLED:-false\}/u);
    assert.match(intake, /BIELOS_INTAKE_DATABASE_URL:/u);
    assert.doesNotMatch(intake, /(?:^|\n)\s+DATABASE_URL:/u);
  }
});

test("Production email worker has no published host port", () => {
  const worker = serviceBlock(productionCompose, "email-worker");
  assert.doesNotMatch(worker, /env_file:/u);
  assert.match(worker, /command:\s*npm run email:worker/u);
  assert.doesNotMatch(worker, /ports:/u);
  assert.match(worker, /DATABASE_URL:\s*\$\{DATABASE_URL:\?/u);
  assert.doesNotMatch(worker, /BIELOS_INTAKE_DATABASE_URL:/u);
});

test("Production long-running services keep recovery policy and private boundaries", () => {
  for (const service of [
    "public-site",
    "hub",
    "intake",
    "session-cleanup",
    "email-worker",
    "postgres"
  ]) {
    assert.match(
      serviceBlock(productionCompose, service),
      /restart:\s*unless-stopped/u,
      `${service} must restart unless stopped`
    );
  }

  const intake = serviceBlock(productionCompose, "intake");
  assert.doesNotMatch(intake, /ports:/u);
  assert.match(intake, /BIELOS_INTAKE_ENABLED:\s*\$\{BIELOS_INTAKE_ENABLED:-false\}/u);

  const hub = serviceBlock(productionCompose, "hub");
  assert.match(hub, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*"true"/u);
  assert.match(hub, /DATABASE_URL:\s*\$\{DATABASE_URL:\?/u);
});
