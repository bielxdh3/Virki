import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const productionCompose = readFileSync(path.join(repositoryRoot, "infra", "docker-compose.prod.yml"), "utf8");
const developmentCompose = readFileSync(path.join(repositoryRoot, "infra", "docker-compose.yml"), "utf8");
const cloudflareCompose = readFileSync(path.join(repositoryRoot, "infra", "docker-compose.cloudflare.yml"), "utf8");
const cloudflareTemplate = readFileSync(path.join(repositoryRoot, "infra", "cloudflare", "config.example.yml"), "utf8");
const environmentTemplate = readFileSync(path.join(repositoryRoot, ".env.example"), "utf8");
const databaseRoleSetup = readFileSync(path.join(repositoryRoot, "infra", "postgres-init", "10-virki-database-roles.sh"), "utf8");

function serviceBlock(compose, service) {
  compose = compose.replace(/\r\n/gu, "\n");
  const match = compose.match(new RegExp(`\\n  ${service}:\\n([\\s\\S]*?)(?=\\n  [a-z0-9-]+:\\n|\\nvolumes:|$)`, "u"));
  assert.ok(match, `Missing Compose service: ${service}`);
  return match[1];
}

function environmentKeys(block) {
  const match = block.match(/(?:^|\n) {4}environment:\n([\s\S]*?)(?=\n {4}[a-z][a-z0-9_-]*:\n|$)/u);
  assert.ok(match, "Missing Compose environment block");
  return [...match[1].matchAll(/^ {6}([A-Z][A-Z0-9_]*):/gmu)].map((entry) => entry[1]).sort();
}

test("production exposes only the public site and loopback application surfaces", () => {
  for (const service of ["public-site", "hub"]) {
    assert.match(serviceBlock(productionCompose, service), /127\.0\.0\.1:/u);
  }
  for (const service of ["oidc-issuer", "session-cleanup", "email-worker", "postgres", "migrate"]) {
    assert.doesNotMatch(serviceBlock(productionCompose, service), /ports:/u);
  }
  assert.doesNotMatch(productionCompose, /^\x20{2}intake:/mu);
  assert.doesNotMatch(productionCompose, /VIRKI_INTAKE|apps\/intake/iu);
});

test("hub keeps Cloudflare Access mandatory and OIDC secrets outside shared environment", () => {
  const hub = serviceBlock(productionCompose, "hub");
  const issuer = serviceBlock(productionCompose, "oidc-issuer");
  assert.match(hub, /VIRKI_PASSKEYS_ENABLED:\s*\$\{VIRKI_PASSKEYS_ENABLED:-false\}/u,
    "Production Hub must receive the explicitly enabled passkey rollout flag, defaulting to disabled");
  assert.match(hub, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*"true"/u);
  assert.match(hub, /CLOUDFLARE_ACCESS_AUDIENCE:\s*\$\{CLOUDFLARE_ACCESS_AUDIENCE:\?/u);
  assert.match(hub, /CLOUDFLARE_TEAM_DOMAIN:\s*\$\{CLOUDFLARE_TEAM_DOMAIN:\?/u);
  assert.match(hub, /path: \.\.\/\.env\.oidc-data/u);
  assert.match(hub, /required: true/u);
  assert.match(issuer, /path: \.\.\/\.env\.oidc(?:\s|$)/u);
  assert.match(issuer, /path: \.\.\/\.env\.oidc-data/u);
  assert.match(issuer, /required: true/u);
  assert.match(issuer, /VIRKI_RATE_LIMIT_HASH_SECRET:\s*\$\{VIRKI_RATE_LIMIT_HASH_SECRET:\?/u);
  assert.match(hub, /VIRKI_AUDIT_HASH_SECRET:\s*\$\{VIRKI_AUDIT_HASH_SECRET:\?/u);
  assert.match(hub, /VIRKI_CSRF_SIGNING_KEY:\s*\$\{VIRKI_CSRF_SIGNING_KEY:\?/u);
  assert.doesNotMatch(productionCompose, /VIRKI_OIDC_SIGNING_JWKS:\s*\$\{/u);
  assert.doesNotMatch(hub, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*\$\{/u);
});

test("production containers receive only their scoped secret files", () => {
  const hub = serviceBlock(productionCompose, "hub");
  const issuer = serviceBlock(productionCompose, "oidc-issuer");
  const bootstrap = serviceBlock(productionCompose, "first-admin-bootstrap");
  const tunnel = serviceBlock(cloudflareCompose, "cloudflared");
  const appServices = ["hub", "oidc-issuer", "migrate", "session-cleanup", "email-worker"]
    .map((service) => serviceBlock(productionCompose, service));

  assert.ok(appServices.every((block) => !/path:\s*\.\.\/\.env\s*$/mu.test(block)));
  assert.match(hub, /path: \.\.\/\.env\.oidc-data/u);
  assert.doesNotMatch(hub, /path: \.\.\/\.env\.oidc(?:\s|$)/u);
  assert.match(issuer, /path: \.\.\/\.env\.oidc(?:\s|$)/u);
  assert.match(issuer, /path: \.\.\/\.env\.oidc-data/u);
  assert.doesNotMatch(hub, /VIRKI_OIDC_SIGNING_JWKS|VIRKI_OIDC_COOKIE_KEY|VIRKI_EMAIL_SMTP_PASSWORD|CLOUDFLARE_TUNNEL_TOKEN/u);
  assert.doesNotMatch(issuer, /VIRKI_TOTP_ENCRYPTION_KEY|VIRKI_EMAIL_SMTP_PASSWORD|CLOUDFLARE_TUNNEL_TOKEN/u);
  assert.match(bootstrap, /profiles: \["bootstrap"\]/u);
  assert.doesNotMatch(bootstrap, /env_file:|CLOUDFLARE|VIRKI_OIDC|VIRKI_CSRF|VIRKI_TOTP|VIRKI_EMAIL|POSTGRES_PASSWORD|MIGRATION_DATABASE_URL/u);
  assert.deepEqual(environmentKeys(bootstrap), ["DATABASE_URL", "NODE_ENV", "VIRKI_AUDIT_HASH_SECRET", "VIRKI_FIRST_INSTALL_BOOTSTRAP"].sort());
  assert.match(bootstrap, /user: node:node/u);
  assert.match(bootstrap, /read_only: true/u);
  assert.match(bootstrap, /cap_drop: \[ALL\]/u);
  assert.match(bootstrap, /DATABASE_URL:\s*\$\{DATABASE_URL:\?/u);
  assert.match(bootstrap, /npm run bootstrap:first-admin --workspace @virki\/auth/u);
  assert.doesNotMatch(bootstrap, /depends_on:|ports:/u);
  assert.match(issuer, /VIRKI_RATE_LIMIT_HASH_SECRET/u);
  assert.match(hub, /VIRKI_AUDIT_HASH_SECRET/u);
  assert.match(hub, /VIRKI_CSRF_SIGNING_KEY/u);
  assert.match(tunnel, /TUNNEL_TOKEN:\s*\$\{CLOUDFLARE_TUNNEL_TOKEN/u);
});

test("development Hub and issuer receive only explicitly scoped environment variables", () => {
  const hub = serviceBlock(developmentCompose, "hub");
  const publicSite = serviceBlock(developmentCompose, "public-site");
  const issuer = serviceBlock(developmentCompose, "oidc-issuer");
  const postgres = serviceBlock(developmentCompose, "postgres");

  assert.match(hub, /VIRKI_PORTAL_URL: \$\{VIRKI_PORTAL_URL:-\}/u);
  assert.match(publicSite, /VIRKI_PORTAL_URL: \$\{VIRKI_PORTAL_URL:-\}/u);
  assert.doesNotMatch(`${hub}\n${publicSite}`, /VIRKI_PORTAL_URL: \$\{VIRKI_PORTAL_URL:-https:\/\/portal\.biel\.dev\.br\}/u);
  assert.doesNotMatch(hub, /env_file:/u);
  assert.doesNotMatch(issuer, /env_file:/u);
  assert.match(hub, /VIRKI_EMAIL_SMTP_PASSWORD:/u);
  assert.match(hub, /VIRKI_EMAIL_OUTBOX_KEY:/u);
  assert.match(issuer, /VIRKI_OIDC_SIGNING_JWKS:/u);
  assert.match(issuer, /VIRKI_RATE_LIMIT_HASH_SECRET:/u);
  assert.doesNotMatch(hub, /VIRKI_OIDC_SIGNING_JWKS|VIRKI_OIDC_COOKIE_KEY|CLOUDFLARE_TUNNEL_TOKEN/u);
  assert.doesNotMatch(issuer, /VIRKI_TOTP_ENCRYPTION_KEY|VIRKI_EMAIL_SMTP_PASSWORD|VIRKI_EMAIL_OUTBOX_KEY|CLOUDFLARE_TUNNEL_TOKEN/u);
  assert.doesNotMatch(`${publicSite}\n${postgres}`, /VIRKI_OIDC_ADAPTER_KEY(?:_PREVIOUS)?/u);
  assert.deepEqual(environmentKeys(hub), [
    "VIRKI_AUDIT_HASH_SECRET", "VIRKI_CSRF_SIGNING_KEY", "VIRKI_CSRF_SIGNING_KEY_PREVIOUS",
    "VIRKI_EMAIL_FROM", "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_EMAIL_REPLY_TO", "VIRKI_EMAIL_SMTP_HOST",
    "VIRKI_EMAIL_SMTP_PASSWORD", "VIRKI_EMAIL_SMTP_PORT", "VIRKI_EMAIL_SMTP_SECURE", "VIRKI_EMAIL_SMTP_USER",
    "VIRKI_EMAIL_TRANSPORT", "VIRKI_HUB_HOSTNAME", "VIRKI_HUB_URL", "VIRKI_OIDC_ADAPTER_KEY",
    "VIRKI_OIDC_ADAPTER_KEY_PREVIOUS",
    "VIRKI_OIDC_PROXY_URL", "VIRKI_PORTAL_HOSTNAME", "VIRKI_PORTAL_URL", "VIRKI_RATE_LIMIT_HASH_SECRET",
    "VIRKI_TOTP_ENCRYPTION_KEY", "CLOUDFLARE_ACCESS_JWT_REQUIRED", "DATABASE_URL", "NODE_ENV"
  ].sort());
  assert.deepEqual(environmentKeys(issuer), [
    "VIRKI_OIDC_ADAPTER_KEY", "VIRKI_OIDC_ADAPTER_KEY_PREVIOUS", "VIRKI_OIDC_COOKIE_KEY",
    "VIRKI_OIDC_ISSUER", "VIRKI_OIDC_SIGNING_JWKS",
    "VIRKI_RATE_LIMIT_HASH_SECRET", "DATABASE_URL", "NODE_ENV", "OIDC_ISSUER_PORT"
  ].sort());
});

test("production services use preloaded exact-revision images without remote builds or pulls", () => {
  for (const service of ["public-site", "hub", "oidc-issuer", "session-cleanup", "email-worker", "first-admin-bootstrap"]) {
    const block = serviceBlock(productionCompose, service);
    assert.match(block, /image:\s*\$\{VIRKI_PRODUCTION_IMAGE:\?/u);
    assert.match(block, /pull_policy:\s*never/u);
    assert.doesNotMatch(block, /build:/u);
  }
  const migrator = serviceBlock(productionCompose, "migrate");
  assert.match(migrator, /image:\s*\$\{VIRKI_MIGRATOR_IMAGE:\?/u);
  assert.match(migrator, /pull_policy:\s*never/u);
  assert.doesNotMatch(migrator, /build:/u);
});

test("portal host reaches the hub OIDC proxy and Cloudflare tunnel uses no www alias", () => {
  const hub = serviceBlock(productionCompose, "hub");
  assert.match(hub, /VIRKI_PORTAL_HOSTNAME:.*portal\.biel\.dev\.br/u);
  assert.match(serviceBlock(productionCompose, "public-site"), /VIRKI_PORTAL_URL: \$\{VIRKI_PORTAL_URL:-\}/u);
  assert.match(hub, /VIRKI_PORTAL_URL: \$\{VIRKI_PORTAL_URL:-\}/u);
  assert.doesNotMatch(productionCompose, /VIRKI_PORTAL_URL:\s*\$\{VIRKI_PORTAL_URL:-https:\/\/portal\.biel\.dev\.br\}/u);
  assert.match(cloudflareCompose, /- oidc-issuer/u);
  assert.match(cloudflareTemplate, /hostname: portal\.biel\.dev\.br\s+service: http:\/\/hub:3001/u);
  assert.doesNotMatch(cloudflareTemplate, /hostname: www\./u);
});

test("production Cloudflared tunnel uses the independently exercised least-privilege sandbox", () => {
  const tunnel = serviceBlock(cloudflareCompose, "cloudflared");
  assert.match(tunnel, /^ {4}user: "65532:65532"$/mu);
  assert.match(tunnel, /^ {4}read_only: true$/mu);
  assert.match(tunnel, /^ {4}cap_drop: \[ALL\]$/mu);
  assert.match(tunnel, /^ {4}security_opt: \[no-new-privileges:true\]$/mu);
  assert.doesNotMatch(tunnel, /^ {4}(?:privileged|network_mode|ports|volumes|devices|pid|ipc):/mu);
  assert.match(tunnel, /TUNNEL_TOKEN:\s*\$\{CLOUDFLARE_TUNNEL_TOKEN:\?/u);
  assert.match(tunnel, /command: tunnel --no-autoupdate run/u);
});

test("production workers and database retain restart policy without published ports", () => {
  for (const service of ["oidc-issuer", "session-cleanup", "email-worker", "postgres"]) {
    const block = serviceBlock(productionCompose, service);
    assert.match(block, /restart:\s*unless-stopped/u);
    assert.doesNotMatch(block, /ports:/u);
  }
  assert.match(serviceBlock(productionCompose, "postgres"), /virki_postgres_data:\/var\/lib\/postgresql\/data/u);
  assert.match(serviceBlock(productionCompose, "postgres"), /postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24/u);
  assert.match(serviceBlock(cloudflareCompose, "cloudflared"), /cloudflare\/cloudflared:2026\.9\.3@sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c/u);
  assert.match(readFileSync(path.join(repositoryRoot, "infra", "Dockerfile.prod"), "utf8"), /node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402/u);
});

test("runtime, migrator, and PostgreSQL bootstrap credentials stay separated", () => {
  const postgres = serviceBlock(productionCompose, "postgres");
  const developmentPostgres = serviceBlock(developmentCompose, "postgres");
  const migrator = serviceBlock(productionCompose, "migrate");
  const applicationServices = ["hub", "oidc-issuer", "session-cleanup", "email-worker"]
    .map((service) => serviceBlock(productionCompose, service));

  assert.match(postgres, /POSTGRES_USER:\s*\$\{POSTGRES_USER:-virki_bootstrap\}/u);
  assert.match(postgres, /VIRKI_RUNTIME_DB_PASSWORD:\s*\$\{VIRKI_RUNTIME_DB_PASSWORD:\?/u);
  assert.match(postgres, /VIRKI_MIGRATOR_DB_PASSWORD:\s*\$\{VIRKI_MIGRATOR_DB_PASSWORD:\?/u);
  assert.doesNotMatch(postgres, /VIRKI_LOCAL_MIGRATOR_CREATEDB/u);
  assert.match(developmentPostgres, /VIRKI_LOCAL_MIGRATOR_CREATEDB:\s*"true"/u);
  assert.match(databaseRoleSetup, /case "\$\{VIRKI_LOCAL_MIGRATOR_CREATEDB:-false\}" in\s+false\) ;;\s+true\)[\s\S]*?ALTER ROLE virki_migrator CREATEDB/u);
  assert.match(postgres, /\.\/postgres-init\/10-virki-database-roles\.sh:[^\n]*:ro/u);
  assert.match(postgres, /pg_isready -h 127\.0\.0\.1/u);
  assert.match(developmentPostgres, /pg_isready -h 127\.0\.0\.1/u);
  assert.match(migrator, /MIGRATION_DATABASE_URL:\s*\$\{MIGRATION_DATABASE_URL:\?/u);
  assert.doesNotMatch(migrator, /^\s+DATABASE_URL:/mu);
  assert.ok(applicationServices.every((block) => /DATABASE_URL:\s*\$\{DATABASE_URL:\?/u.test(block)));
  assert.ok(applicationServices.every((block) => !/MIGRATION_DATABASE_URL|POSTGRES_PASSWORD|VIRKI_RUNTIME_DB_PASSWORD|VIRKI_MIGRATOR_DB_PASSWORD/u.test(block)));
  assert.match(environmentTemplate, /^POSTGRES_USER=virki_bootstrap$/mu);
  assert.match(environmentTemplate, /^DATABASE_URL=postgresql:\/\/virki_runtime:/mu);
  assert.match(environmentTemplate, /^MIGRATION_DATABASE_URL=postgresql:\/\/virki_migrator:/mu);
  assert.match(environmentTemplate, /^VIRKI_RUNTIME_DB_PASSWORD=replace-with-64-hex-character-secret$/mu);
  assert.match(environmentTemplate, /^VIRKI_MIGRATOR_DB_PASSWORD=replace-with-a-different-64-hex-character-secret$/mu);
});

test("database CLI routes schema mutations through the migrator identity", () => {
  const databasePackage = JSON.parse(readFileSync(path.join(repositoryRoot, "packages", "database", "package.json"), "utf8"));
  const migrationRunner = readFileSync(path.join(repositoryRoot, "packages", "database", "scripts", "prisma-migrate.mjs"), "utf8");

  assert.match(databasePackage.scripts["prisma:migrate"], /scripts\/prisma-migrate\.mjs dev/u);
  assert.match(databasePackage.scripts["prisma:migrate:deploy"], /scripts\/prisma-migrate\.mjs deploy/u);
  assert.match(databasePackage.scripts["prisma:migrate:status"], /scripts\/prisma-migrate\.mjs status/u);
  assert.match(databasePackage.scripts["prisma:push"], /scripts\/prisma-migrate\.mjs push/u);
  assert.match(migrationRunner, /MIGRATION_DATABASE_URL must use the virki_migrator database role/u);
  assert.match(migrationRunner, /decodeURIComponent\(url\.username\) === "virki_migrator"/u);
  assert.match(migrationRunner, /env: \{ \.\.\.process\.env, DATABASE_URL: migrationUrl \}/u);
});

test("production application, maintenance, and migration services run non-root with a read-only root filesystem", () => {
  for (const service of ["public-site", "hub", "oidc-issuer", "migrate", "first-admin-bootstrap", "session-cleanup", "email-worker"]) {
    const block = serviceBlock(productionCompose, service);
    assert.match(block, /^\s+user:\s*node:node$/mu, service);
    assert.match(block, /^\s+read_only:\s*true$/mu, service);
    assert.match(block, /^\s+cap_drop:\s*\[ALL\]$/mu, service);
    assert.match(block, /^\s+security_opt:\s*\[no-new-privileges:true\]$/mu, service);
    assert.match(block, /\/tmp:rw,noexec,nosuid,nodev,size=64m/u, service);
  }
  assert.match(serviceBlock(productionCompose, "hub"), /\/app\/apps\/hub\/\.next\/cache:rw,noexec,nosuid,nodev,size=128m/u);
  assert.match(serviceBlock(productionCompose, "public-site"), /\/app\/apps\/public-site\/\.next\/cache:rw,noexec,nosuid,nodev,size=128m/u);
  const dockerfile = readFileSync(path.join(repositoryRoot, "infra", "Dockerfile.prod"), "utf8");
  assert.match(dockerfile, /FROM build AS migrator[\s\S]*?USER node:node[\s\S]*?CMD \["npm", "run", "prisma:migrate:deploy"\]/u);
  assert.match(dockerfile, /ENV HOME=\/tmp\/node-home[\s\S]*?USER node:node/u);
  const runtimeSmoke = readFileSync(path.join(repositoryRoot, "scripts", "production-runtime-smoke.mjs"), "utf8");
  const imageAssertion = readFileSync(path.join(repositoryRoot, "scripts", "production-image-assertion.mjs"), "utf8");
  const boundaryAssertion = readFileSync(path.join(repositoryRoot, "scripts", "lib", "production-boundary-assertion.mjs"), "utf8");
  assert.match(runtimeSmoke, /"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"/u);
  assert.match(runtimeSmoke, /assertSecurityHeaders\(publicResponse\.headers\)/u);
  assert.match(runtimeSmoke, /assertSecurityHeaders\(hubHealth\.headers, "strict-origin"\)/u);
  assert.match(runtimeSmoke, /assertSecurityHeaders\(response\.headers\)/u);
  assert.match(runtimeSmoke, /function assertSecurityHeaders\(headers, referrerPolicy = "no-referrer"\)/u);
  assert.match(imageAssertion, /import \{ assertion \} from "\.\/lib\/production-boundary-assertion\.mjs"/u);
  assert.match(boundaryAssertion, /runtimeUid !== 1000/u);
  assert.match(imageAssertion, /"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"/u);
});

test("oidc-issuer is reachable only on the internal Compose network", () => {
  for (const [name, compose] of [["production", productionCompose], ["development", developmentCompose]]) {
    const issuer = serviceBlock(compose, "oidc-issuer");
    assert.doesNotMatch(issuer, /^\s{4}ports:/mu, `${name} issuer must not publish ports`);
    assert.doesNotMatch(issuer, /^\s{4}(?:expose|network_mode|networks):/mu, `${name} issuer must stay on the default internal network`);
    assert.doesNotMatch(issuer, /VIRKI_OIDC_BIND_ADDRESS/u);
  }
  assert.match(productionCompose, /VIRKI_OIDC_PROXY_URL:\s*http:\/\/oidc-issuer:3003/u);
  assert.doesNotMatch(cloudflareCompose, /^\s{4}ports:/mu);
});
