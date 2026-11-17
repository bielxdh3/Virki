import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withPrivateMfaCredentialFile } from "./lib/staging-mfa-credential-file.mjs";
import {
  assertStagingMfaBootstrapEnvironment,
  assertStagingMfaRuntimeIdentity
} from "./lib/staging-mfa-bootstrap-guard.mjs";

const key = (digit) => digit.repeat(64);
function disposableDatabaseUrl({ hostname = "127.0.0.1", port = 55492, database = "stage_mfa_20261117", username = "virki_runtime", schema = "public" } = {}) {
  // Never keep a URL containing a password in source, even for fake fixtures.
  const url = new URL(`postgresql://${hostname}:${port}/${database}`);
  url.username = username;
  url.password = randomBytes(24).toString("hex");
  url.searchParams.set("schema", schema);
  return url.toString();
}
const safeEnvironment = () => ({
  NODE_ENV: "production",
  VIRKI_STAGING_MFA_BOOTSTRAP: "enabled",
  VIRKI_HUB_PERIMETER_MODE: "native",
  VIRKI_HUB_HOSTNAME: "hub-staging.biel.dev.br",
  VIRKI_HUB_URL: "https://hub-staging.biel.dev.br",
  VIRKI_PORTAL_HOSTNAME: "portal-staging.biel.dev.br",
  VIRKI_PORTAL_URL: "https://portal-staging.biel.dev.br",
  VIRKI_ADMIN_PASSKEYS_ENABLED: "false",
  VIRKI_PASSKEYS_ENABLED: "false",
  VIRKI_STAGING_MFA_TEST_EMAIL: "operator@owned-test.example",
  VIRKI_CSRF_SIGNING_KEY: key("a"),
  VIRKI_TOTP_ENCRYPTION_KEY: key("b"),
  VIRKI_AUDIT_HASH_SECRET: key("c"),
  VIRKI_RATE_LIMIT_HASH_SECRET: key("d"),
  VIRKI_EMAIL_OUTBOX_KEY: key("e"),
  DATABASE_URL: disposableDatabaseUrl()
});

const safeIdentity = {
  database: "stage_mfa_20261117",
  role: "virki_runtime",
  host: "127.0.0.1",
  port: 55492,
  owner: "virki_migrator",
  migratorPresent: true,
  runtimeCanCreate: false,
  migrationLedgerRestricted: true,
  schemaReady: true
};

test("staging-only context accepts an isolated native Hub and returns redacted target metadata", () => {
  assert.deepEqual(assertStagingMfaBootstrapEnvironment(safeEnvironment()), {
    database: "stage_mfa_20261117",
    hostname: "hub-staging.biel.dev.br",
    port: 55492,
    recipient: "operator@owned-test.example"
  });
});

test("staging-only context refuses production, Access, unsafe hosts and URL redirects", () => {
  const overrides = [
    { NODE_ENV: "development" },
    { VIRKI_STAGING_MFA_BOOTSTRAP: "" },
    { VIRKI_HUB_PERIMETER_MODE: "access" },
    { VIRKI_HUB_HOSTNAME: "hub.example.test", VIRKI_HUB_URL: "https://hub.example.test" },
    { VIRKI_HUB_URL: "http://hub-staging.biel.dev.br" },
    { VIRKI_HUB_URL: "https://hub-staging.evil.test" },
    { VIRKI_PORTAL_HOSTNAME: "hub-staging.biel.dev.br", VIRKI_PORTAL_URL: "https://hub-staging.biel.dev.br" },
    {
      VIRKI_HUB_HOSTNAME: "hub-staging.attacker-controlled.invalid",
      VIRKI_HUB_URL: "https://hub-staging.attacker-controlled.invalid",
      VIRKI_PORTAL_HOSTNAME: "portal-staging.attacker-controlled.invalid",
      VIRKI_PORTAL_URL: "https://portal-staging.attacker-controlled.invalid"
    },
    { VIRKI_ADMIN_PASSKEYS_ENABLED: "true" },
    { VIRKI_STAGING_PASSKEY_RP_ENABLED: "true" },
    { DATABASE_URL: disposableDatabaseUrl({ hostname: "postgres", port: 5432, database: "virki" }) },
    { DATABASE_URL: disposableDatabaseUrl({ database: "virki" }) },
    { DATABASE_URL: disposableDatabaseUrl({ username: "postgres" }) },
    { DATABASE_URL: disposableDatabaseUrl({ schema: "other" }) },
    { MIGRATION_DATABASE_URL: disposableDatabaseUrl({ username: "virki_migrator" }) },
    { VIRKI_STAGING_MFA_TEST_EMAIL: "" },
    { VIRKI_AUDIT_HASH_SECRET: key("a") }
  ];
  for (const changed of overrides) {
    assert.throws(() => assertStagingMfaBootstrapEnvironment({ ...safeEnvironment(), ...changed }), /STAGING_MFA_/u, JSON.stringify(Object.keys(changed)));
  }
});

test("staging runtime identity requires distinct migrator owner and no schema creation by runtime", () => {
  const target = assertStagingMfaBootstrapEnvironment(safeEnvironment());
  assert.doesNotThrow(() => assertStagingMfaRuntimeIdentity(safeIdentity, target));
  for (const changed of [
    { database: "virki" },
    { role: "postgres" },
    { host: null },
    { host: "10.0.0.3" },
    { port: 5432 },
    { owner: "virki_runtime" },
    { migratorPresent: false },
    { runtimeCanCreate: true },
    { migrationLedgerRestricted: false },
    { schemaReady: false }
  ]) {
    assert.throws(() => assertStagingMfaRuntimeIdentity({ ...safeIdentity, ...changed }, target), /STAGING_MFA_/u);
  }
});

test("CLI preserves the production bootstrap guard and never accepts passwords from argv", () => {
  const production = readFileSync(new URL("../packages/auth/src/bootstrap-first-admin.ts", import.meta.url), "utf8");
  const cli = readFileSync(new URL("./staging-mfa-bootstrap.mjs", import.meta.url), "utf8");
  assert.match(production, /assertProductionBootstrapContext\(process\.env\)/u);
  assert.match(cli, /assertStagingMfaBootstrapEnvironment\(process\.env\)/u);
  assert.match(cli, /bootstrapFirstAdmin/u);
  assert.match(cli, /process\.stdin\.isTTY/u);
  assert.doesNotMatch(cli, /process\.argv\[[1-9]\]/u);
  assert.doesNotMatch(cli, /console\.log\([^)]*(password|secret|DATABASE_URL)/iu);
});

test("unattended CLI fails before any database import or mutation and prints no secret", () => {
  const env = safeEnvironment();
  const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/staging-mfa-bootstrap.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, ...env },
    encoding: "utf8"
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /STAGING_MFA_BOOTSTRAP_NOT_COMPLETED/u);
  assert.equal((result.stdout + result.stderr).includes(new URL(env.DATABASE_URL).password), false);
  assert.doesNotMatch(result.stdout + result.stderr, /operator@owned-test\.example|postgresql:\/\//u);
});

test("staging credential creation never deletes an existing file owned by a concurrent bootstrap", async () => {
  const dir = mkdtempSync(join(tmpdir(), "virki-mfa-credential-"));
  const file = join(dir, "test-credential.txt");
  try {
    chmodSync(dir, 0o700);
    writeFileSync(file, "credential-from-first-bootstrap", { mode: 0o600 });
    await assert.rejects(withPrivateMfaCredentialFile(file, "other credential", async () => {}));
    assert.equal(readFileSync(file, "utf8"), "credential-from-first-bootstrap");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("staging credential remains recoverable if database outcome is ambiguous", async () => {
  const dir = mkdtempSync(join(tmpdir(), "virki-mfa-credential-"));
  const file = join(dir, "test-credential.txt");
  try {
    chmodSync(dir, 0o700);
    await assert.rejects(withPrivateMfaCredentialFile(file, "retain-if-commit-ack-lost", async () => {
      throw new Error("simulated-post-commit-ack-loss");
    }));
    assert.equal(readFileSync(file, "utf8"), "retain-if-commit-ack-lost");
    assert.equal(statSync(file).mode & 0o077, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("successful credential preparation retains an owner-only file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "virki-mfa-credential-"));
  const file = join(dir, "test-credential.txt");
  try {
    chmodSync(dir, 0o700);
    await withPrivateMfaCredentialFile(file, "created-only-in-test", async () => {});
    assert.equal(readFileSync(file, "utf8"), "created-only-in-test");
    assert.equal(statSync(file).mode & 0o077, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
