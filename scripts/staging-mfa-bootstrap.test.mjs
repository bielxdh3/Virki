import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { withPrivateMfaCredentialFile } from "./lib/staging-mfa-credential-file.mjs";
import {
  assertStagingMfaBootstrapEnvironment,
  assertStagingMfaRuntimeIdentity,
  isStagingDirectoryOutsideRepository,
  stagingCredentialSecurityRoot,
  isNativeLinuxCredentialFilesystem
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
  VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST: "operator@owned-test.example",
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

test("operator preflight binds the staging worker inbox to the disposable ADMIN inbox before Docker", () => {
  const runbook = readFileSync(new URL("../docs/security/pr118-staging-operator-runbook-20261114.md", import.meta.url), "utf8");
  const guard = runbook.indexOf('[[ "$VIRKI_STAGING_MFA_TEST_EMAIL" == "$VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST"');
  const docker = runbook.indexOf("command -v docker >/dev/null");
  assert.ok(guard >= 0 && docker > guard, "the operator must reject a mismatched mailbox before contacting Docker");
  assert.match(runbook, /owner-approved canonical mailbox/u);
});

test("credential path guard rejects deceptive dot-dot-prefixed names inside checkout", () => {
  const repo = resolve("/var/virki/checkout");
  assert.equal(isStagingDirectoryOutsideRepository(repo, repo), false);
  assert.equal(isStagingDirectoryOutsideRepository(repo, join(repo, "..credentials")), false);
  assert.equal(isStagingDirectoryOutsideRepository(repo, join(repo, "private", "..credentials")), false);
  assert.equal(isStagingDirectoryOutsideRepository(repo, resolve(repo, "../other-owner-private")), true);
  const worktree = join(repo, ".worktrees", "pr130");
  assert.equal(stagingCredentialSecurityRoot(worktree), repo);
  assert.equal(isStagingDirectoryOutsideRepository(stagingCredentialSecurityRoot(worktree),
    join(repo, "..credentials")), false, "sibling of the worktree must not be inside the main repository");
  assert.equal(isStagingDirectoryOutsideRepository(stagingCredentialSecurityRoot(worktree),
    resolve(repo, "../outside-both-repositories")), true);
});

test("credential repository guard canonicalizes worktree symlink aliases", () => {
  const disposable = mkdtempSync(join(tmpdir(), "virki-mfa-repo-alias-"));
  try {
    const mainRepo = join(disposable, "repo");
    mkdirSync(join(mainRepo, ".worktrees", "pr130"), { recursive: true });
    symlinkSync(mainRepo, join(disposable, "repo-alias"), "dir");
    const canonicalWorktree = realpathSync(join(disposable, "repo-alias", ".worktrees", "pr130"));
    const securityRoot = stagingCredentialSecurityRoot(canonicalWorktree);
    assert.equal(securityRoot, mainRepo);
    assert.equal(isStagingDirectoryOutsideRepository(securityRoot, join(mainRepo, "..credentials")), false);
    assert.equal(isStagingDirectoryOutsideRepository(securityRoot, join(disposable, "approved-private")), true);
  } finally {
    rmSync(disposable, { recursive: true, force: true });
  }
});

test("credential filesystem guard rejects DrvFs/NTFS and other non-native mounts", () => {
  for (const native of [0xEF53, 0x58465342, 0x9123683E]) {
    assert.equal(isNativeLinuxCredentialFilesystem(native), true);
  }
  for (const unsupported of [0x794C7630, 0x65735546, 0x01021994, 0, null]) {
    assert.equal(isNativeLinuxCredentialFilesystem(unsupported), false);
  }
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
    { VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST: "" },
    { VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST: "attacker@owned-test.example" },
    { VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST: "operator@owned-test.example,attacker@owned-test.example" },
    { VIRKI_STAGING_EMAIL_RECIPIENT_ALLOWLIST: " Operator@owned-test.example" },
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
  assert.match(cli, /process\.versions\.node\.split/u);
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
