import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const productionSource = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
const start = productionSource.indexOf("assert_backup_verified() {");
const end = productionSource.indexOf("# This bridge accepts only", start);
assert.ok(start > 0 && end > start, "actual Bash migration checkpoint functions are available");
const realGuardFunctions = productionSource.slice(start, end);
const revision = "a".repeat(40);
const recoveryDigest = "b".repeat(64);
const identity = "1|2|3";

function createFixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-integrity-guard-"));
  chmodSync(root, 0o700);
  mkdirSync(path.join(root, "backups"), { mode: 0o700 });
  const backupName = "virki-20261024-123456-abcdef.dump";
  const backupPath = path.join(root, "backups", backupName);
  const backup = "isolated fake backup used only to exercise checkpoint metadata";
  writeFileSync(backupPath, backup, { mode: 0o600 });
  const digest = createHash("sha256").update(backup).digest("hex");
  writeFileSync(path.join(root, ".virki-migration-verification"), `revision=${revision}\nbackup_name=${backupName}\nbackup_sha256=${digest}\nverified_at=${new Date().toISOString()}\n`, { mode: 0o600 });
  return { root, backupPath, markerPath: path.join(root, ".virki-migration-integrity-guard") };
}

function run(root, command, { identityOverride = identity, recoveryOverride = recoveryDigest } = {}) {
  return spawnSync("bash", ["-c", `
set -Eeuo pipefail
umask 077
root="$VIRKI_GUARD_TEST_ROOT"
revision='${revision}'
backup_dir="$root/backups"
verification_path="$root/.virki-migration-verification"
migration_guard_path="$root/.virki-migration-integrity-guard"
maintenance_path="$root/.virki-maintenance"
fail() { printf '%s\\n' "$1" >&2; exit 77; }
${realGuardFunctions}
identity_snapshot() { printf '%s\\n' "$VIRKI_GUARD_TEST_IDENTITY"; }
recovery_snapshot() { printf '%s\\n' "$VIRKI_GUARD_TEST_RECOVERY"; }
${command}
`], { encoding: "utf8", env: { ...process.env, VIRKI_GUARD_TEST_ROOT: root, VIRKI_GUARD_TEST_IDENTITY: identityOverride, VIRKI_GUARD_TEST_RECOVERY: recoveryOverride } });
}

test("production migration checkpoint survives process restart and denies PREPARED maintenance-off", { skip: process.platform !== "linux" }, () => {
  const fixture = createFixture();
  try {
    assert.equal(run(fixture.root, `write_migration_guard PREPARED '${identity}' '${recoveryDigest}'`).status, 0);
    const before = run(fixture.root, "assert_migration_guard_verified");
    assert.notEqual(before.status, 0);
    assert.match(before.stderr, /checkpoint unverified/u);
    assert.equal(run(fixture.root, `write_migration_guard VERIFIED '${identity}' '${recoveryDigest}'`).status, 0);
    assert.equal(run(fixture.root, "assert_migration_guard_verified").status, 0);
    assert.notEqual(run(fixture.root, `write_migration_guard PREPARED '${identity}' '${recoveryDigest}'`).status, 0);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("production checkpoint rejects tampered backup or changed user/recovery snapshots", { skip: process.platform !== "linux" }, () => {
  const fixture = createFixture();
  try {
    assert.equal(run(fixture.root, `write_migration_guard PREPARED '${identity}' '${recoveryDigest}' && write_migration_guard VERIFIED '${identity}' '${recoveryDigest}'`).status, 0);
    assert.notEqual(run(fixture.root, "assert_migration_guard_verified", { identityOverride: "0|3|3" }).status, 0);
    assert.notEqual(run(fixture.root, "assert_migration_guard_verified", { recoveryOverride: "c".repeat(64) }).status, 0);
    writeFileSync(fixture.backupPath, "tampered fake backup");
    assert.notEqual(run(fixture.root, "assert_migration_guard_verified").status, 0);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("production checkpoint rejects symlinks, loose permissions, and malformed marker", { skip: process.platform !== "linux" }, () => {
  const fixture = createFixture();
  try {
    assert.equal(run(fixture.root, `write_migration_guard PREPARED '${identity}' '${recoveryDigest}'`).status, 0);
    chmodSync(fixture.markerPath, 0o644);
    assert.notEqual(run(fixture.root, "read_migration_guard").status, 0);
    chmodSync(fixture.markerPath, 0o600);
    writeFileSync(fixture.markerPath, "phase=VERIFIED\nrevision=broken\n");
    assert.notEqual(run(fixture.root, "assert_migration_guard_verified").status, 0);
    rmSync(fixture.markerPath);
    symlinkSync(fixture.backupPath, fixture.markerPath);
    assert.notEqual(run(fixture.root, "assert_migration_guard_verified").status, 0);
    assert.notEqual(run(fixture.root, "assert_migration_guard_absent").status, 0);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("a VERIFIED checkpoint renews an expired backup while preserving original custody", { skip: process.platform !== "linux" }, () => {
  const fixture = createFixture();
  try {
    assert.equal(run(fixture.root, `write_migration_guard PREPARED '${identity}' '${recoveryDigest}' && write_migration_guard VERIFIED '${identity}' '${recoveryDigest}'`).status, 0);
    const initial = readFileSync(fixture.markerPath, "utf8");
    assert.match(initial, /origin_backup_name=virki-20261024-123456-abcdef\.dump/u);
    const oldMarker = path.join(fixture.root, ".virki-migration-verification");
    const oldVerification = readFileSync(oldMarker, "utf8").replace(/verified_at=.*/u, "verified_at=2026-01-01T00:00:00Z");
    writeFileSync(oldMarker, oldVerification);
    assert.notEqual(run(fixture.root, "assert_backup_verified").status, 0, "old backup proof is outside the 24-hour window");
    assert.notEqual(run(fixture.root, "assert_migration_guard_renewable").status, 0, "renewal also requires the maintenance marker");
    writeFileSync(path.join(fixture.root, ".virki-maintenance"), "revision=" + revision + "\n", { mode: 0o600 });
    assert.equal(run(fixture.root, "assert_migration_guard_renewable").status, 0, "old original backup is still verifiable by digest");
    // Simulate loss of the verification marker during interrupted renewal;
    // the guarded original remains recoverable for another isolated restore.
    rmSync(oldMarker);
    assert.equal(run(fixture.root, "assert_migration_guard_renewable").status, 0);
    const renewedName = "virki-20261025-123456-fedcba.dump";
    const renewedPath = path.join(fixture.root, "backups", renewedName);
    const bytes = "new independently restored disposable backup";
    writeFileSync(renewedPath, bytes, { mode: 0o600 });
    const hash = createHash("sha256").update(bytes).digest("hex");
    writeFileSync(oldMarker, `revision=${revision}\nbackup_name=${renewedName}\nbackup_sha256=${hash}\nverified_at=${new Date().toISOString()}\n`, { mode: 0o600 });
    assert.equal(run(fixture.root, "rebind_verified_migration_guard").status, 0);
    assert.equal(run(fixture.root, "assert_migration_guard_verified").status, 0);
    const renewed = readFileSync(fixture.markerPath, "utf8");
    assert.match(renewed, /backup_name=virki-20261025-123456-fedcba\.dump/u);
    assert.match(renewed, /origin_backup_name=virki-20261024-123456-abcdef\.dump/u);
    rmSync(fixture.backupPath);
    assert.notEqual(run(fixture.root, "assert_migration_guard_verified").status, 0, "never lose custody of the original pre-migration backup");
    assert.notEqual(run(fixture.root, "assert_migration_guard_renewable").status, 0);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("a PREPARED checkpoint never permits backup renewal after a crash", { skip: process.platform !== "linux" }, () => {
  const fixture = createFixture();
  try {
    writeFileSync(path.join(fixture.root, ".virki-maintenance"), "revision=" + revision + "\n", { mode: 0o600 });
    assert.equal(run(fixture.root, `write_migration_guard PREPARED '${identity}' '${recoveryDigest}'`).status, 0);
    assert.notEqual(run(fixture.root, "assert_migration_guard_renewable").status, 0);
    assert.notEqual(run(fixture.root, "rebind_verified_migration_guard").status, 0);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("migration prepares durability checkpoint before the first live database mutation", () => {
  const block = productionSource.slice(productionSource.indexOf("apply_production_migrations() {"), productionSource.indexOf("assert_no_maintenance() {"));
  assert.ok(block.indexOf("write_migration_guard PREPARED") > 0);
  assert.ok(block.indexOf("write_migration_guard PREPARED") < block.indexOf("compose up --detach --force-recreate postgres"));
  assert.ok(block.indexOf("write_migration_guard VERIFIED") > block.indexOf("Production migration changed encrypted recovery outbox"));
  assert.match(productionSource, /assert_no_maintenance\(\) \{[\s\S]*?assert_migration_guard_absent/u);
  assert.match(productionSource, /resume_services\(\) \{[\s\S]*?assert_migration_guard_verified/u);
  const install = productionSource.slice(productionSource.indexOf("install_source() {"), productionSource.indexOf("cleanup_deploy_staging() {"));
  assert.ok(install.indexOf("assert_migration_guard_absent") >= 0 && install.indexOf("verify_source_archive") > install.indexOf("assert_migration_guard_absent"), "install-source and deploy must not replace the accepted revision during failed migration");
  const resume = productionSource.slice(productionSource.indexOf("resume_services() {"), productionSource.indexOf("install_source() {"));
  assert.ok(resume.indexOf('rm -- "$maintenance_path"') >= 0 && resume.indexOf('rm -- "$migration_guard_path"') > resume.indexOf('rm -- "$maintenance_path"'), "crashes during marker removal must leave the stronger integrity guard, not an unguarded maintenance flag");
  assert.ok(resume.indexOf('rm -- "$migration_guard_path"') < resume.indexOf("compose up --detach cloudflared"), "the public route must never start before durable removal of maintenance markers");
  assert.ok(resume.indexOf("assert_tunnel_stopped") >= 0 && resume.indexOf("assert_tunnel_stopped") < resume.indexOf("compose up --detach --force-recreate"), "the tunnel must be proven stopped before app recreation");
  const backupVerify = productionSource.slice(productionSource.indexOf("  backup-verify)"), productionSource.indexOf("  migration-status)"));
  assert.match(backupVerify, /assert_migration_guard_renewable[\s\S]*?create_verified_backup[\s\S]*?rebind_verified_migration_guard/u);
  const maintenance = productionSource.slice(productionSource.indexOf("maintenance_on() {"), productionSource.indexOf("stop_routed_services() {"));
  assert.ok(maintenance.indexOf("assert_tunnel_stopped") >= 0 && maintenance.indexOf("assert_tunnel_stopped") < maintenance.indexOf('mv -f -- "$maintenance_path.tmp.$$"'), "stop and confirm the public route before writing a persistent maintenance marker");
  assert.ok(maintenance.indexOf('compose stop "${application_services[@]}"') >= 0 && maintenance.indexOf('compose stop "${application_services[@]}"') < maintenance.indexOf('mv -f -- "$maintenance_path.tmp.$$"'), "stop application writers before maintenance marker publication");
  const backup = productionSource.slice(productionSource.indexOf("create_verified_backup() {"), productionSource.indexOf("run_first_install_recovery_clone_migrations() {"));
  assert.match(backup, /sync -f -- "\$backup_path" && sync -f -- "\$backup_dir"/u, "backup mount can be a separate filesystem from the production root");
  assert.match(backup, /sync -f -- "\$verification_path" && sync -f -- "\$root"/u, "verified backup marker must be committed durably");
  const dispatch = productionSource.slice(productionSource.indexOf("if [[ \"$state_changing_actions\""), productionSource.indexOf("if [[ \"$action\" == first-admin-rescue-prepare"));
  assert.match(dispatch, /assert_migration_guard_absent/u, "reject a pending guard before Docker image tags or accepted source are mutated");
});
