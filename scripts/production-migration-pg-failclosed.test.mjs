import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Run with VIRKI_V01_PG_BIN_DIR set to an independently owned PostgreSQL
// 18 bin directory. No Docker, production host, shared daemon or TCP listener.
const pgBin = process.env.VIRKI_V01_PG_BIN_DIR;
const runnable = process.platform === "linux" && Boolean(pgBin && existsSync(path.join(pgBin, "initdb")));
const required = process.env.VIRKI_V01_PG_REQUIRED === "1";
const source = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
const rootSource = fileURLToPath(new URL("../", import.meta.url));
const slice = (start, end) => {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first + start.length);
  assert.ok(first >= 0 && last > first, `production function extraction missing ${start}`);
  return source.slice(first, last);
};
const snapshotCode = slice("identity_snapshot_sql=", "wait_for_clone() {");
const guardCode = slice("assert_backup_verified() {", "# This bridge accepts only");
const applyCode = slice("apply_production_migrations() {", "assert_no_maintenance() {");
const resumeCode = slice("assert_no_maintenance() {", "install_source() {");
const revision = "e".repeat(40);
const corruptionSql = Object.fromEntries(Object.entries({
  counts: `UPDATE "User" SET "role"='ADMIN' WHERE "id"='user-v01'`,
  payload: `UPDATE "EmailOutboxMessage" SET "payload"='{"ciphertext":"altered-fixture"}'::jsonb WHERE "id"='recover-v01'`,
  attemptCount: `UPDATE "EmailOutboxMessage" SET "attemptCount"=7 WHERE "id"='recover-v01'`,
  deliveryError: `UPDATE "EmailDeliveryAttempt" SET "errorCode"='altered-error' WHERE "id"='attempt-v01'`
}).map(([name, sql]) => [name, Buffer.from(sql).toString("base64")]));

function command(executable, args, env, input) {
  const child = spawnSync(executable, args, { env, input, encoding: "utf8", timeout: 90_000 });
  if (child.error) throw child.error;
  assert.equal(child.status, 0, `${executable} ${args[0] ?? ""}: ${child.stderr.slice(-1800)}`);
  return child.stdout.trim();
}

test("V01 physically corrupts PREPARED PostgreSQL state, blocks resume on restart, and proves independent restored invariants", {
  skip: !required && !runnable ? "Opt-in physical PostgreSQL 18 lab: set VIRKI_V01_PG_BIN_DIR and VIRKI_V01_PG_REQUIRED=1" : false
}, () => {
  assert.ok(runnable, "Physical V01 acceptance requires Linux and VIRKI_V01_PG_BIN_DIR pointing to a PostgreSQL 18 user-space installation.");
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-v01-pg-failclosed-"));
  chmodSync(directory, 0o700);
  const data = path.join(directory, "data");
  const socket = path.join(directory, "socket");
  const backups = path.join(directory, "backups");
  const log = path.join(directory, "postgres.log");
  const backupName = "virki-20261025-123456-abcdef.dump";
  const backup = path.join(backups, backupName);
  const guard = path.join(directory, ".virki-migration-integrity-guard");
  const maintenance = path.join(directory, ".virki-maintenance");
  const routeLog = path.join(directory, "routed-services.log");
  mkdirSync(socket, { mode: 0o700 });
  mkdirSync(backups, { mode: 0o700 });
  // A private Unix socket directory prevents collisions with other lab PGs.
  // TCP is explicitly disabled; no outside process can reach the database.
  const env = {
    ...process.env,
    PATH: `${pgBin}:${process.env.PATH}`,
    PGHOST: socket,
    PGPORT: "55479",
    PGUSER: "virki_v01_lab",
    PGDATABASE: "virki_v01",
    VIRKI_V01_ROOT: directory,
    VIRKI_V01_REVISION: revision
  };
  let started = false;
  const pg = (tool, args, input, overrides = {}) => command(tool, args, { ...env, ...overrides }, input);
  const sql = (statement, database = "virki_v01") => pg("psql", ["--no-psqlrc", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", database], statement);
  const bash = (body, database = "virki_v01", extras = {}) => spawnSync("bash", ["-c", `
set -Eeuo pipefail
root="$VIRKI_V01_ROOT"
revision="$VIRKI_V01_REVISION"
source_dir="$VIRKI_V01_SOURCE"
backup_dir="$root/backups"
verification_path="$root/.virki-migration-verification"
migration_guard_path="$root/.virki-migration-integrity-guard"
maintenance_path="$root/.virki-maintenance"
fail() { printf '%s\\n' "$1" >&2; exit 77; }
database_query() { psql --no-psqlrc -X -At -v ON_ERROR_STOP=1 -d "$PGDATABASE" <<< "$1"; }
${snapshotCode}
${guardCode}
${applyCode}
${resumeCode}
# Only the Docker/health orchestration is emulated. For the actual production
# apply_production_migrations, corrupt committed rows at the exact boundary
# AFTER write_migration_guard PREPARED and before migration verification.
# SQL reads, fingerprint comparison, checkpoint durability and admissions above
# are unchanged and execute against physical PostgreSQL.
application_services=(hub)
compose() {
  printf '%s\\n' "$*" >> "$root/routed-services.log"
  if [[ "$*" == 'up --detach --force-recreate postgres' ]]; then
    read_migration_guard
    [[ "$migration_guard_phase" == PREPARED ]] || fail 'Corruption injected without a durable PREPARED checkpoint.'
    case "\${VIRKI_V01_CORRUPTION:-}" in
      counts) database_query "$(printf %s '${corruptionSql.counts}' | base64 -d)" >/dev/null || return 1 ;;
      payload) database_query "$(printf %s '${corruptionSql.payload}' | base64 -d)" >/dev/null || return 1 ;;
      attemptCount) database_query "$(printf %s '${corruptionSql.attemptCount}' | base64 -d)" >/dev/null || return 1 ;;
      deliveryError) database_query "$(printf %s '${corruptionSql.deliveryError}' | base64 -d)" >/dev/null || return 1 ;;
      *) : ;;
    esac
  fi
  return 0
}
assert_tunnel_stopped() { :; }
normalize_migration_history() { :; }
run_migration_status() { :; }
verify_migration_schema() { :; }
verify_first_install_role_contract() { :; }
activate_source() { :; }
assert_revisions() { :; }
assert_loopback_ports() { :; }
assert_health() { :; }
${body}
`], { env: { ...env, PGDATABASE: database, VIRKI_V01_SOURCE: rootSource, ...extras }, encoding: "utf8", timeout: 30_000 });
  const ensureDenied = (body, expected) => {
    const before = existsSync(routeLog) ? readFileSync(routeLog, "utf8") : "";
    const result = bash(body);
    assert.equal(result.status, 77, `unexpected resume result for ${body}: ${result.stderr}`);
    assert.match(result.stderr, expected);
    assert.match(readFileSync(guard, "utf8"), /^phase=PREPARED$/mu);
    assert.ok(existsSync(maintenance), "denied resume must preserve maintenance");
    const actions = existsSync(routeLog) ? readFileSync(routeLog, "utf8").slice(before.length) : "";
    assert.doesNotMatch(actions, /^up /mu, "a denied resume cannot start any services");
  };
  try {
    pg("initdb", ["-D", data, "--auth-local=trust", "--auth-host=scram-sha-256", "-U", "virki_v01_lab", "--no-instructions"]);
    pg("pg_ctl", ["-D", data, "-o", `-c listen_addresses= -c port=${env.PGPORT} -c unix_socket_directories=${socket}`, "-l", log, "-w", "start"]);
    started = true;
    pg("createdb", ["virki_v01"]);
    const serverVersion = Number(sql("SHOW server_version_num"));
    assert.ok(serverVersion >= 180000 && serverVersion < 190000, `this physical acceptance test requires PostgreSQL 18; observed ${serverVersion}`);
    // Real migration prerequisites: the audit-migration SQL deliberately
    // fails closed without these narrowly scoped role names.
    sql("CREATE ROLE virki_audit_maintenance; CREATE ROLE virki_migrator; CREATE ROLE virki_runtime;");
    const migrations = path.join(rootSource, "packages", "database", "prisma", "migrations");
    for (const name of [
      "0_init", "20261001000000_security_polish", "20261006120000_audit_log_role_boundaries",
      "20261006130000_email_outbox_processing_lease", "20261014120000_account_invitation_email_kind",
      "20261017120000_audit_actor_immutable", "20261017150000_structured_audit_envelope",
      "20261017160000_recovery_request_purpose", "20261019120000_runtime_audit_write_boundary",
      "20261020120000_elevation_credential_key_version"
    ]) pg("psql", ["--no-psqlrc", "-X", "-v", "ON_ERROR_STOP=1", "-d", "virki_v01", "-f", path.join(migrations, name, "migration.sql")]);

    sql(`INSERT INTO "User" ("id", "email", "role", "updatedAt") VALUES
      ('admin-v01', 'admin-v01@example.invalid', 'ADMIN', NOW()),
      ('user-v01', 'user-v01@example.invalid', 'USER', NOW());
      INSERT INTO "EmailOutboxMessage" ("id", "idempotencyKey", "kind", "recipientEmail", "locale", "payload", "updatedAt")
      VALUES ('recover-v01', 'account-recovery-v01', 'ACCOUNT_RECOVERY', 'user-v01@example.invalid', 'pt-BR', '{"ciphertext":"opaque-test-only"}'::jsonb, NOW());
      INSERT INTO "EmailDeliveryAttempt" ("id", "messageId", "attempt", "status", "errorCode")
      VALUES ('attempt-v01', 'recover-v01', 1, 'FAILED', 'synthetic-error');`);
    const initial = bash("identity_snapshot; recovery_snapshot '' after_migrations");
    assert.equal(initial.status, 0, initial.stderr);
    const [identity, digest] = initial.stdout.trim().split(/\r?\n/u);
    assert.equal(identity, "1|1|2");
    assert.match(digest, /^[a-f0-9]{64}$/u);

    pg("pg_dump", ["-Fc", "-d", "virki_v01", "-f", backup]);
    const backupSha = createHash("sha256").update(readFileSync(backup)).digest("hex");
    chmodSync(backup, 0o600);
    writeFileSync(path.join(directory, ".virki-migration-verification"),
      `revision=${revision}\nbackup_name=${backupName}\nbackup_sha256=${backupSha}\nverified_at=${new Date().toISOString()}\n`, { mode: 0o600 });
    writeFileSync(maintenance, `revision=${revision}\n`, { mode: 0o600 });
    // Call the ACTUAL production migration function for each distinct attack.
    // The only substitute is Docker orchestration: the Compose PG-restart
    // boundary mutates real committed rows after production writes PREPARED.
    for (const [corruption, expected] of [
      ["counts", /Production migration changed ADMIN or USER counts/u],
      ["payload", /Production migration changed encrypted recovery outbox/u],
      ["attemptCount", /Production migration changed encrypted recovery outbox/u],
      ["deliveryError", /Production migration changed encrypted recovery outbox/u]
    ]) {
      if (existsSync(guard)) {
        // Only laboratory fixture state is reset; never a production path.
        pg("pg_restore", ["--exit-on-error", "--clean", "--if-exists", "--no-owner", "--no-privileges", "-d", "virki_v01", backup]);
        rmSync(guard);
      }
      writeFileSync(routeLog, "", { mode: 0o600 });
      const attempted = bash("apply_production_migrations", "virki_v01", { VIRKI_V01_CORRUPTION: corruption });
      assert.equal(attempted.status, 77, `${corruption} unexpectedly passed migration: ${attempted.stderr}`);
      assert.match(attempted.stderr, expected, `${corruption} did not reach the actual post-migration integrity comparison`);
      assert.match(readFileSync(guard, "utf8"), /^phase=PREPARED$/mu, `${corruption} must preserve PREPARED`);
      assert.match(readFileSync(routeLog, "utf8"), /^up --detach --force-recreate postgres$/mu, "actual migration entered its guarded PG restart boundary");
      const current = bash("identity_snapshot; recovery_snapshot '' after_migrations");
      assert.equal(current.status, 0, current.stderr);
      const [newIdentity, newRecovery] = current.stdout.trim().split(/\r?\n/u);
      if (corruption === "counts") assert.notEqual(newIdentity, identity);
      else {
        assert.equal(newIdentity, identity, "outbox corruption must not alter account counts");
        assert.notEqual(newRecovery, digest, `${corruption} must independently change the recovery fingerprint`);
      }
      ensureDenied("resume_services", /checkpoint unverified/u);
      ensureDenied("assert_migration_guard_renewable", /Unverified migration/u);
      if (corruption === "counts") {
        pg("pg_ctl", ["-D", data, "-m", "fast", "-w", "stop"]);
        pg("pg_ctl", ["-D", data, "-o", `-c listen_addresses= -c port=${env.PGPORT} -c unix_socket_directories=${socket}`, "-l", log, "-w", "start"]);
        assert.equal(bash("identity_snapshot").stdout.trim(), newIdentity, "mutated database state survives physical PostgreSQL restart");
        ensureDenied("resume_services", /checkpoint unverified/u);
      }
    }

    // A PREPARED orphan after crash has no automatic recovery bridge.
    rmSync(maintenance);
    const orphan = bash("recover_interrupted_verified_resume");
    assert.equal(orphan.status, 77);
    assert.match(orphan.stderr, /Orphaned unverified migration guard/u);
    assert.equal(existsSync(maintenance), false, "never manufacture a maintenance marker from PREPARED");
    writeFileSync(maintenance, `revision=${revision}\n`, { mode: 0o600 });

    // Physical, independent restore/reconciliation proof: a fresh database
    // recovers the original counts and encrypted outbox/attempt digest. This
    // deliberately DOES NOT delete or promote the live PREPARED checkpoint.
    pg("createdb", ["virki_v01_restored"]);
    pg("pg_restore", ["--exit-on-error", "--no-owner", "--no-privileges", "-d", "virki_v01_restored", backup]);
    const restored = bash("identity_snapshot; recovery_snapshot '' after_migrations", "virki_v01_restored");
    assert.equal(restored.status, 0, restored.stderr);
    assert.deepEqual(restored.stdout.trim().split(/\r?\n/u), [identity, digest]);
    const live = bash("identity_snapshot; recovery_snapshot '' after_migrations");
    assert.notDeepEqual(live.stdout.trim().split(/\r?\n/u), [identity, digest]);
    ensureDenied("resume_services", /checkpoint unverified/u);
    assert.match(readFileSync(guard, "utf8"), /^phase=PREPARED$/mu);

    // Reconcile the disposable live database only AFTER verifying the
    // independent restore. In real operations this also requires separately
    // authorized incident review; these calls exercise private fixture state.
    pg("pg_restore", ["--exit-on-error", "--clean", "--if-exists", "--no-owner", "--no-privileges", "-d", "virki_v01", backup]);
    const reconciled = bash("identity_snapshot; recovery_snapshot '' after_migrations");
    assert.equal(reconciled.status, 0, reconciled.stderr);
    assert.deepEqual(reconciled.stdout.trim().split(/\r?\n/u), [identity, digest]);
    ensureDenied("resume_services", /checkpoint unverified/u, "reconciliation alone never clears PREPARED");
    // An independent, explicitly reviewed FIXTURE reset is the only permitted
    // precondition for a clean successful migration attempt in this lab.
    // The product's actual migration routine must produce VERIFIED itself.
    rmSync(guard);
    const clean = bash("apply_production_migrations");
    assert.equal(clean.status, 0, `clean physical migration should verify: ${clean.stderr}`);
    assert.match(readFileSync(guard, "utf8"), /^phase=VERIFIED$/mu);
    assert.equal(bash("assert_migration_guard_verified").status, 0, "production migration itself verifies matching physical restored baseline");

    // Even a VERIFIED marker may not resume if the live state changes again.
    sql(`UPDATE "EmailOutboxMessage" SET "attemptCount"=5 WHERE "id"='recover-v01'`);
    const beforeFinalResume = readFileSync(routeLog, "utf8");
    const denied = bash("resume_services");
    assert.equal(denied.status, 77);
    assert.match(denied.stderr, /Migration integrity invariants changed/u);
    assert.match(readFileSync(guard, "utf8"), /^phase=VERIFIED$/mu);
    assert.ok(existsSync(maintenance));
    assert.doesNotMatch(readFileSync(routeLog, "utf8").slice(beforeFinalResume.length), /^up /mu);
  } finally {
    if (started) {
      const result = spawnSync("pg_ctl", ["-D", data, "-m", "fast", "-w", "stop"], { env, encoding: "utf8", timeout: 30_000 });
      assert.equal(result.status, 0, `isolated PG shutdown failed: ${result.stderr}`);
    }
    rmSync(directory, { recursive: true, force: true });
  }
});
