#!/bin/sh
# Test-only, invoked solely by the no-network disposable PostgreSQL runner.
# All databases are created by the fixture in a private PostgreSQL cluster.
# Never accept a production DATABASE_URL, Docker socket, external PGHOST, or
# caller-supplied SQL. Every log and failure code deliberately excludes data.
set -eu

refuse() { printf '%s\n' "Disposable PostgreSQL recovery refused: $1" >&2; exit 70; }
case "${VIRKI_OFFLINE_PG_DISPOSABLE:-}" in 1) ;; *) refuse 'explicit fixture opt-in absent';; esac
test "$(id -u)" = 70 || refuse 'postgres uid required'
test "${PGHOST:-}" = /tmp || refuse 'private Unix socket required'
test "${PGPORT:-}" = 5432 || refuse 'private PostgreSQL port required'
test "${PGUSER:-}" = postgres || refuse 'isolated bootstrap role required'
test "${PGDATABASE:-}" = postgres || refuse 'isolated bootstrap database required'
test "${PGPASSWORD:-}" = '' || refuse 'external password rejected'
test "${PGHOSTADDR:-}" = '' || refuse 'TCP address rejected'
test "${DATABASE_URL:-}" = '' || refuse 'production database URL rejected'
test "${MIGRATION_DATABASE_URL:-}" = '' || refuse 'migration URL rejected'
test "${PGSERVICE:-}" = '' || refuse 'external PG service rejected'
test -d /tmp/virki-pg-recovery && test ! -L /tmp/virki-pg-recovery || refuse 'fixture root must already exist'
test "$(stat -c %u:%g:%a /tmp/virki-pg-recovery)" = '70:70:700' || refuse 'fixture root ownership mismatch'
test -r /workspace/scripts/fixtures/offline-pg-recovery/inventory.psql || refuse 'fixed audited inventory missing'

fixture=/tmp/virki-pg-recovery
backup="$fixture/virki.dump"
backup_digest="$fixture/virki.sha256"
control_db=virki_control
source_db=virki_source
restore_db=virki_restore
rollback_db=virki_rollback
inventory_sql=/workspace/scripts/fixtures/offline-pg-recovery/inventory.psql

sql() {
  # All commands are static in this trusted regression script. Never echo SQL
  # containing data or return psql stderr to the caller.
  psql -X -q -A -t -v ON_ERROR_STOP=1 -d "$1" -c "$2" 2>"$fixture/pg-error"
}
psql_file() {
  psql -X -q -v ON_ERROR_STOP=1 -d "$1" -f "$2" > /dev/null 2>"$fixture/pg-error"
}
control() { sql "$control_db" "$1"; }
last_phase() { control "SELECT phase FROM recovery_attempt WHERE id=1"; }
fingerprint() {
  psql -X -q -A -t -v ON_ERROR_STOP=1 -d "$1" -f "$inventory_sql" 2>"$fixture/pg-error"
}
require_equal() {
  test "$1" = "$2" || refuse "$3"
}
verify_backup() {
  test -f "$backup" && test ! -L "$backup" || refuse 'backup missing or aliased'
  test "$(stat -c %u:%g:%a "$backup")" = '70:70:600' || refuse 'backup owner/mode changed'
  test "$(sha256sum "$backup" | cut -d ' ' -f 1)" = "$(cat "$backup_digest")" ||
    refuse 'backup digest changed'
  test "$(head -c 5 "$backup")" = PGDMP || refuse 'not a PostgreSQL custom archive'
  pg_restore --list "$backup" > /dev/null 2>"$fixture/pg-error" ||
    refuse 'PostgreSQL archive parse failed'
}
record() {
  control "UPDATE recovery_attempt SET phase='$1', updated_at=clock_timestamp() WHERE id=1 AND phase='$2'" > /dev/null ||
    refuse 'unexpected journal state'
  require_equal "$(last_phase)" "$1" 'journal transition failed'
}
require_ledger() {
  require_equal "$(control "SELECT count(*) FROM recovery_attempt")" 1 'missing unique attempted journal'
}
admit() {
  # Fixed id+single INSERT is the unique admission lock. Crash leaves this row.
  # A second caller can neither steal nor silently reset a previous attempt.
  control "INSERT INTO recovery_attempt(id,phase) VALUES (1,'attempted') ON CONFLICT DO NOTHING" > /dev/null ||
    refuse 'journal insert failed'
  require_equal "$(last_phase)" attempted 'prior attempt is unresolved'
  # POSIX noclobber is the independent local filesystem latch. This must never
  # be removed automatically, including after successful fixture rollback.
  ( set -C; printf '%s\n' 'attempted' > "$fixture/.attempted" ) 2>/dev/null ||
    refuse 'attempt latch already exists'
}
run_backup() {
  pg_dump -Fc --no-owner --no-privileges -d "$source_db" > "$backup" 2>"$fixture/pg-error" ||
    refuse 'pg_dump failed'
  chmod 600 "$backup"
  test -s "$backup" || refuse 'empty backup'
  sha256sum "$backup" | cut -d ' ' -f 1 > "$backup_digest"
  chmod 600 "$backup_digest"
  verify_backup
}
restore_into() {
  target="$1"
  case "$target" in
    "$restore_db"|"$rollback_db") ;;
    *) refuse 'unowned restoration database';;
  esac
  test "$(sql postgres "SELECT count(*) FROM pg_database WHERE datname='$target'")" = 0 ||
    refuse 'restore target already exists'
  createdb "$target" > /dev/null 2>"$fixture/pg-error" || refuse 'create disposable database failed'
  verify_backup
  pg_restore --exit-on-error --no-owner --no-privileges -d "$target" "$backup" > /dev/null 2>"$fixture/pg-error" || refuse 'pg_restore refused archive'
}
assert_fingerprint() {
  require_equal "$(fingerprint "$1")" "$2" 'protected data, tables or schema mismatch'
}
assert_schema() {
  require_equal "$(sql "$1" "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='TotpFactor' AND column_name='secretCiphertext'")" 1 'TOTP ciphertext column missing'
  require_equal "$(sql "$1" "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='AccountRecoveryRequest' AND column_name='requestKeyHash'")" 1 'recovery hash schema incompatible'
  require_equal "$(sql "$1" "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='EmailOutboxMessage' AND column_name='payload'")" 1 'outbox schema incompatible'
  require_equal "$(sql "$1" "SELECT count(*) FROM information_schema.tables WHERE table_schema='virki_security' AND table_name='audit_retention_policy'")" 1 'audit policy schema incompatible'
}
rollback() {
  verify_backup
  # Validate independent restore BEFORE touching old database. A broken
  # archive leaves maintenance locked and old data untouched when possible.
  restore_into "$rollback_db"
  assert_fingerprint "$rollback_db" "$baseline_fingerprint"
  assert_schema "$rollback_db"
  # All writer clients are stopped by this fixture. No production equivalent.
  dropdb "$source_db" > /dev/null 2>"$fixture/pg-error" || refuse 'rollback source was not quiescent'
  createdb "$source_db" > /dev/null 2>"$fixture/pg-error" || refuse 'rollback target creation failed'
  pg_restore --exit-on-error --no-owner --no-privileges -d "$source_db" "$backup" > /dev/null 2>"$fixture/pg-error" || refuse 'rollback restore failed'
  assert_fingerprint "$source_db" "$baseline_fingerprint"
  assert_schema "$source_db"
  record rolled_back live_migrated
  # Attempt latch intentionally retained. Operator must reconcile.
}
crash_point() {
  if test "${VIRKI_OFFLINE_PG_CASE:-}" = crash_live && test "$1" = live_migrated; then
    kill -KILL "$$"
  fi
}
attempt() {
  case "${VIRKI_OFFLINE_PG_CASE:-}" in
    happy|incompatible|tamper|fail_live|crash_live|corrupt_backup|race) ;;
    *) refuse 'unsupported fixture case';;
  esac
  baseline_fingerprint="$(fingerprint "$source_db")"
  test -n "$baseline_fingerprint" || refuse 'source inventory missing'
  assert_schema "$source_db"
  printf '%s\n' "$baseline_fingerprint" > "$fixture/baseline.sha256"
  chmod 600 "$fixture/baseline.sha256"
  admit
  record maintenance attempted
  run_backup
  record backed_up maintenance
  restore_into "$restore_db"
  assert_fingerprint "$restore_db" "$baseline_fingerprint"
  record restored backed_up
  if test "${VIRKI_OFFLINE_PG_CASE}" = tamper; then
    sql "$restore_db" "UPDATE \"TotpFactor\" SET \"secretCiphertext\"='evil' WHERE id='proof-totp'" > /dev/null
    assert_fingerprint "$restore_db" "$baseline_fingerprint"
    refuse 'tamper undetected'
  fi
  if test "${VIRKI_OFFLINE_PG_CASE}" = incompatible; then
    sql "$restore_db" 'ALTER TABLE "TotpFactor" DROP COLUMN "secretCiphertext"' > /dev/null
    assert_schema "$restore_db"
    refuse 'incompatible schema undetected'
  fi
  # Actual PostgreSQL schema migration against restored clone first. The
  # column is fixture-only. Preserve every preexisting field.
  sql "$restore_db" 'ALTER TABLE "User" ADD COLUMN "offlineFixtureAdditive" TEXT DEFAULT NULL' > /dev/null ||
    refuse 'restored migration failed'
  assert_fingerprint "$restore_db" "$baseline_fingerprint"
  record restore_migrated restored
  test "${VIRKI_OFFLINE_PG_CASE}" = race && sleep 0.2
  sql "$source_db" 'ALTER TABLE "User" ADD COLUMN "offlineFixtureAdditive" TEXT DEFAULT NULL' > /dev/null ||
    refuse 'live fixture migration failed'
  assert_fingerprint "$source_db" "$baseline_fingerprint"
  record live_migrated restore_migrated
  crash_point live_migrated
  if test "${VIRKI_OFFLINE_PG_CASE}" = corrupt_backup; then
    printf '%s' 'broken' > "$backup"
  fi
  if test "${VIRKI_OFFLINE_PG_CASE}" = fail_live ||
    test "${VIRKI_OFFLINE_PG_CASE}" = corrupt_backup; then
    rollback
    return
  fi
  require_equal "$(sql "$source_db" 'SELECT count(*) FROM "User" WHERE "offlineFixtureAdditive" IS NOT NULL')" 0 'fixture health failed'
  assert_fingerprint "$source_db" "$baseline_fingerprint"
  record completed live_migrated
  # Full release acceptance is never claimed, even on success.
}
case "${1:-}" in
  attempt) attempt ;;
  inspect)
    # Safe status only. No passwords, dumps, queries or user data.
    control 'SELECT phase FROM recovery_attempt WHERE id=1' ;;
  reconcile)
    require_equal "$(last_phase)" live_migrated 'reconciliation requires interrupted live migration'
    baseline_fingerprint="$(cat "$fixture/baseline.sha256")"
    rollback
    ;;
  *) refuse 'unsupported operation';;
esac
