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
route_file="$fixture/private-route"
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
  # The terminal rollback crash proof must stop inside the journal transition,
  # immediately after the committed checkpoint is independently read back.
  # This avoids an untested execution interval after recording restoration
  # and before injecting SIGKILL in the caller.
  if test "$1" = rollback_restored; then
    crash_point rollback_restored
  fi
}
require_ledger() {
  require_equal "$(control "SELECT count(*) FROM recovery_attempt")" 1 'missing unique attempted journal'
}
admit() {
  # Create exclusive owner latch BEFORE writing the PG journal. A crash after
  # journal INSERT but before latch creation could otherwise let another
  # process claim the predecessor's attempted row as its own. A crash in the
  # opposite order leaves an orphan latch, which safely blocks all retries.
  ( set -C; printf '%s\n' 'attempted' > "$fixture/.attempted" ) 2>/dev/null ||
    refuse 'attempt latch already exists'
  sync -f "$fixture/.attempted" > /dev/null 2>"$fixture/pg-error" ||
    refuse 'cannot synchronize attempt latch'
  sync -f "$fixture" > /dev/null 2>"$fixture/pg-error" ||
    refuse 'cannot synchronize fixture directory'
  crash_point latch_created
  # Require that OUR INSERT actually won the unique constraint. Observing an
  # existing 'attempted' row is never sufficient provenance of admission.
  inserted="$(control "INSERT INTO recovery_attempt(id,phase) VALUES (1,'attempted') ON CONFLICT DO NOTHING RETURNING id")" ||
    refuse 'journal insert failed'
  require_equal "$inserted" 1 'prior journal already reserved'
  require_equal "$(last_phase)" attempted 'journal reservation changed'
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
  if test "$target" = "$rollback_db"; then crash_point rollback_clone_created; fi
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
private_health() {
  # The only canary probe is a private Unix socket on the owned isolated PG
  # cluster. No public routing, Cloudflare or production service is contacted.
  pg_isready -h /tmp -p 5432 -d "$source_db" > /dev/null 2>"$fixture/pg-error" ||
    refuse 'private PostgreSQL health unavailable'
  assert_schema "$source_db"
  assert_fingerprint "$source_db" "$baseline_fingerprint"
  require_equal "$(sql "$source_db" 'SELECT count(*) FROM "User" WHERE "offlineFixtureAdditive" IS NOT NULL')" 0 'private canary data probe failed'
}
canary_health() {
  # Return a probe failure so rollback can be requested without misreporting a
  # passed canary. A lost PG connection during rollback still keeps the latch.
  pg_isready -h /tmp -p 5432 -d "$source_db" > /dev/null 2>"$fixture/pg-error" || return 1
  measured="$(sql "$source_db" 'SELECT count(*) FROM "User" WHERE "offlineFixtureAdditive" IS NOT NULL')" || return 1
  test "$measured" = 0 || return 1
  measured="$(fingerprint "$source_db")" || return 1
  test "$measured" = "$baseline_fingerprint"
}
read_route() {
  test -f "$route_file" && test ! -L "$route_file" || refuse 'private route marker missing'
  test "$(stat -c %u:%g:%a "$route_file")" = '70:70:600' || refuse 'private route marker untrusted'
  cat "$route_file"
}
switch_route() {
  expected="$1"
  next="$2"
  case "$expected:$next" in
    predecessor:canary|canary:predecessor) ;;
    *) refuse 'private route transition invalid';;
  esac
  require_equal "$(read_route)" "$expected" 'private route changed before switch'
  # Only a disposable marker is atomically replaced; this is a fixture proof
  # of the pre-switch journal fence, not an external service routing operation.
  staged="$fixture/.private-route-next"
  test ! -e "$staged" || refuse 'ambiguous pending private route switch'
  ( set -C; printf '%s\n' "$next" > "$staged" ) 2>/dev/null ||
    refuse 'private route stage already exists'
  chmod 600 "$staged"
  sync -f "$staged" > /dev/null 2>"$fixture/pg-error" || refuse 'route stage sync failed'
  mv "$staged" "$route_file" || refuse 'route atomic replace failed'
  sync -f "$fixture" > /dev/null 2>"$fixture/pg-error" || refuse 'route parent sync failed'
  require_equal "$(read_route)" "$next" 'private route readback failed'
}
rollback() {
  verify_backup
  # Persist each irreversible boundary in the separate control database.
  # The physical operation may finish before its next journal commit: every
  # replay checks the ACTUAL database state and never trusts the phase alone.
  phase="$(last_phase)"
  case "$phase" in
    live_migrated|private_healthy|canary_prepared|canary_active) record rollback_started "$phase" ;;
    rollback_started|rollback_proven|rollback_rebuild|rollback_restored) ;;
    *) refuse 'rollback journal phase is unsupported' ;;
  esac
  # A canary may have switched immediately before a process died. Inspect
  # actual route state and fence it to predecessor BEFORE PG restore. Never
  # resume writers as an inferred consequence of rollback.
  route="$(read_route)"
  case "$route" in
    predecessor) ;;
    canary) switch_route canary predecessor ;;
    *) refuse 'unknown private route state';;
  esac
  # Reuse ONLY an existing independently VERIFIED clone. Never overwrite,
  # clean, or delete a partially restored clone automatically. Operator must
  # inspect such a fixture separately while the attempted latch remains.
  if test "$(sql postgres "SELECT count(*) FROM pg_database WHERE datname='$rollback_db'")" = 0; then
    restore_into "$rollback_db"
  fi
  assert_fingerprint "$rollback_db" "$baseline_fingerprint"
  assert_schema "$rollback_db"
  if test "$(last_phase)" = rollback_started; then
    record rollback_proven rollback_started
  fi
  crash_point rollback_proven
  if test "$(last_phase)" = rollback_restored; then
    # This state is only allowed after a prior full pg_restore. Any changed
    # data/structure now is an independent integrity incident, not a reason
    # to overwrite another database without review.
    assert_fingerprint "$source_db" "$baseline_fingerprint"
    assert_schema "$source_db"
    record rolled_back rollback_restored
    return
  fi
  if test "$(last_phase)" = rollback_proven; then
    record rollback_rebuild rollback_proven
  fi
  require_equal "$(last_phase)" rollback_rebuild 'rollback rebuild admission missing'
  # All writer clients are stopped by this disposable fixture. A native host
  # must independently prove quiescence before any analogous data mutation.
  dropdb --if-exists "$source_db" > /dev/null 2>"$fixture/pg-error" ||
    refuse 'rollback source was not quiescent'
  crash_point rollback_dropped
  createdb "$source_db" > /dev/null 2>"$fixture/pg-error" ||
    refuse 'rollback target creation failed'
  crash_point rollback_created
  pg_restore --exit-on-error --no-owner --no-privileges -d "$source_db" "$backup" > /dev/null 2>"$fixture/pg-error" || refuse 'rollback restore failed'
  crash_point rollback_loaded
  assert_fingerprint "$source_db" "$baseline_fingerprint"
  assert_schema "$source_db"
  # Adversarial proof of the pre-checkpoint failure window. Before 063b44b the
  # runner accepted ANY child non-zero status as a simulated SIGKILL and then
  # misreported the lingering rollback_rebuild journal as exit 143. This case
  # deliberately fails after a complete pg_restore but BEFORE the durable
  # checkpoint. It must remain uncommitted and explicitly reconcilable.
  if test "${VIRKI_OFFLINE_PG_CASE:-}" = rollback_precheckpoint_error; then
    refuse 'injected failure before rollback_restored checkpoint'
  fi
  record rollback_restored rollback_rebuild
  record rolled_back rollback_restored
  # Attempt latch intentionally retained. Operator must reconcile.
}
crash_point() {
  case "${VIRKI_OFFLINE_PG_CASE:-}:$1" in
    crash_live:live_migrated|crash_canary:canary_switched|crash_admit:latch_created|crash_rollback_clone:rollback_clone_created|crash_rollback_proven:rollback_proven|crash_rollback_dropped:rollback_dropped|crash_rollback_created:rollback_created|crash_rollback_loaded:rollback_loaded|crash_rollback_restored:rollback_restored)
      kill -KILL "$$" ;;
  esac
}
attempt() {
  case "${VIRKI_OFFLINE_PG_CASE:-}" in
    happy|incompatible|tamper|fail_live|crash_live|corrupt_backup|race|crash_admit|crash_rollback_clone|crash_rollback_proven|crash_rollback_dropped|crash_rollback_created|crash_rollback_loaded|crash_rollback_restored|rollback_precheckpoint_error|canary_unhealthy|crash_canary|precanary_unhealthy|postcanary_unhealthy) ;;
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
  case "${VIRKI_OFFLINE_PG_CASE}" in
    fail_live|corrupt_backup|crash_rollback_clone|crash_rollback_proven|crash_rollback_dropped|crash_rollback_created|crash_rollback_loaded|crash_rollback_restored|rollback_precheckpoint_error)
      rollback
      return
      ;;
  esac
  if test "${VIRKI_OFFLINE_PG_CASE}" = precanary_unhealthy; then
    sql "$source_db" "UPDATE \"User\" SET \"offlineFixtureAdditive\"='health-failure'" > /dev/null ||
      refuse 'could not inject disposable pre-canary health failure'
  fi
  if ! (private_health); then
    rollback
    return
  fi
  record private_healthy live_migrated
  require_equal "$(read_route)" predecessor 'unexpected predecessor route'
  record canary_prepared private_healthy
  switch_route predecessor canary
  crash_point canary_switched
  record canary_active canary_prepared
  if test "${VIRKI_OFFLINE_PG_CASE}" = canary_unhealthy; then
    # Deliberately contaminate only disposable synthetic rows AFTER canary
    # activation, proving the health probe rejects a real SQL discrepancy.
    sql "$source_db" "UPDATE \"User\" SET \"offlineFixtureAdditive\"='health-failure'" > /dev/null ||
      refuse 'could not inject disposable canary health failure'
  fi
  if ! canary_health; then
    rollback
    return
  fi
  if test "${VIRKI_OFFLINE_PG_CASE}" = postcanary_unhealthy; then
    sql "$source_db" "UPDATE \"User\" SET \"offlineFixtureAdditive\"='health-failure'" > /dev/null ||
      refuse 'could not inject disposable post-canary health failure'
  fi
  if ! (private_health); then
    rollback
    return
  fi
  record completed canary_active
  # Full release acceptance is never claimed, even on success.
}
case "${1:-}" in
  attempt) attempt ;;
  inspect)
    # Safe status only. No passwords, dumps, queries or user data.
    control 'SELECT phase FROM recovery_attempt WHERE id=1' ;;
  reconcile)
    case "$(last_phase)" in
      live_migrated|private_healthy|canary_prepared|canary_active|rollback_started|rollback_proven|rollback_rebuild|rollback_restored) ;;
      *) refuse 'reconciliation requires an interrupted, uncommitted rollback' ;;
    esac
    test -f "$fixture/.attempted" || refuse 'attempt latch missing during reconciliation'
    baseline_fingerprint="$(cat "$fixture/baseline.sha256")"
    rollback
    ;;
  *) refuse 'unsupported operation';;
esac
