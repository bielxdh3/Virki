#!/bin/sh
# Invoked exclusively inside the pinned disposable postgres image with
# --network=none, --read-only, private tmpfs, user postgres and no host socket.
set -eu
case "${VIRKI_OFFLINE_PG_DISPOSABLE:-}" in 1) ;; *) exit 91;; esac
test "$(id -u)" = 70 && test -e /.dockerenv || exit 92
test "$(stat -f -c %t /tmp)" = 1021994 || exit 93
test "$(stat -f -c %t /var/lib/postgresql/data)" = 1021994 || exit 94
test -d /workspace/scripts/fixtures/offline-pg-recovery || exit 95
test ! -S /var/run/docker.sock || exit 96
test "${DATABASE_URL:-}" = '' && test "${MIGRATION_DATABASE_URL:-}" = '' || exit 97
test "${PGHOST:-}" = '' && test "${PGHOSTADDR:-}" = '' || exit 98
umask 077
export PGHOST=/tmp PGPORT=5432 PGUSER=postgres PGDATABASE=postgres
mkdir -m 700 /tmp/virki-pg-recovery
fixture=/tmp/virki-pg-recovery
initdb --auth-local=trust -D /var/lib/postgresql/data > "$fixture/init.log" 2>&1 || { echo 'Disposable cluster initialization failed' >&2; exit 99; }
pg_ctl -D /var/lib/postgresql/data -o "-c listen_addresses='' -c unix_socket_directories=/tmp" -w start > "$fixture/pg-start.log" 2>&1 ||
  { echo 'Disposable PostgreSQL could not start' >&2; exit 100; }
# Container destruction removes entire private PGDATA tmpfs after this script.
trap 'pg_ctl -D /var/lib/postgresql/data -m immediate stop > /dev/null 2>&1 || true' EXIT

createdb virki_source || { echo 'Source fixture creation failed' >&2; exit 101; }
createdb virki_control || { echo 'Journal fixture creation failed' >&2; exit 102; }
psql -X -q -v ON_ERROR_STOP=1 -d virki_control -c "CREATE TABLE recovery_attempt (id int PRIMARY KEY CHECK(id=1), phase text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp())" > /dev/null 2>"$fixture/pg-error" || exit 103

# Reuse the actual ordered, reviewed SQL migrations already exercised by
# backup-restore-validation.mjs. This fixture deliberately does not invent a
# parallel application schema or claim to have generated Prisma history.
psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "CREATE ROLE virki_migrator NOLOGIN" > /dev/null 2>"$fixture/pg-error" || exit 104
psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "CREATE ROLE virki_runtime NOLOGIN" > /dev/null 2>"$fixture/pg-error" || exit 105
psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "CREATE ROLE virki_audit_maintenance NOLOGIN" > /dev/null 2>"$fixture/pg-error" || exit 106
for migration in /workspace/packages/database/prisma/migrations/*/migration.sql; do
  test -f "$migration" || exit 107
  psql -X -q -v ON_ERROR_STOP=1 -d virki_source -f "$migration" > /dev/null 2>"$fixture/pg-error" ||
    { printf '%s\n' 'Checked-in fixture SQL migration failed' >&2; exit 108; }
done
psql -X -q -v ON_ERROR_STOP=1 -d virki_source -f /workspace/scripts/fixtures/offline-pg-recovery/seed.psql > /dev/null 2>"$fixture/pg-error" ||
  { echo 'Synthetic private-data seed failed' >&2; exit 109; }
protected_count="$(psql -X -qAt -v ON_ERROR_STOP=1 -d virki_source -c '
SELECT
  (SELECT count(*) FROM "User")=2
  AND (SELECT count(*) FROM "Session")=1
  AND (SELECT count(*) FROM "TotpFactor")=1
  AND (SELECT count(*) FROM "RecoveryCode")=1
  AND (SELECT count(*) FROM "AdministrativeCredential")=1
  AND (SELECT count(*) FROM "AdministrativeRecoveryCode")=1
  AND (SELECT count(*) FROM "AccountRecoveryRequest")=1
  AND (SELECT count(*) FROM "AuditLog")=1
  AND (SELECT count(*) FROM "EmailOutboxMessage")=1
  AND (SELECT count(*) FROM "EmailDeliveryAttempt")=1
  AND (SELECT count(*) FROM "OidcArtifact")=1
' 2>"$fixture/pg-error")"
test "$protected_count" = t ||
  { echo 'Representative security data is incomplete' >&2; exit 133; }

case "${1:-}" in
  happy|incompatible|tamper|fail_live|crash_live|corrupt_backup|race|crash_admit|crash_rollback_clone|crash_rollback_proven|crash_rollback_dropped|crash_rollback_created|crash_rollback_loaded|crash_rollback_restored)
    export VIRKI_OFFLINE_PG_CASE="$1"
    case "$1" in
      happy)
        sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/controller.err" ||
          { echo 'Happy-path recovery rehearsal failed' >&2; exit 110; }
        test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = completed || exit 111
        ;;
      crash_live)
        # Keep postgres supervisor alive while killing ONLY the child. Its
        # committed journal row and locked snapshot remain inspectable.
        ( sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/controller.err" ) &
        pid=$!
        wait "$pid" && exit 112
        test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = live_migrated || exit 113
        test -f "$fixture/.attempted" && test -s "$fixture/virki.dump" || exit 114
        sh /workspace/scripts/lib/offline-pg-disposable-controller.sh reconcile > /dev/null 2>"$fixture/reconcile.err" || exit 115
        test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = rolled_back || exit 116
        test -f "$fixture/.attempted" || exit 117
        ;;
      crash_admit)
        ( sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/controller.err" ) &
        pid=$!
        wait "$pid" && exit 136
        test -f "$fixture/.attempted" || exit 137
        test "$(psql -X -qAt -d virki_control -c 'SELECT count(*) FROM recovery_attempt')" = 0 || exit 138
        VIRKI_OFFLINE_PG_CASE=happy
        export VIRKI_OFFLINE_PG_CASE
        if sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/replay.err"; then exit 139; fi
        test "$(psql -X -qAt -d virki_control -c 'SELECT count(*) FROM recovery_attempt')" = 0 || exit 140
        ;;
      crash_rollback_clone|crash_rollback_proven|crash_rollback_dropped|crash_rollback_created|crash_rollback_loaded|crash_rollback_restored)
        ( sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/controller.err" ) &
        pid=$!
        wait "$pid" && exit 141
        test -f "$fixture/.attempted" && test -s "$fixture/virki.dump" || exit 142
        phase="$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')"
        case "$phase" in rollback_started|rollback_proven|rollback_rebuild|rollback_restored) ;; *) exit 143;; esac
        VIRKI_OFFLINE_PG_CASE=happy
        export VIRKI_OFFLINE_PG_CASE
        if test "$1" = crash_rollback_clone; then
          # The owned rollback clone exists with incomplete SQL content.
          # Automatic deletion would hide uncertainty: explicit operator STOP.
          if sh /workspace/scripts/lib/offline-pg-disposable-controller.sh reconcile > /dev/null 2>"$fixture/reconcile.err"; then exit 144; fi
          test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = rollback_started || exit 145
          test "$(psql -X -qAt -d postgres -c "SELECT count(*) FROM pg_database WHERE datname='virki_source'")" = 1 || exit 146
        else
          sh /workspace/scripts/lib/offline-pg-disposable-controller.sh reconcile > /dev/null 2>"$fixture/reconcile.err" || exit 147
          test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = rolled_back || exit 148
          current_inventory="$(psql -X -qAt -v ON_ERROR_STOP=1 -d virki_source -f /workspace/scripts/fixtures/offline-pg-recovery/inventory.psql 2>"$fixture/pg-error")"
          test "$current_inventory" = "$(cat "$fixture/baseline.sha256")" || exit 149
        fi
        test -f "$fixture/.attempted" || exit 150
        ;;
      fail_live)
        sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/controller.err" || exit 118
        test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = rolled_back || exit 119
        test -f "$fixture/.attempted" || exit 120
        ;;
      race)
        ( sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/race-a.err" ) &
        first=$!
        ( sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/race-b.err" ) &
        second=$!
        first_status=0
        second_status=0
        wait "$first" || first_status=$?
        wait "$second" || second_status=$?
        if test "$first_status" -eq 0; then
          test "$second_status" -ne 0 || exit 128
        else
          test "$second_status" -eq 0 || exit 129
        fi
        test "$(psql -X -qAt -d virki_control -c 'SELECT count(*) FROM recovery_attempt')" = 1 || exit 130
        test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = completed || exit 131
        test -f "$fixture/.attempted" || exit 132
        ;;
      corrupt_backup)
        if sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/controller.err"; then exit 121; fi
        test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = live_migrated || exit 122
        test -f "$fixture/.attempted" || exit 123
        ;;
      incompatible|tamper)
        if sh /workspace/scripts/lib/offline-pg-disposable-controller.sh attempt > /dev/null 2>"$fixture/controller.err"; then exit 124; fi
        test "$(psql -X -qAt -d virki_control -c 'SELECT phase FROM recovery_attempt WHERE id=1')" = restored || exit 125
        test -f "$fixture/.attempted" || exit 126
        current_inventory="$(psql -X -qAt -v ON_ERROR_STOP=1 -d virki_source -f /workspace/scripts/fixtures/offline-pg-recovery/inventory.psql 2>"$fixture/pg-error")"
        test "$current_inventory" = "$(cat "$fixture/baseline.sha256")" || exit 134
        test "$(psql -X -qAt -d virki_source -c 'SELECT count(*) FROM information_schema.columns WHERE table_name = '\''User'\'' AND column_name = '\''offlineFixtureAdditive'\''')" = 0 || exit 135
        ;;
    esac
    printf 'PASS real PostgreSQL disposable %s (NON_AUTHORIZING)\n' "$1"
    ;;
  *) echo 'Unsupported disposable test case' >&2; exit 127;;
esac
