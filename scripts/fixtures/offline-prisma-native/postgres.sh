#!/bin/sh
# Real PostgreSQL 17, disposable ONLY; no published ports, no external network.
# Source and dependencies are read-only. All cluster/data/archive bytes reside
# only on private tmpfs; the host never receives database files/credentials.
set -eu
test "${VIRKI_PRISMA_NATIVE_DISPOSABLE:-}" = 1 || exit 90
test "$(id -u)" = 70 && test -e /.dockerenv || exit 91
test "${DATABASE_URL:-}" = '' && test "${MIGRATION_DATABASE_URL:-}" = '' || exit 92
test "${PGHOST:-}" = '' && test "${PGHOSTADDR:-}" = '' || exit 93
test ! -S /var/run/docker.sock || exit 94
test "$(stat -f -c %t /tmp)" = 1021994 || exit 95
test "$(stat -f -c %t /var/lib/postgresql)" = 1021994 || exit 96
umask 077
mkdir -m 700 /tmp/virki-proof
mkdir -m 700 /var/lib/postgresql/data
initdb --auth-local=trust --auth-host=reject -D /var/lib/postgresql/data > /tmp/virki-proof/pg.log 2>&1 || exit 97
# No TCP listener at all: the only client transport is a Unix socket in a
# random owner-labelled Docker volume shared with a fixed Node runner. Both
# containers run --network none; no port or network can reach this Postgres.
pg_ctl -D /var/lib/postgresql/data -o "-c listen_addresses='' -c unix_socket_directories=/var/run/postgresql" -w start \
  > /tmp/virki-proof/pg-start.log 2>&1 || exit 98
trap 'pg_ctl -D /var/lib/postgresql/data -m immediate stop >/dev/null 2>&1 || true' EXIT
createdb -h /var/run/postgresql -U postgres virki_source || exit 99
createdb -h /var/run/postgresql -U postgres virki_clone || exit 100
createdb -h /var/run/postgresql -U postgres virki_rollback || exit 101
# Mirror the existing real PostgreSQL disposable recovery fixture's required
# independent role bootstrap BEFORE the audited role-boundary migrations.
# These NOLOGIN roles exist only inside this disposable private PGDATA tmpfs.
for role in virki_migrator virki_runtime virki_audit_maintenance; do
  psql -X -q -v ON_ERROR_STOP=1 -h /var/run/postgresql -U postgres -d postgres \
    -c "CREATE ROLE $role NOLOGIN" > /tmp/virki-proof/roles.log 2>&1 || exit 103
done
psql -X -q -v ON_ERROR_STOP=1 -h /var/run/postgresql -U postgres -d virki_source \
  -f /workspace/packages/database/prisma/migrations/0_init/migration.sql \
  >/tmp/virki-proof/seed.log 2>&1 || exit 102
printf 'READY\n' > /tmp/virki-proof/ready
while sleep 1; do :; done
