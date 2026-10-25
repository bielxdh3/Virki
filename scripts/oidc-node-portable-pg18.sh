#!/usr/bin/env bash
# Disposable PG18 RP-session integration on WSL/Linux without Docker, sudo or
# an installed PostgreSQL service. Requires operator-provided portable .deb
# extraction (postgresql-18, postgresql-client-18, libpq5, liburing2).
set -euo pipefail
umask 077
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${VIRKI_PG18_PORTABLE_BUNDLE:?Set VIRKI_PG18_PORTABLE_BUNDLE to your isolated extracted PG18 bundle}"
BIN="${VIRKI_PG18_PORTABLE_BUNDLE}/root/usr/lib/postgresql/18/bin"
LIB="${VIRKI_PG18_PORTABLE_BUNDLE}/root/usr/lib/x86_64-linux-gnu"
SHARE="${VIRKI_PG18_PORTABLE_BUNDLE}/root/usr/share/postgresql/18"
for file in "$BIN/initdb" "$BIN/pg_ctl" "$BIN/postgres" "$BIN/psql" "$LIB/libpq.so.5" "$LIB/liburing.so.2"; do
  if [[ ! -e "$file" ]]; then echo 'Portable PG18 dependency unavailable' >&2; exit 1; fi
done
if [[ "$("$BIN/postgres" --version 2>/dev/null || true)" != *'PostgreSQL) 18.'* ]]; then
  # Run version probe again with the local shared-library path below.
  export LD_LIBRARY_PATH="$LIB"
  [[ "$("$BIN/postgres" --version)" == *'PostgreSQL) 18.'* ]] || { echo 'PostgreSQL 18 required' >&2; exit 1; }
fi
export LD_LIBRARY_PATH="$LIB"
export PATH="$BIN:$PATH"
command -v node >/dev/null
[[ "$(node -p 'process.versions.node.split(".")[0]')" == 22 ]] || { echo 'Node 22 required' >&2; exit 1; }
[[ -d "$REPO/examples/oidc-node-rp/node_modules/pg" ]] || { echo 'Install example dependencies first' >&2; exit 1; }
DATA="$(mktemp -d /dev/shm/virki59-pg18-XXXXXXXX)"
cleanup() {
  pg_ctl -D "$DATA" -m immediate -w stop >/dev/null 2>&1 || true
  if [[ "$DATA" == /dev/shm/virki59-pg18-* && -d "$DATA" ]]; then rm -rf -- "$DATA"; fi
}
trap cleanup EXIT INT TERM
export PGHOST="$DATA"
export PGPORT=55472
initdb -D "$DATA" -A trust --no-instructions --no-sync -L "$SHARE" >/dev/null
# Private Unix domain socket in a unique 0700 directory. Never listen on TCP.
pg_ctl -D "$DATA" -o "-c listen_addresses='' -c unix_socket_directories=$DATA -p $PGPORT" -w start >/dev/null
psql -d postgres -X -q -v ON_ERROR_STOP=1 -f "$REPO/examples/oidc-node-rp/schema.psql.txt"
export VIRKI_RP_PG_TEST_SOCKET="$DATA"
export VIRKI_RP_PG_TEST_PORT="$PGPORT"
export VIRKI_RP_PG_TEST_ROLE="$(id -un)"
node --test "$REPO/examples/oidc-node-rp/server.pg.integration.test.mjs"
echo 'Disposable PostgreSQL 18 RP session proof PASS; cluster will be stopped/removed'
