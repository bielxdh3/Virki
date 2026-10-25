#!/usr/bin/env bash
# WSL/Linux Node22 physical proof of the unchanged OIDC PostgreSQL18 store suite.
# No Docker/sudo/system service: all PG binaries stay in an explicit private bundle.
set -euo pipefail
umask 077

# libpq uses PGHOSTADDR as the network destination even when --host points to
# a private Unix socket. Never inherit an operator's database connection env.
unset PGHOSTADDR PGHOST PGPORT PGUSER PGDATABASE PGPASSWORD PGPASSFILE
unset PGSERVICE PGSERVICEFILE PGSYSCONFDIR PGOPTIONS PGCONNECT_TIMEOUT
unset PGSSLMODE PGSSLROOTCERT PGSSLCERT PGSSLKEY PGSSLCRL PGSSLCRLDIR
unset PGTARGETSESSIONATTRS PGCHANNELBINDING PGREQUIREPEER PGREQUIREAUTH
unset PGGSSENCMODE PGKRBSRVNAME PGAPPNAME PGCLIENTENCODING

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
: "${VIRKI_PG18_PORTABLE_BUNDLE:?Set VIRKI_PG18_PORTABLE_BUNDLE to an isolated, extracted PG18 bundle}"
ROOT="$VIRKI_PG18_PORTABLE_BUNDLE/root"
BIN="$ROOT/usr/lib/postgresql/18/bin"
LIB="$ROOT/usr/lib/x86_64-linux-gnu"
SHARE="$ROOT/usr/share/postgresql/18"
TEST="$REPO/packages/oidc-node/src/postgres-store.integration.test.ts"
for needed in "$BIN/initdb" "$BIN/pg_ctl" "$BIN/postgres" "$BIN/psql" "$LIB/libpq.so.5" "$LIB/liburing.so.2" "$TEST"; do
  [[ -f "$needed" ]] || { echo "Portable PostgreSQL proof input missing." >&2; exit 1; }
done
export LD_LIBRARY_PATH="$LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
[[ "$("$BIN/postgres" --version)" == *'PostgreSQL) 18.'* ]] || { echo "PG18 binary required." >&2; exit 1; }
[[ "$(node -p 'process.versions.node.split(".")[0]')" == "22" ]] || { echo "Node22 required." >&2; exit 1; }

OWNER="$(node -p 'require("node:crypto").randomUUID()')"
DATA_ROOT="$(mktemp -d /dev/shm/virki59-oidc-store-XXXXXXXX)"
printf '%s\n' "$OWNER" > "$DATA_ROOT/.owner"
DATA="$DATA_ROOT/pgdata"
SOCKET="$DATA_ROOT/socket"
SHIM="$DATA_ROOT/tools"
mkdir -m 700 "$DATA" "$SOCKET" "$SHIM"
started=false

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$DATA_ROOT" == /dev/shm/virki59-oidc-store-* &&
        -f "$DATA_ROOT/.owner" &&
        "$(cat "$DATA_ROOT/.owner")" == "$OWNER" &&
        "$(stat -c '%u' "$DATA_ROOT")" == "$(id -u)" ]]; then
    if [[ "$started" == true ]]; then
      "$BIN/pg_ctl" -D "$DATA" -m immediate -w stop >/dev/null 2>&1 || status=1
    fi
    rm -rf -- "$DATA_ROOT" || status=1
  else
    echo "Owner verification failed; private PostgreSQL data preserved for inspection." >&2
    status=1
  fi
  echo "Portable PG18 own-cluster cleanup status: $status"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export PGHOST="$SOCKET"
export PGPORT="$(node -p 'require("node:crypto").randomInt(23000, 59000)')"
export PGUSER="$(id -un)"
"$BIN/initdb" -D "$DATA" -A trust --no-instructions --no-sync -L "$SHARE" >/dev/null
# No TCP listeners. The socket is inside a private 0700 directory.
"$BIN/pg_ctl" -D "$DATA" -o "-c listen_addresses='' -c unix_socket_directories=$SOCKET -p $PGPORT -c max_connections=64 -c shared_buffers=16MB" -w start >/dev/null
started=true
[[ "$("$BIN/psql" -d postgres -X -At -c 'SHOW listen_addresses')" == "" ]] || { echo "TCP unexpectedly enabled." >&2; exit 1; }
[[ "$("$BIN/psql" -d postgres -X -At -c 'SHOW unix_socket_directories')" == "$SOCKET" ]] || { echo "Unexpected Unix socket location." >&2; exit 1; }
[[ "$("$BIN/psql" -d postgres -X -At -c 'SHOW data_directory')" == "$DATA" ]] || { echo "Connected to unexpected PostgreSQL cluster." >&2; exit 1; }
[[ "$("$BIN/psql" -d postgres -X -At -c 'SELECT inet_server_addr() IS NULL')" == t ]] || { echo "PostgreSQL connection is not a local Unix socket." >&2; exit 1; }

export VIRKI_OIDC_PG_CONTAINER="virki-oidc-pg18-$OWNER"
export VIRKI_OIDC_PG_ROLE=rp_oidc_owner
export VIRKI_OIDC_PG_DATABASE=rp_oidc_proof
export VIRKI_OIDC_PG_SCHEMA=rp_oidc_private
export VIRKI_OIDC_PG_PASSWORD="$(node -p 'require("node:crypto").randomBytes(32).toString("hex")')"
export VIRKI_OIDC_PG_SOCKET="$SOCKET"
export VIRKI_OIDC_PSQL_BINARY="$BIN/psql"

"$BIN/psql" -d postgres -X -q -v ON_ERROR_STOP=1 -c "CREATE ROLE rp_oidc_owner LOGIN PASSWORD '$VIRKI_OIDC_PG_PASSWORD'"
"$BIN/psql" -d postgres -X -q -v ON_ERROR_STOP=1 -c "CREATE DATABASE rp_oidc_proof OWNER rp_oidc_owner"
"$BIN/psql" -d rp_oidc_proof -X -q -v ON_ERROR_STOP=1 -c 'SET ROLE rp_oidc_owner; CREATE SCHEMA rp_oidc_private AUTHORIZATION rp_oidc_owner; CREATE TABLE rp_oidc_private."VirkiOidcLoginFlow" ("stateHash" text PRIMARY KEY, "ciphertext" text NOT NULL, "expiresAt" timestamptz NOT NULL); RESET ROLE'
"$BIN/psql" -d rp_oidc_proof -X -q -v ON_ERROR_STOP=1 -c 'ALTER ROLE rp_oidc_owner IN DATABASE rp_oidc_proof SET search_path = rp_oidc_private'
"$BIN/psql" -d rp_oidc_proof -X -q -v ON_ERROR_STOP=1 -c "ALTER ROLE rp_oidc_owner IN DATABASE rp_oidc_proof SET TimeZone = 'America/Porto_Velho'"

# Narrow transport shim: accepts exclusively the existing test's docker exec
# psql command shape, validates ownership/credentials, strips its hardcoded TCP
# host, and executes native psql over the private Unix socket. Never uses Docker.
cat > "$SHIM/docker" <<'SHIM_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 20 && "$1" == exec && "$2" == --env ]] || exit 82
[[ "$3" == "PGPASSWORD=$VIRKI_OIDC_PG_PASSWORD" ]] || exit 83
[[ "$4" == "$VIRKI_OIDC_PG_CONTAINER" && "$5" == psql ]] || exit 84
shift 5
[[ "$#" -eq 15 && "$1" == --host && "$2" == 127.0.0.1 ]] || exit 85
[[ "$3" == --username && "$4" == "$VIRKI_OIDC_PG_ROLE" ]] || exit 86
[[ "$5" == --dbname && "$6" == "$VIRKI_OIDC_PG_DATABASE" ]] || exit 87
[[ "$7" == --no-psqlrc && "$8" == --quiet && "$9" == --tuples-only && "${10}" == --no-align ]] || exit 88
[[ "${11}" == '--field-separator=|' && "${12}" == --set && "${13}" == ON_ERROR_STOP=1 && "${14}" == --command ]] || exit 89
# Rebuild the entire command; never forward any caller-supplied connection
# options or alternate host/database. Only the known test SQL may vary.
exec "$VIRKI_OIDC_PSQL_BINARY" --host "$VIRKI_OIDC_PG_SOCKET" --port "$PGPORT" \
  --username "$VIRKI_OIDC_PG_ROLE" --dbname "$VIRKI_OIDC_PG_DATABASE" \
  --no-psqlrc --quiet --tuples-only --no-align '--field-separator=|' \
  --set ON_ERROR_STOP=1 --command "${15}"
SHIM_SCRIPT
chmod 700 "$SHIM/docker"
export VIRKI_OIDC_DOCKER_BINARY="$SHIM/docker"

# Noncanonical caller args must be rejected before psql even if the fixed
# prefix would otherwise be accepted.
if "$SHIM/docker" exec --env "PGPASSWORD=$VIRKI_OIDC_PG_PASSWORD" \
  "$VIRKI_OIDC_PG_CONTAINER" psql \
  --host 127.0.0.1 --username "$VIRKI_OIDC_PG_ROLE" --dbname "$VIRKI_OIDC_PG_DATABASE" \
  --no-psqlrc --quiet --tuples-only --no-align '--field-separator=|' \
  --set ON_ERROR_STOP=1 --command 'SELECT 1' --host=remote.example.invalid; then
  echo "Unsafe extra PostgreSQL connection argument accepted." >&2
  exit 1
fi

export VIRKI_OIDC_TSX_PATH="${VIRKI_OIDC_TSX_PATH:-$REPO/node_modules/tsx/dist/cli.mjs}"
[[ -f "$VIRKI_OIDC_TSX_PATH" ]] || { echo "Linux tsx unavailable. Install local dependencies under Node22, or set VIRKI_OIDC_TSX_PATH to an isolated Linux tsx CLI." >&2; exit 1; }
echo "PG18 portable socket ready; Node $(node --version); running unchanged 10-test suite."
node "$VIRKI_OIDC_TSX_PATH" --test "$TEST"
