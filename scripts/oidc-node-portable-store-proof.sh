#!/usr/bin/env bash
# WSL/Linux Node22 physical proof of the unchanged OIDC PostgreSQL18 store suite.
# No Docker/sudo/system service: all PG binaries stay in an explicit private bundle.
set -euo pipefail
umask 077

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
[[ "$#" -ge 5 && "$1" == exec && "$2" == --env ]] || exit 82
[[ "$3" == "PGPASSWORD=$VIRKI_OIDC_PG_PASSWORD" ]] || exit 83
[[ "$4" == "$VIRKI_OIDC_PG_CONTAINER" && "$5" == psql ]] || exit 84
shift 5
args=()
seen_host=false
seen_role=false
seen_database=false
while (( $# )); do
  case "$1" in
    --host)
      [[ "$#" -ge 2 && "$2" == 127.0.0.1 ]] || exit 85
      seen_host=true
      shift 2
      ;;
    --username)
      [[ "$#" -ge 2 && "$2" == "$VIRKI_OIDC_PG_ROLE" ]] || exit 86
      seen_role=true
      args+=( "$1" "$2" )
      shift 2
      ;;
    --dbname)
      [[ "$#" -ge 2 && "$2" == "$VIRKI_OIDC_PG_DATABASE" ]] || exit 87
      seen_database=true
      args+=( "$1" "$2" )
      shift 2
      ;;
    *)
      args+=( "$1" )
      shift
      ;;
  esac
done
[[ "$seen_host" == true && "$seen_role" == true && "$seen_database" == true ]] || exit 88
exec "$VIRKI_OIDC_PSQL_BINARY" --host "$VIRKI_OIDC_PG_SOCKET" "${args[@]}"
SHIM_SCRIPT
chmod 700 "$SHIM/docker"
export VIRKI_OIDC_DOCKER_BINARY="$SHIM/docker"

export VIRKI_OIDC_TSX_PATH="${VIRKI_OIDC_TSX_PATH:-$REPO/node_modules/tsx/dist/cli.mjs}"
[[ -f "$VIRKI_OIDC_TSX_PATH" ]] || { echo "Linux tsx unavailable. Install local dependencies under Node22, or set VIRKI_OIDC_TSX_PATH to an isolated Linux tsx CLI." >&2; exit 1; }
echo "PG18 portable socket ready; Node $(node --version); running unchanged 10-test suite."
node "$VIRKI_OIDC_TSX_PATH" --test "$TEST"
