#!/usr/bin/env bash
# C4 V23: disposable real Linux kernel UID/GID peer boundary integration.
# Run ONLY in disposable WSL/test Linux as root, explicitly:
#   wsl.exe -u root -e bash /mnt/e/Virki/.worktrees/.../owner-crossuid-v23.integration.sh
#
# Does NOT create users, install services, use keys, write production paths,
# change system config, start Docker or enable SIGN_ACK. All files under one
# new private mktemp directory in /tmp, deleted by trap. This tests Linux
# SO_PEERCRED with real different numeric UIDs, NOT an independent off-host
# owner, a physical BuildKit worker, or production authority.
set -euo pipefail
umask 077

if [[ "$(id -u)" != "0" ]]; then
  echo "V23_REQUIRES_ISOLATED_TEST_LINUX_ROOT (no automatic elevation)" >&2
  exit 77
fi
for cmd in gcc setpriv mktemp stat grep awk kill; do
  command -v "$cmd" >/dev/null || { echo "missing test tool: $cmd" >&2; exit 77; }
done

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
case "$source_dir" in
  */infra/offline/native-owner-authority) ;;
  *) echo "unexpected source directory" >&2; exit 77 ;;
esac

test_dir="$(mktemp -d /tmp/virki-owner-v23-XXXXXXXXXX)"
daemon_pid=""
cleanup() {
  local ret=$?
  trap - EXIT
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -TERM "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  if [[ "$ret" != 0 && -e "$test_dir/owner.log" ]]; then
    echo "C4_V23_OWNER_LOG_ON_FAILURE:" >&2
    tail -50 "$test_dir/owner.log" >&2 || true
  fi
  # The test directory is generated and root-owned under /tmp only.
  if [[ "$test_dir" == /tmp/virki-owner-v23-* && -d "$test_dir" ]]; then
    rm -rf -- "$test_dir"
  fi
  exit "$ret"
}
trap cleanup EXIT

owner_uid=25111
daemon_uid=25112
attacker_uid=25113
daemon_gid=25112
owner_bin="$test_dir/native-owner"
client_bin="$test_dir/native-client"

gcc -static -std=c11 -O2 -Wall -Wextra -Werror "$source_dir/native-owner-authority.c" -o "$owner_bin"
gcc -std=c11 -O2 -Wall -Wextra -Werror "$source_dir/owner-authority-client-fixture.c" -o "$client_bin"
chmod 0755 "$test_dir" "$owner_bin" "$client_bin"

mkdir "$test_dir/socket" "$test_dir/ledger"
chown "$owner_uid:$daemon_gid" "$test_dir/socket"
chmod 0750 "$test_dir/socket"
chown "$owner_uid:$owner_uid" "$test_dir/ledger"
chmod 0700 "$test_dir/ledger"
socket="$test_dir/socket/owner.sock"
ledger="$test_dir/ledger"

owner_args=(--socket "$socket" --ledger-dir "$ledger"
  --daemon-uid "$daemon_uid" --daemon-gid "$daemon_gid")

start_owner() {
  : >"$test_dir/owner.log"
  setpriv --reuid "$owner_uid" --regid "$daemon_gid" --clear-groups \
    "$owner_bin" "${owner_args[@]}" >"$test_dir/owner.log" 2>&1 &
  daemon_pid=$!
  local ready=0
  for _ in $(seq 1 100); do
    if grep -q 'VIRKI_OWNER_AUTHORITY_READY:' "$test_dir/owner.log"; then
      ready=1
      break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then break; fi
    sleep 0.04
  done
  if [[ "$ready" != "1" ]]; then
    echo "V23_STRICT_OWNER_DID_NOT_START" >&2
    return 1
  fi
}
stop_owner() {
  local pid="$daemon_pid"
  [[ -n "$pid" ]] || return 1
  kill -TERM "$pid"
  wait "$pid"
  daemon_pid=""
}
invoke() {
  local uid="$1" gid="$2"
  shift 2
  setpriv --reuid "$uid" --regid "$gid" --clear-groups \
    "$client_bin" "$socket" "$@"
}
value() {
  local key="$1"
  awk -F= -v k="$key" '$1==k{print substr($0,length(k)+2);exit}'
}
assert_status() {
  local expected="$1" data="$2" label="$3"
  if [[ "$(printf '%s\n' "$data" | value STATUS)" != "$expected" ]]; then
    echo "V23_BAD_STATUS $label expected=$expected actual=$data" >&2
    return 1
  fi
}

start_owner
[[ "$(stat -c %a "$socket")" == "660" ]]
[[ "$(stat -c %u "$socket")" == "$owner_uid" ]]
[[ "$(stat -c %g "$socket")" == "$daemon_gid" ]]
[[ "$(stat -c %a "$ledger")" == "700" ]]

authorized="$(invoke "$daemon_uid" "$daemon_gid" status)"
assert_status 0 "$authorized" "different real UID authorized"
# A same-UID caller with foreign primary GID can retain the authorized
# socket group as a supplementary group. Socket DAC may allow connect,
# but explicit --daemon-gid now MUST pin SO_PEERCRED.gid as well.
foreign_primary_gid=25114
foreign_group_peer="$(setpriv --reuid "$daemon_uid" --regid "$foreign_primary_gid" \
  --groups "$daemon_gid" "$client_bin" "$socket" status)"
assert_status 10 "$foreign_group_peer" "pinned UID but foreign primary GID rejected"
epoch="$(printf '%s\n' "$authorized" | value EPOCH)"
seq="$(printf '%s\n' "$authorized" | value SEQ)"
[[ "$epoch" == "1" && "$seq" == "1001" ]]

# Both hostile and owner UIDs can connect to the 0660 socket by membership
# or inode ownership, but SO_PEERCRED must refuse their operations.
for uid in "$attacker_uid" "$owner_uid"; do
  for action in status begin; do
    denied="$(invoke "$uid" "$daemon_gid" "$action" \
      0123456789abcdef0123456789abcdef "" "$epoch")"
    assert_status 10 "$denied" "unauthorized UID=$uid $action"
  done
done
root_denied="$("$client_bin" "$socket" status)"
assert_status 10 "$root_denied" "root peer rejected"
after_denial="$(invoke "$daemon_uid" "$daemon_gid" status)"
[[ "$(printf '%s\n' "$after_denial" | value SEQ)" == "$seq" ]]

nonce=0123456789abcdef0123456789abcdef
started="$(invoke "$daemon_uid" "$daemon_gid" begin "$nonce" "" "$epoch")"
assert_status 0 "$started" "authorized independent daemon begin"
scope="$(printf '%s\n' "$started" | value SCOPE_TOKEN)"
[[ "${#scope}" == 64 ]]
assert_status 15 "$(invoke "$daemon_uid" "$daemon_gid" begin "$nonce" "" "$epoch")" \
  "durable nonce replay from legitimate UID"

before_sign="$(invoke "$daemon_uid" "$daemon_gid" status)"
sign="$(invoke "$daemon_uid" "$daemon_gid" sign "$nonce" "$scope" "$epoch")"
assert_status 22 "$sign" "native owner sign disabled across real peer UIDs"
[[ -z "$(printf '%s\n' "$sign" | value SIG_B64)" ]]
[[ -z "$(printf '%s\n' "$sign" | value ACK_SHA)" ]]
after_sign="$(invoke "$daemon_uid" "$daemon_gid" status)"
[[ "$(printf '%s\n' "$before_sign" | value SEQ)" == \
   "$(printf '%s\n' "$after_sign" | value SEQ)" ]]

assert_status 0 "$(invoke "$daemon_uid" "$daemon_gid" abort "$nonce" "$scope" "$epoch")" \
  "authorized exact-scope abort"
assert_status 21 "$(invoke "$daemon_uid" "$daemon_gid" abort "$nonce" "$scope" "$epoch")" \
  "terminal scope replay rejection"

stop_owner
start_owner
recovered="$(invoke "$daemon_uid" "$daemon_gid" status)"
assert_status 0 "$recovered" "cross-UID owner ledger restart"
new_epoch="$(printf '%s\n' "$recovered" | value EPOCH)"
[[ "$new_epoch" == "2" ]]
assert_status 15 "$(invoke "$daemon_uid" "$daemon_gid" begin "$nonce" "" "$new_epoch")" \
  "nonce rejected after durable restart"
assert_status 16 "$(invoke "$daemon_uid" "$daemon_gid" begin \
  abcdef0123456789abcdef0123456789 "" "$epoch")" "old epoch after restart"
stop_owner

echo "C4_V23_REAL_LINUX_CROSS_UID_GID_SOCKET_AND_LEDGER_PASS"
echo "C4_V23_SIGN_ACK=DENIED"
echo "C4_V23_PRODUCTION_AUTHORITY=NO_GO"
