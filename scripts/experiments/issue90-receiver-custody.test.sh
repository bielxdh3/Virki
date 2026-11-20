#!/usr/bin/env bash
# DEV-only Linux permission contract; no BuildKit daemon, network or real project data.
set -euo pipefail
if [[ $(id -u) != 0 ]]; then
  printf '%s\n' 'SKIP: isolated fixture setup requires root' >&2
  exit 77
fi
for command in setpriv getent mktemp stat install; do
  command -v "$command" >/dev/null || { printf 'Missing tool: %s\n' "$command" >&2; exit 77; }
done
receiver=60001
observer=60002
# The fixture must not borrow existing named local users or groups.
for n in "$receiver" "$observer"; do
  if getent passwd "$n" >/dev/null || getent group "$n" >/dev/null; then
    printf 'SKIP: fixture identity %s is assigned\n' "$n" >&2
    exit 77
  fi
done
root=$(mktemp -d /tmp/virki-issue90-custody.XXXXXXXX)
trap 'rm -rf -- "$root"' EXIT
chmod 0711 "$root"
install -d -m 0700 -o "$receiver" -g "$receiver" "$root/receiver"

as_identity() {
  local uid=$1
  shift
  setpriv --reuid "$uid" --regid "$uid" --clear-groups \
    --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
}

[[ $(stat -c '%u:%a' "$root") == 0:711 ]]
[[ $(stat -c '%u:%g:%a' "$root/receiver") == "$receiver:$receiver:700" ]]
as_identity "$receiver" test -w "$root/receiver"
as_identity "$receiver" test ! -w "$root"
as_identity "$observer" test ! -r "$root/receiver"
as_identity "$observer" test ! -w "$root/receiver"
as_identity "$observer" test ! -x "$root/receiver"
as_identity "$observer" test ! -w "$root"
as_identity "$receiver" sh -c 'umask 077; printf "%s\n" fixture > "$1/marker"' sh "$root/receiver"
[[ $(stat -c '%u:%a' "$root/receiver/marker") == "$receiver:600" ]]
[[ $(as_identity "$receiver" cat "$root/receiver/marker") == fixture ]]
as_identity "$observer" test ! -r "$root/receiver/marker"
[[ $(as_identity "$receiver" id -u) == "$receiver" ]]
[[ $(as_identity "$observer" id -u) == "$observer" ]]
printf '%s\n' 'PASS: distinct unprivileged identities, root-owned parent and private receiver directory on Linux' \
  'LIMIT: not integrated with BuildKit; no concurrent publication, mount isolation, or production admission proof.'
