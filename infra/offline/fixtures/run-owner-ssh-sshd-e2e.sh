#!/bin/sh
# Development-only test runner. The parent WSL /etc, /run, /usr/local/lib and
# running sshd are NEVER modified: all mounts occur only after unshare -m.
set -eu

[ "${VIRKI_SSH_DISPOSABLE_E2E:-}" = "1" ] || {
  echo "isolated SSH fixture requires explicit opt-in" >&2; exit 2;
}
[ "$(id -u)" = 0 ] && [ "$(uname -m)" = x86_64 ] || {
  echo "disposable SSH fixture requires Linux root/amd64" >&2; exit 2;
}

if [ "${1:-}" != "--isolated-mount-namespace" ]; then
  # APT materialization is local /tmp only, NOT package installation:
  # no dpkg -i, systemctl, SSH host keys, service or /etc modifications.
  mkdir -p /tmp/virki-sshd-package
  if [ ! -x /tmp/virki-sshd-package/usr/sbin/sshd ]; then
    (cd /tmp && apt download openssh-server)
    dpkg-deb -x /tmp/openssh-server_*.deb /tmp/virki-sshd-package
  fi
  exec unshare -m -n --propagation private /bin/sh "$0" --isolated-mount-namespace
fi

# No mutation before independent mount-namespace creation.
[ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] || {
  echo "mount namespace was not isolated" >&2; exit 2;
}
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || {
  echo "network namespace was not isolated" >&2; exit 2;
}
grep -Eq '^NoNewPrivs:[[:space:]]*0$' /proc/self/status || {
  echo "sudo elevation cannot run under no_new_privs" >&2; exit 2;
}
mount --make-rprivate /
# All sshd/ssh traffic is confined to a NEW namespace's loopback. Nothing
# binds production, localhost of the parent host, or an existing service.
/usr/sbin/ip link set lo up
mount -t tmpfs -o rw,nosuid,nodev,mode=755,size=16m tmpfs /etc
mount -t tmpfs -o rw,nosuid,nodev,mode=755,size=32m tmpfs /run
mount -t tmpfs -o rw,nosuid,nodev,mode=755,size=16m tmpfs /usr/local/lib
mkdir -p /usr/local/lib/virki
mount -t tmpfs -o rw,nosuid,nodev,mode=755,size=16m tmpfs /usr/local/lib/virki
# OpenSSH 10 splits its daemon into sshd-auth and sshd-session. Both package
# binaries are test-only copies, placed in a private mount with no OS writes.
mount -t tmpfs -o rw,nosuid,nodev,mode=755,size=16m tmpfs /usr/lib/openssh
cp /tmp/virki-sshd-package/usr/lib/openssh/sshd-auth /usr/lib/openssh/sshd-auth
cp /tmp/virki-sshd-package/usr/lib/openssh/sshd-session /usr/lib/openssh/sshd-session
chmod 0755 /usr/lib/openssh/sshd-auth /usr/lib/openssh/sshd-session
# OpenSSH self-reexec expects the compiled /usr/sbin/sshd location. Overlay
# /usr/sbin ONLY inside this private mount namespace, preserving host binaries.
mount -t tmpfs -o rw,nosuid,nodev,mode=755,size=16m tmpfs /usr/sbin
cp /tmp/virki-sshd-package/usr/sbin/sshd /usr/sbin/sshd
chmod 0755 /usr/sbin/sshd
ln -s /etc/alternatives/visudo /usr/sbin/visudo

cd /mnt/e/Virki/.worktrees/virki-ssh-bootstrap-w45-20261029
export VIRKI_SSH_ISOLATED_NETWORK=1
exec /usr/bin/node --test infra/offline/owner-ssh-sshd.e2e.test.mjs
