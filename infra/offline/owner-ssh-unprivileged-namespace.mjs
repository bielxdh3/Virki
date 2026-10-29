import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, realpathSync } from "node:fs";
import path from "node:path";

/*
 * DEV-only argument builder. Not a trusted root launcher, signer or installer.
 * This JS may run only as an ordinary account. To avoid even executing this
 * untrusted JS on the host, an operator can invoke /usr/bin/bwrap DIRECTLY with
 * the literal audited argv from docs/offline-ssh-unprivileged-namespace.md.
 *
 * Crucial ordering: the FIRST executed process is a trusted system bwrap
 * binary. Project-supplied shell/Node bytes are interpreted only AFTER bwrap
 * remaps root to the unprivileged host UID and makes an empty private root.
 * The W61 root --isolated-mount-namespace fixture is intentionally NOT run.
 */
const BWRAP = "/usr/bin/bwrap";
const ALLOWED_SCRIPTS = /^[a-z0-9][a-z0-9._-]{0,100}\.sh$/u;
function refuse(reason) {
  throw new Error("Unprivileged SSH namespace refused: " + reason);
}
export function requireUnprivilegedSshSandboxStartup({ uid, euid, gid, egid } = {}) {
  return Number.isSafeInteger(uid) && uid > 0 &&
    Number.isSafeInteger(euid) && euid === uid &&
    Number.isSafeInteger(gid) && gid > 0 &&
    Number.isSafeInteger(egid) && egid === gid;
}
export function buildDisposableUnprivilegedSshSandbox(options = {}) {
  const allowedKeys = ["sourceDirectory", "script"];
  if (!options || typeof options !== "object" || Array.isArray(options) ||
      Object.keys(options).length !== allowedKeys.length ||
      !allowedKeys.every((key) => Object.hasOwn(options, key))) {
    refuse("caller cannot provide verifier, owner pin, env, arbitrary commands or authority");
  }
  const { sourceDirectory, script } = options;
  // No caller-supplied UID or effective UID can ever become trusted state.
  // In particular setuid-root processes can have real uid=1000, euid=0.
  // Require REAL and EFFECTIVE credentials for both user and group.
  const identity = {
    uid: process.getuid?.(), euid: process.geteuid?.(),
    gid: process.getgid?.(), egid: process.getegid?.(),
  };
  if (process.platform !== "linux" || !requireUnprivilegedSshSandboxStartup(identity)) {
    refuse("unsafe effective identity: ordinary Linux real/effective UID/GID required");
  }
  if (typeof sourceDirectory !== "string" || !path.isAbsolute(sourceDirectory) ||
      path.normalize(sourceDirectory) !== sourceDirectory ||
      !ALLOWED_SCRIPTS.test(script) || script.includes("..")) {
    refuse("only a canonical source directory and single script basename accepted");
  }
  const real = realpathSync.native(sourceDirectory);
  if (real !== sourceDirectory) refuse("aliased source root not accepted");
  const st = lstatSync(sourceDirectory, { bigint: true });
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== BigInt(identity.uid))
    refuse("non-directory or foreign-owned source");
  const bin = lstatSync(BWRAP);
  if (realpathSync.native(BWRAP) !== BWRAP ||
      !bin.isFile() || bin.uid !== 0 || (bin.mode & 0o022) !== 0) {
    refuse("independently installed unprivileged sandbox executable unavailable");
  }
  for (const directory of ["/", "/usr", "/usr/bin"]) {
    const meta = lstatSync(directory);
    if (!meta.isDirectory() || meta.uid !== 0 || (meta.mode & 0o022) !== 0) {
      refuse("shared writable ancestor of sandbox executable");
    }
  }
  const args = Object.freeze([
    "--die-with-parent", "--new-session", "--unshare-user",
    "--uid", "0", "--gid", "0",
    "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
    "--clearenv",
    "--tmpfs", "/",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--tmpfs", "/root",
    // bwrap v0.11 --ro-bind-fd takes a pre-opened directory handle, rather
    // than reopening an attacker-swappable path after JS validation.
    "--ro-bind-fd", "3", "/workspace",
    "--chdir", "/workspace",
    "--setenv", "PATH", "/usr/bin:/bin",
    "--setenv", "HOME", "/root",
    "--setenv", "LC_ALL", "C",
    "--cap-drop", "ALL",
    "--",
    "/bin/sh", "/workspace/" + script,
  ]);
  // A descriptor is opened at the USE point with O_NOFOLLOW, and compared
  // against the exact inode observed during planning. An attacker may rename
  // the old source path or alter the scripts themselves; bwrap can only mount
  // the fd 3 inode that we deliberately pass, never a late path replacement.
  function run() {
    if (!requireUnprivilegedSshSandboxStartup({
      uid: process.getuid?.(), euid: process.geteuid?.(),
      gid: process.getgid?.(), egid: process.getegid?.(),
    })) refuse("effective identity changed before sandbox execution");
    if (realpathSync.native(sourceDirectory) !== sourceDirectory)
      refuse("source path replaced with an alias before sandbox execution");
    const fd = openSync(sourceDirectory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      const pinned = fstatSync(fd, { bigint: true });
      if (!pinned.isDirectory() || pinned.dev !== st.dev ||
          pinned.ino !== st.ino || pinned.uid !== st.uid ||
          pinned.mode !== st.mode || pinned.gid !== st.gid ||
          pinned.nlink !== st.nlink) {
        refuse("source directory replaced since initial inspection");
      }
      // fd 3 is inherited into the child. bwrap --ro-bind-fd consumes this
      // exact open file description and does not resolve sourceDirectory.
      // --clearenv only runs AFTER execve has already invoked the host ELF
      // loader. A hostile inherited LD_PRELOAD/LD_AUDIT would run a constructor
      // with the host UID BEFORE bwrap can create its sandbox. Supply no
      // inherited environment at execve; bwrap sets the tiny sandbox env itself.
      return spawnSync(BWRAP, args, {
        shell: false, timeout: 10_000, encoding: "utf8", maxBuffer: 8192,
        env: {}, stdio: ["ignore", "pipe", "pipe", fd],
      });
    } finally { closeSync(fd); }
  }
  return Object.freeze({
    executable: BWRAP, args,
    run,
    authority: "DEV_ONLY_UNPRIVILEGED_SANDBOX_NO_NATIVE_ROOT",
    nativeSshdVerified: false, sudoPrivsepVerified: false,
    deployAuthorized: false,
  });
}
