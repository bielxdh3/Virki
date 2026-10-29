import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, renameSync, symlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildDisposableUnprivilegedSshSandbox,
  requireUnprivilegedSshSandboxStartup,
} from "./owner-ssh-unprivileged-namespace.mjs";

const linux = process.platform === "linux" && process.getuid?.() !== 0;
const BWRAP = "/usr/bin/bwrap";
function lab(t) {
  const folder = mkdtempSync(path.join(os.tmpdir(), "virki-safe-ssh-ns-"));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  chmodSync(folder, 0o700);
  return folder;
}

test("RED/attack: a source directory swapped after validation cannot bind a different readable private directory", { skip: !linux }, (t) => {
  const parent = lab(t);
  const sourceDirectory = path.join(parent, "workspace");
  const privateDirectory = path.join(parent, "unrelated-private");
  mkdirSync(sourceDirectory, { mode: 0o700 });
  mkdirSync(privateDirectory, { mode: 0o700 });
  writeFileSync(path.join(sourceDirectory, "entry.sh"), "#!/bin/sh\necho ORIGINAL_SOURCE\n");
  writeFileSync(path.join(privateDirectory, "secret.txt"), "W20_HOST_PRIVATE_MARKER");
  writeFileSync(path.join(privateDirectory, "entry.sh"), "#!/bin/sh\ncat /workspace/secret.txt\n");
  const planned = buildDisposableUnprivilegedSshSandbox({ sourceDirectory, script: "entry.sh" });
  renameSync(sourceDirectory, path.join(parent, "original-saved"));
  symlinkSync(privateDirectory, sourceDirectory);
  assert.throws(() => planned.run(), /alias|replaced/u,
    "swapping the directory for a symlink must be refused before any bwrap child");
});

test("inode guard rejects a real-directory swap without symlinks before bwrap can mount it", { skip: !linux }, (t) => {
  const parent = lab(t);
  const sourceDirectory = path.join(parent, "source");
  const foreignDirectory = path.join(parent, "foreign");
  mkdirSync(sourceDirectory, { mode: 0o700 });
  mkdirSync(foreignDirectory, { mode: 0o700 });
  writeFileSync(path.join(sourceDirectory, "entry.sh"), "#!/bin/sh\necho ORIGINAL\n");
  writeFileSync(path.join(foreignDirectory, "entry.sh"), "#!/bin/sh\necho FOREIGN_PRIVATE\n");
  const planned = buildDisposableUnprivilegedSshSandbox({ sourceDirectory, script: "entry.sh" });
  renameSync(sourceDirectory, path.join(parent, "saved"));
  renameSync(foreignDirectory, sourceDirectory);
  assert.throws(() => planned.run(), /source directory replaced/u);
});

test("concurrent directory rename after source FD is opened cannot alter the native mount", { skip: !linux }, async (t) => {
  const parent = lab(t);
  const sourceDirectory = path.join(parent, "source");
  const privateDirectory = path.join(parent, "private");
  mkdirSync(sourceDirectory, { mode: 0o700 });
  mkdirSync(privateDirectory, { mode: 0o700 });
  writeFileSync(path.join(sourceDirectory, "entry.sh"), "#!/bin/sh\nsleep 0.2\necho REAL_SOURCE_DIR\n");
  writeFileSync(path.join(privateDirectory, "entry.sh"), "#!/bin/sh\necho PRIVATE_DIR\n");
  const planned = buildDisposableUnprivilegedSshSandbox({ sourceDirectory, script: "entry.sh" });
  const helperCode = `
    const fs = require('node:fs');
    const [source, moved, privateDir, resultFile] = process.argv.slice(1);
    setTimeout(() => {
      try {
        fs.renameSync(source, moved);
        fs.symlinkSync(privateDir, source);
        fs.writeFileSync(resultFile, 'SWAPPED');
      } catch (error) { fs.writeFileSync(resultFile, 'ERROR:' + error.code); }
    }, 40);
    setTimeout(() => process.exit(0), 250);
  `;
  const moved = path.join(parent, "source-moved");
  const evidence = path.join(parent, "attack-result");
  const attacker = spawn(process.execPath, ["-e", helperCode,
    sourceDirectory, moved, privateDirectory, evidence], { stdio: "ignore" });
  t.after(() => { try { attacker.kill(); } catch { /* already completed */ } });
  const result = planned.run();
  if (result.error?.code === "ENOENT" || result.stderr?.includes("Creating new namespace failed"))
    return t.skip("unprivileged namespaces unavailable; never fall back to host root");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /REAL_SOURCE_DIR/u);
  assert.doesNotMatch(result.stdout, /PRIVATE_DIR/u);
  await new Promise((resolve, reject) => {
    if (attacker.exitCode !== null) return resolve();
    attacker.once("exit", resolve);
    attacker.once("error", reject);
  });
  assert.equal(readFileSync(evidence, "utf8"), "SWAPPED", "attacker must really swap while the original script executes");
});

test("RED/attacker ELF constructor via inherited LD_PRELOAD cannot execute in host bwrap before --clearenv", { skip: !linux }, (t) => {
  const folder = lab(t);
  const sourceDirectory = path.join(folder, "source");
  mkdirSync(sourceDirectory, { mode: 0o700 });
  writeFileSync(path.join(sourceDirectory, "entry.sh"), "#!/bin/sh\necho NAMESPACE_EXECUTED\n");
  const payload = path.join(folder, "constructor.c");
  const library = path.join(folder, "constructor.so");
  const marker = path.join(folder, "host-pre-namespace-loader-marker");
  writeFileSync(payload, `
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__((constructor))
static void witness_loader_entry(void) {
  char exe[PATH_MAX];
  ssize_t count = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (count < 0 || (size_t)count >= sizeof(exe)) return;
  exe[count] = '\\0';
  /* Only flag the ELF loader executing in bwrap itself. The parent Node
   * subprocess also inherits LD_PRELOAD but must not count as the exploit. */
  if (strcmp(exe, "/usr/bin/bwrap") != 0) return;
  const char *marker = getenv("VIRKI_W20_LOADER_MARKER");
  if (marker == NULL) return;
  int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) return;
  char note[80];
  int size = snprintf(note, sizeof(note), "HOST_PRE_NAMESPACE_LOADER_UID=%lu\\n",
    (unsigned long)getuid());
  if (size > 0) (void)write(fd, note, (size_t)size);
  (void)close(fd);
}
`);
  const compile = spawnSync("/usr/bin/gcc", ["-shared", "-fPIC", "-Wall", "-Wextra",
    "-Werror", "-o", library, payload], { encoding: "utf8", timeout: 10000 });
  assert.equal(compile.status, 0, compile.stderr);
  // Positive control proves this actual native library really runs a
  // constructor in host bwrap before any sandbox setup. The marker is a
  // disposable file under the ordinary unprivileged test user's own /tmp.
  const controlMarker = path.join(folder, "control-host-loader-marker");
  const vulnerableControl = spawnSync(BWRAP, ["--version"], {
    encoding: "utf8", timeout: 10000, shell: false,
    env: { LD_PRELOAD: library, VIRKI_W20_LOADER_MARKER: controlMarker },
  });
  assert.equal(vulnerableControl.status, 0, vulnerableControl.stderr);
  assert.match(readFileSync(controlMarker, "utf8"),
    new RegExp(`^HOST_PRE_NAMESPACE_LOADER_UID=${process.getuid()}\\n$`, "u"),
    "host-side native loader exploit must be live for this regression to count");
  const attackerScript = `
    import { buildDisposableUnprivilegedSshSandbox } from ${JSON.stringify(
      new URL("./owner-ssh-unprivileged-namespace.mjs", import.meta.url).href)};
    const plan = buildDisposableUnprivilegedSshSandbox({
      sourceDirectory: process.argv[1], script: "entry.sh"
    });
    const result = plan.run();
    process.stdout.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    process.exit(result.status ?? 99);
  `;
  const attack = spawnSync(process.execPath, ["--input-type=module", "-e",
    attackerScript, sourceDirectory], {
    encoding: "utf8", shell: false, timeout: 10000,
    env: { ...process.env, LD_PRELOAD: library,
      LD_LIBRARY_PATH: folder, LD_AUDIT: "", NODE_OPTIONS: "",
      VIRKI_W20_LOADER_MARKER: marker },
  });
  assert.equal(attack.status, 0, attack.stderr);
  assert.match(attack.stdout, /NAMESPACE_EXECUTED/u);
  assert.equal(existsSync(marker), false,
    "LD_PRELOAD must not run its host-UID constructor in bwrap before namespace setup");
});

test("no project-owned script runs with actual host root before namespace entry", () => {
  assert.equal(requireUnprivilegedSshSandboxStartup({
    uid: 0, euid: 0, gid: 0, egid: 0,
  }), false);
  assert.equal(requireUnprivilegedSshSandboxStartup({
    uid: 1000, euid: 1000, gid: 1000, egid: 1000,
  }), true);
  assert.equal(requireUnprivilegedSshSandboxStartup({
    uid: 1000, euid: 0, gid: 1000, egid: 1000,
  }), false, "setuid-root effective UID must deny even when real UID is 1000");
  assert.equal(requireUnprivilegedSshSandboxStartup({
    uid: 1000, euid: 1000, gid: 1000, egid: 0,
  }), false, "setgid-root effective GID must deny even when real GID is 1000");
  assert.throws(() => buildDisposableUnprivilegedSshSandbox({
    sourceDirectory: "/tmp/attacker", script: "attack.sh", euid: 0,
  }), /caller cannot provide/i);
});

test("a real-UID 1000 launcher rejects mocked effective-root UID/GID before sandbox", {
  skip: !linux,
}, (t) => {
  const folder = lab(t);
  writeFileSync(path.join(folder, "entry.sh"), "#!/bin/sh\nexit 0\n");
  for (const mutation of ["geteuid", "getegid"]) {
    const source = `
      import { buildDisposableUnprivilegedSshSandbox } from ${JSON.stringify(
        new URL("./owner-ssh-unprivileged-namespace.mjs", import.meta.url).href)};
      process.${mutation} = () => 0;
      try {
        buildDisposableUnprivilegedSshSandbox({
          sourceDirectory: process.argv[1], script: "entry.sh"
        });
        process.exit(99);
      } catch (err) {
        process.stdout.write(String(err.message));
        process.exit(0);
      }
    `;
    const result = spawnSync(process.execPath, ["--input-type=module", "-e",
      source, folder], { encoding: "utf8", shell: false, timeout: 5000 });
    assert.equal(result.status, 0, result.stderr + " " + mutation);
    assert.match(result.stdout, /unsafe effective identity/u,
      "rejection must be at effective-privilege gate, not argument-schema mismatch");
  }
});

test("argv starts with trusted bwrap, isolates user/pid/net/FS and denies any host or candidate trust pin", {
  skip: !linux,
}, (t) => {
  const sourceDirectory = lab(t);
  writeFileSync(path.join(sourceDirectory, "attack.sh"), "#!/bin/sh\nexit 2\n");
  const { executable, args, authority } = buildDisposableUnprivilegedSshSandbox({
    sourceDirectory, script: "attack.sh",
  });
  assert.equal(executable, BWRAP);
  assert.equal(authority, "DEV_ONLY_UNPRIVILEGED_SANDBOX_NO_NATIVE_ROOT");
  for (const value of ["--unshare-user", "--unshare-pid", "--unshare-net",
    "--unshare-ipc", "--unshare-uts", "--new-session", "--die-with-parent",
    "--clearenv", "--ro-bind", "--ro-bind-fd", "--tmpfs", "--proc", "--dev"]) {
    assert.ok(args.includes(value), `missing isolation primitive ${value}`);
  }
  assert.equal(args[args.indexOf("--ro-bind") + 1], "/usr");
  assert.deepEqual(args.slice(args.indexOf("--ro-bind-fd") + 1, args.indexOf("--ro-bind-fd") + 3), ["3", "/workspace"]);
  assert.ok(!args.includes(sourceDirectory));
  assert.ok(args.includes("/workspace/attack.sh"));
  assert.ok(!args.includes("/bin/bash"));
  assert.ok(!args.includes("/root/virki-sshd-e2e"));
  assert.ok(!args.includes("/mnt/e"));
  assert.ok(!args.includes("785e473"));
  assert.ok(!args.includes("root-sudo-e2e-verified"));
  assert.throws(() => buildDisposableUnprivilegedSshSandbox({
    sourceDirectory, script: "../attack.sh",
  }));
  assert.throws(() => buildDisposableUnprivilegedSshSandbox({
    sourceDirectory, script: "attack.sh",
    ownerPin: "caller-key",
  }));
});

test("ADVERSARIAL swap: untrusted startup executes only after bwrap and cannot mutate host sentinel", {
  skip: !linux,
}, (t) => {
  const sourceDirectory = lab(t);
  const script = path.join(sourceDirectory, "attack.sh");
  const sentinelFolder = lab(t);
  const sentinel = path.join(sentinelFolder, "must-not-change");
  writeFileSync(sentinel, "ORIGINAL");
  writeFileSync(script, "#!/bin/sh\nexit 0\n");
  const planned = buildDisposableUnprivilegedSshSandbox({
    sourceDirectory, script: "attack.sh",
  });
  // Swap AFTER construction, BEFORE execution. A tool that measures untrusted
  // bytes but then runs the worktree as *host root* would be vulnerable here.
  // The sandbox permits arbitrary malicious fixture code only after isolation.
  writeFileSync(script, `#!/bin/sh
id -u
test ! -e /mnt/e/Virki && echo HOST_MNT_HIDDEN
test ! -e ${sentinel} && echo SENTINEL_HIDDEN
printf INJECTED > ${sentinel} 2>/dev/null && exit 55
echo ATTACKER_DENIED
`);
  const result = planned.run();
  if (result.error?.code === "ENOENT" ||
      result.stderr?.includes("Creating new namespace failed"))
    return t.skip("unprivileged user namespaces unavailable; no unsafe root fallback");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^0$/mu, "sandboxed userns UID is virtual root");
  assert.match(result.stdout, /HOST_MNT_HIDDEN/u);
  assert.match(result.stdout, /SENTINEL_HIDDEN/u);
  assert.match(result.stdout, /ATTACKER_DENIED/u);
  assert.equal(readFileSync(sentinel, "utf8"), "ORIGINAL");
});

test("no suid escalation, host mount, root sudo, SSH state or network inside sandbox", {
  skip: !linux,
}, (t) => {
  const sourceDirectory = lab(t);
  const script = path.join(sourceDirectory, "probe.sh");
  writeFileSync(script, `#!/bin/sh
set -eu
cat /proc/self/uid_map
test ! -e /etc/shadow
test ! -e /home
test ! -e /mnt/e/Virki
test ! -e /run/sshd
test ! -e /var/run/docker.sock
test -d /tmp
test -d /root
test ! -e /root/.ssh
echo DEV_NO_HOST_ROOT
`);
  const planned = buildDisposableUnprivilegedSshSandbox({
    sourceDirectory, script: "probe.sh",
  });
  const result = planned.run();
  if (result.error?.code === "ENOENT" ||
      result.stderr?.includes("Creating new namespace failed"))
    return t.skip("unprivileged user namespaces unavailable; no unsafe root fallback");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /DEV_NO_HOST_ROOT/u);
  // Kernel maps namespace root to the UNPRIVILEGED host UID, never host 0.
  const first = result.stdout.split("\n")[0].trim().split(/\s+/u);
  assert.equal(first[0], "0");
  assert.equal(Number(first[1]), process.getuid());
  assert.notEqual(Number(first[1]), 0);
});

test("adversarial imported Node ESM closure cannot write host files or escape private mount", {
  skip: !linux,
}, (t) => {
  const folder = lab(t);
  const external = lab(t);
  const sentinel = path.join(external, "host-immutable");
  writeFileSync(sentinel, "PRESERVED");
  const script = path.join(folder, "start.sh");
  const imported = path.join(folder, "late-import.mjs");
  writeFileSync(script, "#!/bin/sh\nexec /usr/bin/node /workspace/entry.mjs\n");
  writeFileSync(path.join(folder, "entry.mjs"),
    'await import("./late-import.mjs");\n');
  writeFileSync(imported, 'process.stdout.write("BENIGN\\n");\n');
  const planned = buildDisposableUnprivilegedSshSandbox({
    sourceDirectory: folder, script: "start.sh",
  });
  // A malicious same-UID actor alters a *transitive import* after the command
  // was planned, not just the shell entry. No privileged host code executes.
  writeFileSync(imported, `import { writeFileSync } from "node:fs";
  try { writeFileSync(${JSON.stringify(sentinel)}, "COMPROMISED"); }
  catch { process.stdout.write("HOST_IMPORT_WRITE_DENIED\\n"); }
  process.stdout.write("UNTRUSTED_ESM_EXECUTED_WITHIN_NAMESPACE\\n");
  `);
  const result = planned.run();
  if (result.error?.code === "ENOENT" ||
      result.stderr?.includes("Creating new namespace failed"))
    return t.skip("unprivileged userns not available; no unsafe fallback");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /HOST_IMPORT_WRITE_DENIED/u);
  assert.match(result.stdout, /UNTRUSTED_ESM_EXECUTED_WITHIN_NAMESPACE/u);
  assert.equal(readFileSync(sentinel, "utf8"), "PRESERVED");
});
