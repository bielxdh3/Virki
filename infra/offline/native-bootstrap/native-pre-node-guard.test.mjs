import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, copyFileSync, existsSync, linkSync, lstatSync, mkdtempSync,
  readFileSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

// The positive test is a SEPARATE, explicitly nonauthorizing fixture build,
// not an owner installation. No private keys or production paths are read.
const supported = process.platform === "linux" && process.getuid?.() === 0 &&
  existsSync("/root") && existsSync("/usr/bin/gcc");
const current = path.dirname(fileURLToPath(import.meta.url));
const source = path.join(current, "native-pre-node-guard.c");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const run = (exe, args = [], env = {}) => spawnSync(exe, args, {
  encoding: "utf8", env: { PATH: "/usr/bin:/bin", ...env }, timeout: 5000,
});
const compile = (out, args) => {
  const proc = run("/usr/bin/gcc", args.concat(["-o", out]));
  assert.equal(proc.status, 0, proc.stderr);
};

test("TDD native static guard: external roots, ELF and environment refuse before any launch", {
  skip: !supported && "root Linux GCC test only; Windows never serves as a host",
}, async (t) => {
  const root = mkdtempSync("/root/virki-pre-node-guard-fixture-");
  t.after(() => {
    assert.match(root, /^\/root\/virki-pre-node-guard-fixture-[a-zA-Z0-9]+$/u);
    rmSync(root, { recursive: true, force: true });
  });
  const owner = path.join(root, "bootstrap-policy.json");
  const target = path.join(root, "node");
  const pins = path.join(root, "owner-pin.txt");
  const launcher = path.join(root, "native-pre-node-guard");
  const output = path.join(root, "stub.c");
  const benignSource = [
    "#define _GNU_SOURCE",
    "#include <stdio.h>",
    "#include <unistd.h>",
    "#include <linux/capability.h>",
    "#include <sys/prctl.h>",
    "#include <sys/syscall.h>",
    "int main(int n,char**v) {",
    '  if(n!=2 || __builtin_strcmp(v[1],"--version") || getuid()!=65534 ||',
    "      getgid()!=65534 || getgroups(0,NULL)!=0 ||",
    "      prctl(PR_GET_SECUREBITS,0,0,0,0)!=0 ||",
    "      prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1) return 9;",
    "  struct __user_cap_header_struct h = {.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};",
    "  struct __user_cap_data_struct d[2] = {{0},{0}};",
    "  if(syscall(SYS_capget,&h,d)) return 10;",
    "  for(int i=0;i<2;i++) if(d[i].effective || d[i].permitted ||",
    "      d[i].inheritable) return 11;",
    "  for(int cap=0;cap<1024;cap++) {",
    "    int bound=prctl(PR_CAPBSET_READ,cap,0,0,0);",
    "    if(bound<0) break;",
    "    if(bound!=0 || prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,cap,0,0)!=0)",
    "      return 12;",
    "  }",
    '  puts("STATIC_STUB_VERSION_ONLY"); return 0;',
    "}",
  ].join("\n") + "\n";
  writeFileSync(output, benignSource);
  compile(target, ["-static", "-O2", output]);
  writeFileSync(owner, '{"version":1,"mode":"disposable-fake-owner-root"}', { mode: 0o600 });
  const acceptedPins = () => "VIRKI_DEV_NATIVE_GUARD_PIN_V1\n" +
    "bootstrap_sha256=" + sha(readFileSync(owner)) + "\n" +
    "node_sha256=" + sha(readFileSync(target)) + "\n" +
    "launcher_sha256=" + sha(readFileSync(launcher)) + "\n";
  compile(launcher, [
    "-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    "-DVIRKI_TEST_ONLY_ROOT_FIXTURE=1",
    `-DVIRKI_PIN_PATH="${pins}"`, `-DVIRKI_OWNER_PATH="${owner}"`,
    `-DVIRKI_NODE_PATH="${target}"`, `-DVIRKI_LAUNCHER_PATH="${launcher}"`,
    source,
  ]);
  const elf = run("/usr/bin/readelf", ["-l", launcher]);
  assert.equal(elf.status, 0, elf.stderr);
  assert.doesNotMatch(elf.stdout, /INTERP/u);
  writeFileSync(pins, acceptedPins(), { mode: 0o600 });
  const invoke = (env, args = []) => run(launcher, args, env);
  const blocked = (env = {}, args = []) => {
    const result = invoke(env, args);
    assert.equal(result.status, 2, result.stdout + result.stderr);
    assert.doesNotMatch(result.stdout, /STATIC_STUB_VERSION_ONLY/u);
  };
  const accepted = invoke({});
  assert.equal(accepted.status, 0, accepted.stdout + accepted.stderr);
  assert.match(accepted.stdout, /STATIC_STUB_VERSION_ONLY/u);
  assert.match(accepted.stdout, /DEV_ONLY_STATIC_BYTE_PROBE_NO_RELEASE_AUTHORITY/u);

  // TDD adversary: force Linux SECBIT_NO_SETUID_FIXUP (setuid no longer
  // removes capabilities) and a permitted+inheritable+ambient cap. The helper
  // asserts that both hostile kernel states really exist BEFORE execing the
  // guard, and fails the test if this WSL kernel cannot construct them.
  const hostileSource = path.join(root, "inject-caps.c");
  const hostile = path.join(root, "inject-caps");
  writeFileSync(hostileSource, `
#define _GNU_SOURCE
#include <linux/capability.h>
#include <linux/securebits.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
extern char **environ;
int main(int argc, char **argv) {
  if (argc != 3 || getuid() != 0 || geteuid() != 0) return 91;
  struct __user_cap_header_struct header = {
    .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0
  };
  struct __user_cap_data_struct values[2] = {{0}, {0}};
  if (syscall(SYS_capget, &header, values)) return 92;
  if (strcmp(argv[2], "no-setpcap") == 0) {
    if (prctl(PR_CAPBSET_DROP, CAP_SETPCAP, 0, 0, 0) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 100;
    const unsigned capset_bit = 1U << (CAP_SETPCAP % 32);
    values[CAP_SETPCAP / 32].effective &= ~capset_bit;
    values[CAP_SETPCAP / 32].permitted &= ~capset_bit;
    if (syscall(SYS_capset, &header, values) ||
        syscall(SYS_capget, &header, values) ||
        (values[CAP_SETPCAP / 32].effective & capset_bit) ||
        prctl(PR_CAPBSET_READ, CAP_SETPCAP, 0, 0, 0) != 0)
      return 101;
  } else {
  const unsigned cap = CAP_NET_BIND_SERVICE;
  values[cap / 32].inheritable |= 1U << (cap % 32);
  if (syscall(SYS_capset, &header, values)) return 93;
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) return 94;
  if (strcmp(argv[2], "securebits") == 0) {
    if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP, 0, 0, 0)) return 95;
    if (prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != SECBIT_NO_SETUID_FIXUP)
      return 96;
  } else if (strcmp(argv[2], "locked-securebits") == 0) {
    const int locked = SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED;
    if (prctl(PR_SET_SECUREBITS, locked, 0, 0, 0) ||
        prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != locked) return 102;
  } else if (strcmp(argv[2], "ambient") != 0) return 97;
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 1) return 98;
  }
  char *args[] = {argv[1], NULL};
  char *env[] = {"PATH=/usr/bin:/bin", NULL};
  execve(argv[1], args, env);
  return 99;
}
`);
  compile(hostile, ["-static", "-O2", "-Wall", "-Wextra", "-Werror", hostileSource]);
  for (const mode of ["securebits", "locked-securebits", "ambient", "no-setpcap"]) {
    const hostileRun = run(hostile, [launcher, mode]);
    assert.equal(hostileRun.status, 2,
      mode + " should fail closed after hostile capabilities, but returned: " +
      hostileRun.stdout + hostileRun.stderr);
    assert.doesNotMatch(hostileRun.stdout, /STATIC_STUB_VERSION_ONLY/u);
  }

  blocked({ NODE_OPTIONS: "--require=/tmp/evil" });
  blocked({ LD_PRELOAD: "/tmp/evil.so" });
  blocked({ LD_AUDIT: "/tmp/evil.so" });
  blocked({ V8_FLAGS: "--allow-natives-syntax" });
  blocked({}, ["--do-not-run-unreviewed-code"]);
  renameSync(pins, pins + ".old"); blocked();
  renameSync(pins + ".old", pins);
  writeFileSync(pins, acceptedPins() + "override=true\n"); blocked();
  writeFileSync(pins, acceptedPins());
  chmodSync(pins, 0o666); blocked();
  chmodSync(pins, 0o600);
  chmodSync(root, 0o777); blocked(); chmodSync(root, 0o700);
  writeFileSync(pins, acceptedPins().replace(/launcher_sha256=[a-f0-9]{64}/u,
    "launcher_sha256=" + "0".repeat(64))); blocked();
  writeFileSync(pins, acceptedPins());
  writeFileSync(owner, '{"version":1,"mode":"changed-owner-root"}'); blocked();
  writeFileSync(owner, '{"version":1,"mode":"disposable-fake-owner-root"}');
  writeFileSync(target, Buffer.concat([readFileSync(target), Buffer.from([0])]));
  blocked();
  compile(target, ["-static", "-O2", output]);
  writeFileSync(pins, acceptedPins());
  const dynamic = path.join(root, "dynamic");
  compile(dynamic, ["-O2", output]);
  copyFileSync(dynamic, target);
  writeFileSync(pins, acceptedPins());
  blocked(); // A valid digest cannot make PT_INTERP / dynamic linker trusted.
  compile(target, ["-static", "-O2", output]);
  writeFileSync(pins, acceptedPins());
  const hardlink = target + ".hardlink";
  linkSync(target, hardlink); blocked(); unlinkSync(hardlink);
  const moved = path.join(root, "original-node");
  renameSync(target, moved);
  symlinkSync(moved, target); blocked(); // Inode and symlink refusal.
  rmSync(target); renameSync(moved, target);
  assert.equal(lstatSync(pins).mode & 0o777, 0o600);
  assert.equal(invoke({}).status, 0);
  writeFileSync(output, [
    "#include <stdio.h>", "#include <unistd.h>", "#include <signal.h>",
    "int main(void) {",
    ' printf("WATCHDOG_CHILD_STARTED:%ld\\n",(long)getpid()); fflush(stdout);',
    " signal(SIGALRM,SIG_IGN); for (;;) sleep(1);",
    "}",
  ].join("\n") + "\n");
  compile(target, ["-static", "-O2", output]);
  writeFileSync(pins, acceptedPins());
  const hung = invoke({});
  assert.equal(hung.status, 2, hung.stdout + hung.stderr);
  assert.doesNotMatch(hung.stdout, /DEV_ONLY_STATIC_BYTE_PROBE_NO_RELEASE_AUTHORITY/u);
  // Parent SIGKILL must never leave a live static diagnostic child. The
  // child ignores SIGALRM so the kernel parent-death signal is essential.
  const watchdog = await new Promise((resolve, reject) => {
    const main = spawn(launcher, [], {
      env: { PATH: "/usr/bin:/bin" }, stdio: ["ignore", "pipe", "pipe"],
    });
    let childPid = 0;
    let buffer = "";
    let killedParent = false;
    const started = Date.now();
    let finished = false;
    const ended = () => {
      if (!childPid) return false;
      try {
        const proc = readFileSync(`/proc/${childPid}/stat`, "utf8");
        return /\)\s+[ZX]/u.test(proc); // zombie/dead, no longer running.
      } catch (error) {
        if (error.code === "ENOENT") return true;
        throw error;
      }
    };
    const done = (error) => {
      if (finished) return;
      finished = true;
      clearInterval(check);
      clearTimeout(deadline);
      if (main.exitCode === null) main.kill("SIGKILL");
      if (error) reject(error);
      else resolve({ childPid, elapsedMs: Date.now() - started });
    };
    const check = setInterval(() => {
      if (killedParent && ended()) done();
    }, 25);
    const deadline = setTimeout(() => {
      if (childPid) {
        try { process.kill(childPid, "SIGKILL"); }
        catch { /* already gone: intentional bounded cleanup only */ }
      }
      done(new Error("orphaned static diagnostic child survived parent SIGKILL"));
    }, 2500);
    main.stdout.on("data", (part) => {
      buffer += part.toString();
      const found = buffer.match(/WATCHDOG_CHILD_STARTED:(\d+)/u);
      if (found && !killedParent) {
        childPid = Number(found[1]);
        killedParent = main.kill("SIGKILL");
      }
    });
    main.on("error", (error) => done(error));
  });
  assert.ok(watchdog.childPid > 1);
  assert.ok(watchdog.elapsedMs < 2500, "orphan must die within bounded deadline");
  writeFileSync(output, benignSource);
  compile(target, ["-static", "-O2", output]);
  writeFileSync(pins, acceptedPins());
  assert.equal(invoke({}).status, 0);
});

test("production guard rejects WSL, arbitrary flags and uninstalled roots by default", {
  skip: !supported && "root Linux GCC test only",
}, (t) => {
  const root = mkdtempSync("/root/virki-pre-node-guard-fixture-");
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const exe = path.join(root, "native-pre-node-guard");
  compile(exe, ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    source]);
  const result = run(exe);
  assert.equal(result.status, 2, result.stderr);
  assert.doesNotMatch(result.stdout, /DEV_ONLY_STATIC_BYTE_PROBE_NO_RELEASE_AUTHORITY/u);
  assert.equal(run(exe, ["--any-flag"]).status, 2);
});
