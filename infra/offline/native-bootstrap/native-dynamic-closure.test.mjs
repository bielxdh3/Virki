import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

// No operator root, private signing key, installed verifier or Docker target is
// ever constructed. A fixture manifest is *explicitly* not a trust anchor.
const enabled = process.platform === "linux" && process.getuid?.() === 0 &&
  existsSync("/usr/bin/gcc") && existsSync("/usr/bin/readelf") &&
  existsSync("/usr/bin/node") && existsSync("/root");
const source = path.join(path.dirname(fileURLToPath(import.meta.url)), "native-dynamic-closure.c");
const run = (exe, args = [], env = {}) => spawnSync(exe, args, {
  encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024,
  env: { PATH: "/usr/bin:/bin", ...env },
});
const digest = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const canonical = (p) => realpathSync(p);

const sections = (p) => {
  const ph = run("/usr/bin/readelf", ["-l", p]);
  const dyn = run("/usr/bin/readelf", ["-d", p]);
  assert.equal(ph.status, 0, ph.stderr);
  assert.equal(dyn.status, 0, dyn.stderr);
  const interpreter = ph.stdout.match(/Requesting program interpreter:\s*([^\]]+)\]/u)?.[1];
  const libs = [...dyn.stdout.matchAll(/\(NEEDED\)\s+Shared library:\s*\[([^\]]+)\]/gu)].map((m) => m[1]);
  return { interpreter, libs };
};
const directories = ["/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/lib64"];
const lookup = (basename) => {
  for (const directory of directories) {
    const p = path.join(directory, basename);
    if (existsSync(p)) return canonical(p);
  }
  throw Error("fixture missing installed library " + basename);
};
const makeInventory = (node) => {
  const queue = [canonical(node)];
  const found = new Set();
  const labels = new Map([[canonical(node), "node"]]);
  let loader;
  while (queue.length) {
    const entry = queue.shift();
    if (found.has(entry)) continue;
    found.add(entry);
    const info = sections(entry);
    if (info.interpreter) {
      if (loader && loader !== canonical(info.interpreter)) throw Error("multiple ELF loaders");
      loader = canonical(info.interpreter);
      labels.set(loader, path.basename(info.interpreter));
    }
    for (const name of info.libs) {
      const candidate = lookup(name);
      if (labels.has(candidate) && labels.get(candidate) !== name) {
        throw Error("conflicting SONAME alias " + name);
      }
      labels.set(candidate, name);
      queue.push(candidate);
    }
    if (found.size > 64 || queue.length > 160) throw Error("unexpected large dynamic closure");
  }
  assert.ok(loader, "real Node22 must have PT_INTERP");
  const entries = [canonical(node), loader, ...[...found].filter((p) => p !== canonical(node) && p !== loader)];
  return "VIRKI_DEV_ELF_CLOSURE_V1\n" +
    entries.map((p) => labels.get(p) + " " + p + " " + digest(p)).join("\n") + "\n";
};

test("real Node22 native ELF closure is fully measured, still never executable or authorizing", {
  skip: !enabled && "Linux root GCC/readelf fixture required",
}, (t) => {
  const root = mkdtempSync("/root/virki-elf-closure-fixture-");
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const pins = path.join(root, "operator-inventory.txt");
  const exe = path.join(root, "native-dynamic-closure");
  const compile = run("/usr/bin/gcc", [
    "-static", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
    "-DVIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE=1",
    `-DVIRKI_CLOSURE_INVENTORY="${pins}"`, source, "-o", exe,
  ]);
  assert.equal(compile.status, 0, compile.stderr);
  const elf = run("/usr/bin/readelf", ["-l", exe]);
  assert.equal(elf.status, 0, elf.stderr);
  assert.doesNotMatch(elf.stdout, /INTERP/u);
  const manifest = makeInventory("/usr/bin/node");
  const entries = manifest.trim().split("\n").slice(1);
  assert.ok(entries.length >= 12, "exercise Node and transitive libnode/ICU/crypto libs");
  writeFileSync(pins, manifest, { mode: 0o600 });
  const inspect = (env = {}) => run(exe, [], env);
  const good = inspect();
  assert.equal(good.status, 0, good.stdout + good.stderr);
  assert.match(good.stdout, /DEV_ONLY_REAL_NODE22_ELF_CLOSURE_MEASURED_NO_EXEC_NO_AUTHORITY/u);
  assert.match(good.stdout, /PT_INTERP_PINNED_BYTES_ONLY/u);
  assert.doesNotMatch(good.stdout, /deployAuthorized:true/u);
  const denied = (content, env = {}) => {
    writeFileSync(pins, content);
    const result = inspect(env);
    assert.equal(result.status, 2, result.stdout + result.stderr);
    assert.doesNotMatch(result.stdout, /MEASURED_NO_EXEC/u);
  };
  denied(manifest.replace(/([a-f0-9]{64})/u, "0".repeat(64))); // pinned main bytes wrong
  denied(manifest.split("\n").filter((line) => !line.includes("libnode.so.127")).join("\n"));
  denied(manifest.split("\n").filter((line) => !line.startsWith("ld-linux-x86-64.so.2 ")).join("\n"));
  denied(manifest.replace(/([a-f0-9]{64})\n$/u, "f".repeat(64) + "\n")); // transitive DSO
  denied(manifest.replace("libnode.so.127 ", "libnode.so.126 ")); // wrong DT_NEEDED alias
  denied(manifest.replace("libnode.so.127 ", "libc.so.6 ")); // duplicate SONAME
  denied(manifest.replace("/usr/bin/node ", "/tmp/fake-node ")); // untrusted executable alias
  denied(manifest + "unexpected=trust\n");
  denied(manifest.replace("VIRKI_DEV_ELF_CLOSURE_V1", "VIRKI_DEPLOY_AUTHORIZED"));
  writeFileSync(pins, manifest);
  chmodSync(pins, 0o666);
  assert.equal(inspect().status, 2);
  chmodSync(pins, 0o600);
  assert.equal(inspect({ NODE_OPTIONS: "--require=/tmp/evil" }).status, 2);
  assert.equal(inspect({ LD_AUDIT: "/tmp/evil.so" }).status, 2);
  assert.equal(run(exe, ["--deploy"]).status, 2);
  // Include a root-owned, hash-correct, wrong-soname copied ELF in the
  // fixture to ensure a signed-looking digest is never a dependency binding.
  const replacement = path.join(root, "libnode.so.127");
  copyFileSync("/usr/bin/node", replacement);
  const altered = manifest.replace(/\/usr\/lib\/x86_64-linux-gnu\/libnode\.so\.127 [a-f0-9]{64}/u,
    replacement + " " + digest(replacement));
  assert.notEqual(altered, manifest);
  denied(altered);
  writeFileSync(pins, manifest);
  assert.equal(inspect().status, 0);
});

test("production source never self-issues a signed owner inventory on WSL", {
  skip: !enabled && "Linux root GCC required",
}, (t) => {
  const root = mkdtempSync("/root/virki-elf-closure-fixture-");
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const exe = path.join(root, "native-dynamic-closure");
  const compiled = run("/usr/bin/gcc", [
    "-static", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", source, "-o", exe,
  ]);
  assert.equal(compiled.status, 0, compiled.stderr);
  const result = run(exe);
  assert.equal(result.status, 2, result.stdout + result.stderr);
});
