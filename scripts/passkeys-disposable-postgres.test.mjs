import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createAdmittedOidcDockerClient } from "./lib/disposable-docker-session.mjs";

test("passkeys Docker admission pins local engine under hostile remote context", () => {
  const calls = [];
  const docker = createAdmittedOidcDockerClient({
    platform: "win32", nativeArch: "x64",
    env: { DOCKER_HOST: "tcp://prod.internal:2376", DOCKER_CONTEXT: "production",
      DOCKER_TLS_VERIFY: "1", VIRKI_OIDC_DOCKER_BINARY: "evil-docker" },
    spawn: (binary, args, options) => {
      calls.push({ binary, args, env: options.env });
      return { status: 0, stdout: args[2] === "version" ? "linux|amd64" : "ok" };
    }
  });
  docker.invoke(["run", "--name", "fake"]);
  docker.invoke(["rm", "--force", "fake"]);
  assert.equal(calls.length, 3);
  for (const c of calls) {
    assert.equal(c.binary, "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe");
    assert.deepEqual(c.args.slice(0, 2), ["--host", "npipe:////./pipe/dockerDesktopLinuxEngine"]);
    assert.equal(c.env.DOCKER_HOST, "npipe:////./pipe/dockerDesktopLinuxEngine");
    assert.equal(c.env.DOCKER_CONTEXT, undefined);
    assert.equal(c.env.DOCKER_TLS_VERIFY, undefined);
  }
  assert.throws(() => createAdmittedOidcDockerClient({
    platform: "linux", nativeArch: "x64",
    env: { DOCKER_HOST: "ssh://production" }, spawn: () => { throw Error("unexpected Docker"); }
  }), /Disposable Docker session refused/u);
});

test("passkeys runner cleanup refuses foreign ownership and unknown Docker state", () => {
  const root = mkdtempSync(join(tmpdir(), "virki-passkeys-fake-docker-"));
  try {
    const runner = join(root, "scripts", "passkeys-disposable-postgres.mjs");
    const fakeClient = join(root, "scripts", "lib", "disposable-docker-session.mjs");
    mkdirSync(dirname(fakeClient), { recursive: true });
    const source = readFileSync(fileURLToPath(new URL("./passkeys-disposable-postgres.mjs", import.meta.url)), "utf8");
    assert.match(source, /import \{ spawnSync \} from "node:child_process";/u);
    assert.match(source, /createRequire\(import.meta.url\).resolve\("tsx\/cli"\)/u);
    writeFileSync(runner, source
      .replace('import { spawnSync } from "node:child_process";',
        'import { spawnSync } from "./fake-child.mjs";')
      .replace('createRequire(import.meta.url).resolve("tsx/cli")', '"fake-tsx"'));
    writeFileSync(join(root, "package.json"), '{"type":"module"}\n');
    writeFileSync(join(root, "scripts", "fake-child.mjs"),
      'export function spawnSync() { return { status: 0 }; }\n');
    writeFileSync(fakeClient, `
      import { appendFileSync } from "node:fs";
      export function createAdmittedOidcDockerClient() {
        let owner, name, removed = false, inspectCount = 0;
        const cid = "a".repeat(64);
        const otherCid = "b".repeat(64);
        const absent = (target) => ({ status: 1,
          stderr: "Error: No such object: " + target + "\\n" });
        return { subprocessEnv: { DOCKER_HOST: "npipe:////./pipe/dockerDesktopLinuxEngine" },
          invoke(args) {
            appendFileSync(process.env.VIRKI_FAKE_LOG, args[0] + "\\n");
            const scenario = process.env.VIRKI_FAKE_CASE;
            const ok = (stdout = "ok") => ({ status: 0, stdout });
            if (args[0] === "run") {
              name = args[args.indexOf("--name") + 1];
              owner = args[args.indexOf("--label") + 1].split("=").at(-1);
              return ["run-error", "late-create"].includes(scenario)
                ? { status: 1, stderr: "lost ack" } : ok(cid);
            }
            if (args[0] === "port") return ok("127.0.0.1:5432");
            if (args[0] === "inspect" && args.includes("{{.State.Health.Status}}")) return ok("healthy");
            if (args[0] === "inspect") {
              inspectCount += 1;
              if (scenario === "foreign") return ok(cid + "|/" + name + "|someone-else");
              if (scenario === "denied") return { status: 1, stderr: "permission denied" };
              if (["absent", "late-create"].includes(scenario) || (removed && scenario !== "still-present")) {
                return absent(args.at(-1));
              }
              if (scenario === "id-swap") return ok(otherCid + "|/" + name + "|" + owner);
              if (scenario === "name-swap" && inspectCount > 1) {
                return ok(cid + "|/wrong-name|" + owner);
              }
              return ok(cid + "|/" + name + "|" + owner);
            }
            if (args[0] === "rm" && scenario === "rm-error") return { status: 1 };
            if (args[0] === "rm") removed = true;
            return ok();
          } };
      }
    `);
    for (const [scenario, code, remove] of [
      ["owned", 0, true], ["absent", 0, false],
      ["foreign", 1, false], ["denied", 1, false],
      ["run-error", 1, true], ["late-create", 1, false],
      ["rm-error", 1, true], ["id-swap", 1, false],
      ["name-swap", 1, false], ["still-present", 1, true]
    ]) {
      const log = join(root, scenario + ".txt");
      const receiptDir = join(root, ".virki-mission-tmp", "passkeys-docker-recovery");
      mkdirSync(receiptDir, { recursive: true });
      const prior = new Set(readdirSync(receiptDir, { withFileTypes: true }).map((entry) => entry.name));
      const result = spawnSync(process.execPath, [runner], { cwd: root, encoding: "utf8",
        windowsHide: true, timeout: 10_000,
        env: { ...process.env, VIRKI_FAKE_CASE: scenario, VIRKI_FAKE_LOG: log,
          DOCKER_HOST: "tcp://production.internal:2376", DOCKER_CONTEXT: "production" } });
      assert.equal(result.error, undefined, scenario);
      assert.equal(result.status, code, scenario + ": cleanup must fail closed");
      const calls = readFileSync(log, "utf8").trim().split(/\r?\n/u);
      assert.ok(calls.includes("run") && calls.includes("inspect"), scenario);
      assert.equal(calls.includes("rm"), remove, scenario);
      const created = readdirSync(receiptDir).filter((file) => !prior.has(file));
      assert.equal(created.length, 1, scenario + ": one durable reconciliation receipt");
      const journal = readFileSync(join(receiptDir, created[0]), "utf8")
        .trim().split(/\r?\n/u).map(JSON.parse);
      assert.equal(journal[0].stage, "RUN_PENDING", scenario);
      if (scenario === "late-create") {
        assert.match(journal.at(-1).stage, /^RECONCILIATION_REQUIRED:/u);
        assert.match(result.stderr, /reconcile.*\.jsonl/u);
      } else if (["owned", "run-error"].includes(scenario)) {
        assert.equal(journal.at(-1).stage, "CLEANUP_CONFIRMED", scenario);
      }
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
