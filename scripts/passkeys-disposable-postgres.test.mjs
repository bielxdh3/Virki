import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
        let owner;
        return { subprocessEnv: { DOCKER_HOST: "npipe:////./pipe/dockerDesktopLinuxEngine" },
          invoke(args) {
            appendFileSync(process.env.VIRKI_FAKE_LOG, args[0] + "\\n");
            const scenario = process.env.VIRKI_FAKE_CASE;
            const ok = (stdout = "ok") => ({ status: 0, stdout });
            if (args[0] === "run") {
              owner = args[args.indexOf("--label") + 1].split("=").at(-1);
              return scenario === "run-error" ? { status: 1, stderr: "lost ack" } : ok();
            }
            if (args[0] === "port") return ok("127.0.0.1:5432");
            if (args[0] === "inspect" && args.includes("{{.State.Health.Status}}")) return ok("healthy");
            if (args[0] === "inspect") {
              if (scenario === "foreign") return ok("someone-else");
              if (scenario === "denied") return { status: 1, stderr: "permission denied" };
              if (scenario === "absent") return { status: 1,
                stderr: "Error: No such object: " + args.at(-1) + "\\n" };
              return ok(owner);
            }
            if (args[0] === "rm" && scenario === "rm-error") return { status: 1 };
            return ok();
          } };
      }
    `);
    for (const [scenario, code, remove] of [
      ["owned", 0, true], ["absent", 0, false],
      ["foreign", 1, false], ["denied", 1, false],
      ["run-error", 1, true], ["rm-error", 1, true]
    ]) {
      const log = join(root, scenario + ".txt");
      const result = spawnSync(process.execPath, [runner], { cwd: root, encoding: "utf8",
        windowsHide: true, timeout: 10_000,
        env: { ...process.env, VIRKI_FAKE_CASE: scenario, VIRKI_FAKE_LOG: log,
          DOCKER_HOST: "tcp://production.internal:2376", DOCKER_CONTEXT: "production" } });
      assert.equal(result.error, undefined, scenario);
      assert.equal(result.status, code, scenario + ": cleanup must fail closed");
      const calls = readFileSync(log, "utf8").trim().split(/\r?\n/u);
      assert.ok(calls.includes("run") && calls.includes("inspect"), scenario);
      assert.equal(calls.includes("rm"), remove, scenario);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
