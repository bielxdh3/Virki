import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  STAGING_NODE_RANGE,
  STAGING_NPM_RANGE,
  sanitizedNpmEnvironment,
  verifyCleanNodeStartup,
  verifyStagingToolchain
} from "./staging-toolchain-preflight.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scriptPath = fileURLToPath(new URL("./staging-toolchain-preflight.mjs", import.meta.url));

test("staging toolchain range exactly matches package.json engines", () => {
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const source = readFileSync(scriptPath, "utf8");
  assert.equal(manifest.engines.node, ">=22.13.0 <23");
  assert.equal(manifest.engines.npm, ">=10.9.3 <11");
  assert.deepEqual(STAGING_NODE_RANGE, { minimum: "22.13.0", maximumExclusive: "23.0.0" });
  assert.deepEqual(STAGING_NPM_RANGE, { minimum: "10.9.3", maximumExclusive: "11.0.0" });
  assert.match(source, /spawnSync\(process\.execPath, \[pinnedNpmCliPath\(\), "--version"\]/u,
    "the preflight must run the npm CLI bundled with the exact Node executable, not resolve npm from PATH");
  assert.doesNotMatch(source, /spawnSync\("npm"/u);
  assert.match(source, /NODE_OPTIONS\|NODE_PATH\|npm_config_/u,
    "npm version probing must ignore ambient Node preloads and npm configuration overrides");
});

test("staging toolchain accepts the exact lower bounds and supported patch releases", () => {
  assert.equal(verifyStagingToolchain({ nodeVersion: "22.13.0", npmVersion: "10.9.3" }), true);
  assert.equal(verifyStagingToolchain({ nodeVersion: "22.22.1", npmVersion: "10.9.9" }), true);
  assert.equal(verifyStagingToolchain({ nodeVersion: "22.23.3", npmVersion: "10.10.0" }), true);
});

test("staging toolchain rejects unsupported Node versions and malformed prereleases", () => {
  for (const nodeVersion of ["22.12.9", "23.0.0", "24.14.1", "22.13", "22.13.0-rc.1", "22.13.0+local", "v22.13.0"]) {
    assert.throws(() => verifyStagingToolchain({ nodeVersion, npmVersion: "10.9.3" }), {
      code: "UNSUPPORTED_NODE_VERSION"
    }, nodeVersion);
  }
});

test("staging toolchain rejects unsupported npm versions and malformed prereleases", () => {
  for (const npmVersion of ["9.2.0", "10.9.2", "11.0.0", "10.9", "10.9.3-rc.1", "10.9.3+local", "v10.9.3"]) {
    assert.throws(() => verifyStagingToolchain({ nodeVersion: "22.20.0", npmVersion }), {
      code: "UNSUPPORTED_NPM_VERSION"
    }, npmVersion);
  }
});

test("staging toolchain refuses preloads and strips inherited npm, Node, and TLS key-log overrides", () => {
  assert.equal(verifyCleanNodeStartup({ execArgv: [], environment: { PATH: "/bin" } }), true);
  for (const [execArgv, environment] of [
    [["--require", "/tmp/injected-preload.cjs"], {}],
    [["--import=/tmp/injected-preload.mjs"], {}],
    [[], { NODE_OPTIONS: "--require=/tmp/injected-preload.cjs" }],
    [[], { NODE_PATH: "/tmp/modules" }]
  ]) {
    assert.throws(() => verifyCleanNodeStartup({ execArgv, environment }), {
      code: "UNTRUSTED_NODE_PRELOAD"
    });
  }
  assert.deepEqual(sanitizedNpmEnvironment({
    PATH: "/bin", NODE_OPTIONS: "--require=bad", NODE_PATH: "/tmp/modules",
    npm_config_userconfig: "/tmp/unsafe", NPM_CONFIG_PREFIX: "/tmp/prefix",
    PGSSLKEYLOGFILE: "/tmp/postgres-secrets.log", SSLKEYLOGFILE: "/tmp/tls-secrets.log"
  }), { PATH: "/bin" });
});

test("staging toolchain CLI fails closed on the real npm child-process result", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-staging-npm-shim-"));
  const npmPath = path.join(directory, process.platform === "win32" ? "npm.cmd" : "npm");
  const pinnedNpmCli = process.platform === "win32"
    ? path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js")
    : realpathSync(path.join(path.dirname(process.execPath), "npm"));
  const actualNpm = spawnSync(process.execPath, [pinnedNpmCli, "--version"], {
    encoding: "utf8",
    env: { ...process.env, PATH: path.dirname(process.execPath) },
    windowsHide: true
  });
  assert.equal(actualNpm.status, 0, actualNpm.stderr);
  let expectedStatus = 0;
  try {
    verifyStagingToolchain({ nodeVersion: process.versions.node, npmVersion: actualNpm.stdout.trim() });
  } catch {
    expectedStatus = 1;
  }
  const run = () => spawnSync(process.execPath, [scriptPath], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PATH: `${directory}${path.delimiter}${process.env.PATH ?? ""}` },
    windowsHide: true
  });
  try {
    writeFileSync(npmPath, process.platform === "win32" ? "@echo off\r\necho 99.0.0\r\n" : "#!/bin/sh\nprintf '%s\\n' '99.0.0'\n");
    if (process.platform !== "win32") chmodSync(npmPath, 0o700);
    const accepted = run();
    assert.equal(accepted.status, expectedStatus,
      "the CLI must use the npm CLI bundled beside the running Node binary, never a PATH shim");
    assert.equal(accepted.stdout, expectedStatus === 0 ? "STAGING_TOOLCHAIN=PASS\n" : "");
    assert.equal(accepted.stderr, expectedStatus === 0 ? "" : "BLOCK:STAGING_TOOLCHAIN\n");

    writeFileSync(npmPath, process.platform === "win32" ? "@echo off\r\necho 9.2.0\r\n" : "#!/bin/sh\nprintf '%s\\n' '9.2.0'\n");
    if (process.platform !== "win32") chmodSync(npmPath, 0o700);
    const rejected = run();
    assert.equal(rejected.status, expectedStatus,
      "changing a PATH shim must not change the pinned npm version result");
    assert.equal(rejected.stdout, expectedStatus === 0 ? "STAGING_TOOLCHAIN=PASS\n" : "");
    assert.equal(rejected.stderr, expectedStatus === 0 ? "" : "BLOCK:STAGING_TOOLCHAIN\n");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
