import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildChromiumEnvironment, buildServiceEnvironment, getServiceCommand, platformEnvironmentVariableNames } from "./isolated-service.mjs";

const repositoryRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));

test("Playwright loads E2E config, setup, and OIDC spec through their ESM entrypoints", () => {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "bielos-playwright-loader-"));
  try {
    const configPath = join(temporaryDirectory, "playwright.config.mjs");
    const config = {
      globalSetup: resolve(repositoryRoot, "scripts/e2e/global-setup.mts"),
      testDir: resolve(repositoryRoot, "e2e"),
      testMatch: "oidc-authorization-code.spec.mts",
      outputDir: temporaryDirectory,
      workers: 1,
      reporter: "line"
    };
    writeFileSync(configPath, `export default ${JSON.stringify(config)};\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });

    const platformNames = platformEnvironmentVariableNames[process.platform === "win32" ? "windows" : "posix"];
    const environment = Object.fromEntries(platformNames
      .filter((key) => typeof process.env[key] === "string")
      .map((key) => [key, process.env[key]]));
    if (process.platform === "win32" && environment.PATH === undefined && process.env.Path) {
      environment.PATH = process.env.Path;
    }
    const cliPath = resolve(repositoryRoot, "node_modules/playwright/cli.js");
    const options = { cwd: repositoryRoot, env: environment, encoding: "utf8", timeout: 30_000, windowsHide: true };
    const setupResult = spawnSync(process.execPath, [cliPath, "test", "--config", configPath], options);
    assert.ifError(setupResult.error);
    const setupOutput = `${setupResult.stdout ?? ""}\n${setupResult.stderr ?? ""}`;
    assert.equal(setupResult.status, 0, `Playwright could not load the E2E setup modules.\n${setupOutput}`);
    assert.match(setupOutput, /1 skipped/u, "the real OIDC spec was discovered and safely skipped without a fixture");

    const configPathUnderTest = resolve(repositoryRoot, "playwright.config.mts");
    const listingResult = spawnSync(process.execPath, [cliPath, "test", "--list", "--config", configPathUnderTest], options);
    assert.ifError(listingResult.error);
    const listingOutput = `${listingResult.stdout ?? ""}\n${listingResult.stderr ?? ""}`;
    assert.equal(listingResult.status, 0, `Playwright could not load the actual ESM config and tests.\n${listingOutput}`);
    assert.match(listingOutput, /oidc-authorization-code\.spec\.mts/u, "the OIDC ESM spec is discoverable from the real config");
    assert.match(listingOutput, /authenticated-journeys\.spec\.mts/u, "the authenticated ESM spec is discoverable from the real config");
    assert.match(listingOutput, /public-entry\.spec\.mts/u, "the public ESM spec is discoverable from the real config");
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test("Hub Next dev receives the private E2E CA for its server worker", () => {
  const tlsDirectory = mkdtempSync(join(tmpdir(), "bielos-e2e-next-tls-"));
  const keyPath = join(tlsDirectory, "server-key.pem");
  const certificatePath = join(tlsDirectory, "server-cert.pem");
  const caCertificatePath = join(tlsDirectory, "test-ca-cert.pem");
  try {
    for (const path of [keyPath, certificatePath, caCertificatePath]) {
      writeFileSync(path, "fixture", { encoding: "utf8", flag: "wx", mode: 0o600 });
    }

    const { args } = getServiceCommand("hub", {
      BIELOS_E2E_TLS_KEY_PATH: keyPath,
      BIELOS_E2E_TLS_CERTIFICATE_PATH: certificatePath,
      NODE_EXTRA_CA_CERTS: caCertificatePath
    });
    assert.deepEqual(args.slice(-7), [
      "--experimental-https",
      "--experimental-https-key", keyPath,
      "--experimental-https-cert", certificatePath,
      "--experimental-https-ca", caCertificatePath
    ]);
  } finally {
    rmSync(tlsDirectory, { recursive: true, force: true });
  }
});

test("service children receive only their E2E allowlist and required OS paths", () => {
  const source = {
    PATH: process.env.PATH ?? process.env.Path ?? "",
    HOME: "e2e-home-sentinel",
    TMPDIR: "e2e-tmpdir-sentinel",
    TMP: "e2e-tmp-sentinel",
    TEMP: "e2e-temp-sentinel",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATHEXT: process.env.PATHEXT ?? ".EXE;.CMD;.BAT",
    SystemRoot: process.env.SystemRoot ?? process.env.SYSTEMROOT ?? "C:\\Windows",
    WINDIR: process.env.WINDIR ?? "C:\\Windows",
    ComSpec: process.env.ComSpec ?? process.env.COMSPEC ?? "C:\\Windows\\System32\\cmd.exe",
    USERPROFILE: process.env.USERPROFILE ?? "C:\\Users\\e2e",
    HOMEDRIVE: process.env.HOMEDRIVE ?? "C:",
    HOMEPATH: process.env.HOMEPATH ?? "\\Users\\e2e",
    APPDATA: process.env.APPDATA ?? "C:\\Users\\e2e\\AppData\\Roaming",
    LOCALAPPDATA: process.env.LOCALAPPDATA ?? "C:\\Users\\e2e\\AppData\\Local",
    ProgramFiles: process.env.ProgramFiles ?? "C:\\Program Files",
    "ProgramFiles(x86)": process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
    ProgramW6432: process.env.ProgramW6432 ?? "C:\\Program Files",
    SYSTEMDRIVE: process.env.SYSTEMDRIVE ?? "C:",
    LOGONSERVER: process.env.LOGONSERVER ?? "\\E2E",
    USERDOMAIN: process.env.USERDOMAIN ?? "E2E",
    USERNAME: process.env.USERNAME ?? "e2e",
    NODE_OPTIONS: "--require caller-controlled-preload.cjs",
    NODE_PATH: "caller-controlled-module-path",
    CALLER_SECRET_SENTINEL: "must-not-reach-service",
    BIELOS_E2E_DATABASE_URL: "must-stay-in-the-runner",
    BIELOS_CORE_TEST_DATABASE_CONFIRM: "disposable",
    BIELOS_E2E_JWKS_REGISTRATION_TOKEN: "fixture-registration-token",
    BIELOS_PORTAL_URL: "https://portal.localhost:3001",
    BIELOS_HUB_HOSTNAME: "hub.localhost",
    BIELOS_PORTAL_HOSTNAME: "portal.localhost",
    BIELOS_HUB_URL: "https://hub.localhost:3001",
    DATABASE_URL: "postgresql://e2e_test@127.0.0.1:5432/bielos_test",
    BIELOS_OIDC_PROXY_URL: "http://127.0.0.1:3003",
    BIELOS_OIDC_ISSUER: "https://portal.localhost:3001",
    BIELOS_OIDC_BIND_ADDRESS: "127.0.0.1",
    OIDC_ISSUER_PORT: "3003",
    BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE: "C:\\Temp\\issuer-config.json",
    BIELOS_OIDC_ADAPTER_KEY: "must-stay-in-private-config",
    BIELOS_OIDC_COOKIE_KEY: "must-stay-in-private-config",
    BIELOS_OIDC_SIGNING_JWKS: "must-stay-in-private-config",
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: "fixture-audience",
    CLOUDFLARE_TEAM_DOMAIN: "http://127.0.0.1:3010",
    BIELOS_E2E_ACCESS_DIAGNOSTICS: "true",
    BIELOS_E2E_TLS_KEY_PATH: "C:\\Temp\\fixture-key.pem",
    BIELOS_E2E_TLS_CERTIFICATE_PATH: "C:\\Temp\\fixture-cert.pem",
    BIELOS_CSRF_SIGNING_KEY: "a".repeat(64),
    NODE_EXTRA_CA_CERTS: join(tmpdir(), "fixture-ca-cert.pem"),
    BIELOS_TOTP_ENCRYPTION_KEY: "e2e-totp-key-sentinel",
    BIELOS_EMAIL_OUTBOX_KEY: "e2e-email-key-sentinel"
  };

  const services = [
    { name: "jwks", allowed: ["BIELOS_E2E_JWKS_REGISTRATION_TOKEN"] },
    { name: "public-site", allowed: ["NODE_ENV", "NEXT_TELEMETRY_DISABLED", "BIELOS_PORTAL_URL"] },
    {
      name: "hub",
      allowed: [
        "NODE_ENV", "NEXT_TELEMETRY_DISABLED", "BIELOS_HUB_HOSTNAME", "BIELOS_PORTAL_HOSTNAME",
        "BIELOS_HUB_URL", "BIELOS_PORTAL_URL", "DATABASE_URL", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
        "CLOUDFLARE_ACCESS_AUDIENCE", "CLOUDFLARE_TEAM_DOMAIN", "BIELOS_E2E_ACCESS_DIAGNOSTICS", "BIELOS_TOTP_ENCRYPTION_KEY", "BIELOS_OIDC_PROXY_URL", "BIELOS_E2E_TLS_KEY_PATH",
        "BIELOS_E2E_TLS_CERTIFICATE_PATH", "BIELOS_CSRF_SIGNING_KEY", "NODE_EXTRA_CA_CERTS", "BIELOS_EMAIL_OUTBOX_KEY"
      ]
    },
    { name: "issuer", allowed: ["DATABASE_URL", "BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE", "BIELOS_OIDC_ISSUER", "BIELOS_OIDC_BIND_ADDRESS", "OIDC_ISSUER_PORT"] }
  ];

  for (const service of services) {
    const environment = buildServiceEnvironment(service.name, source, process.platform);
    const probe = `process.stdout.write(JSON.stringify({
      keys: Object.keys(process.env).sort(),
      path: process.env.PATH === ${JSON.stringify(source.PATH)},
      home: process.env.HOME === "e2e-home-sentinel",
      tmpdir: process.env.TMPDIR === "e2e-tmpdir-sentinel",
      temp: process.env.TEMP === "e2e-temp-sentinel",
      tmp: process.env.TMP === "e2e-tmp-sentinel",
      systemRoot: process.env.SystemRoot === ${JSON.stringify(source.SystemRoot)},
      pathext: process.env.PATHEXT === ${JSON.stringify(source.PATHEXT)}
    }));`;
    const child = spawnSync(process.execPath, ["-e", probe], { env: environment, encoding: "utf8", windowsHide: true });

    assert.equal(child.status, 0, `${service.name} sentinel child exits successfully`);
    const result = JSON.parse(child.stdout);
    const allowedKeys = new Set([
      ...(process.platform === "win32" ? platformEnvironmentVariableNames.windows : platformEnvironmentVariableNames.posix),
      ...service.allowed
    ]);
    if (service.name !== "jwks") {
      allowedKeys.add("NODE_ENV");
      allowedKeys.add("NEXT_TELEMETRY_DISABLED");
    }
    assert.deepEqual(result.keys, [...allowedKeys].sort(), `${service.name} receives no unlisted caller variables`);
    assert.equal(result.keys.includes("NODE_OPTIONS"), false);
    assert.equal(result.keys.includes("NODE_PATH"), false);
    assert.equal(result.path, true);
    assert.equal(result.temp, true);
    assert.equal(result.tmp, true);
    if (process.platform === "win32") {
      assert.equal(result.systemRoot, true);
      assert.equal(result.pathext, true);
    } else {
      assert.equal(result.home, true);
      assert.equal(result.tmpdir, true);
    }

    if (service.name === "hub" || service.name === "issuer") {
      assert.equal(environment.DATABASE_URL, source.DATABASE_URL, `${service.name} keeps the validated database URL`);
      assert.equal(result.keys.includes("BIELOS_CORE_TEST_DATABASE_CONFIRM"), false, `${service.name} does not receive the test marker`);
    }
    if (service.name === "hub") {
      assert.equal(environment.BIELOS_CSRF_SIGNING_KEY, source.BIELOS_CSRF_SIGNING_KEY, "all Hub dev workers receive the same E2E-only CSRF key");
      assert.equal(environment.NODE_EXTRA_CA_CERTS, source.NODE_EXTRA_CA_CERTS, "the Hub trusts only the E2E runtime CA bundle");
    } else {
      assert.equal(result.keys.includes("BIELOS_CSRF_SIGNING_KEY"), false, `${service.name} does not receive the Hub CSRF key`);
      assert.equal(result.keys.includes("NODE_EXTRA_CA_CERTS"), false, `${service.name} does not receive the Hub CA bundle`);
    }
  }

  assert.throws(
    () => buildServiceEnvironment("hub", { ...source, BIELOS_CSRF_SIGNING_KEY: "invalid" }, process.platform),
    /configuration is incomplete/u,
    "the Hub rejects an invalid shared E2E CSRF key"
  );

  assert.throws(
    () => buildServiceEnvironment("issuer", { ...source, BIELOS_OIDC_BIND_ADDRESS: "0.0.0.0" }, process.platform),
    /configuration is incomplete/u,
    "the isolated issuer cannot listen on every network interface"
  );

  const remoteDatabase = {
    ...source,
    DATABASE_URL: "postgresql://production_user@remote.example.invalid:5432/bielos"
  };
  for (const service of ["hub", "issuer"]) {
    assert.throws(
      () => buildServiceEnvironment(service, remoteDatabase, process.platform),
      /local or isolated CI host/u,
      `${service} refuses remote database targets`
    );
  }

  const platformKeys = process.platform === "win32" ? platformEnvironmentVariableNames.windows : platformEnvironmentVariableNames.posix;
  const direct = spawnSync(process.execPath, [fileURLToPath(new URL("./isolated-service.mjs", import.meta.url)), "hub"], {
    env: {
      ...Object.fromEntries(platformKeys.filter((key) => typeof source[key] === "string").map((key) => [key, source[key]])),
      NODE_ENV: "development",
      DATABASE_URL: remoteDatabase.DATABASE_URL,
      BIELOS_CORE_TEST_DATABASE_CONFIRM: "disposable",
      BIELOS_OIDC_PROXY_URL: "http://127.0.0.1:3003",
      BIELOS_E2E_TLS_KEY_PATH: "C:\\Temp\\fixture-key.pem",
      BIELOS_E2E_TLS_CERTIFICATE_PATH: "C:\\Temp\\fixture-cert.pem"
    },
    encoding: "utf8",
    windowsHide: true
  });
  assert.equal(direct.status, 1, "direct Hub launch fails closed for a remote database");
  assert.equal(direct.stderr, "E2E service configuration is invalid.\n");
  assert.equal(direct.stderr.includes("remote.example.invalid"), false, "database targets are not echoed in errors");

  const windowsEnvironment = buildServiceEnvironment("public-site", source, "win32");
  for (const key of platformEnvironmentVariableNames.windows) {
    if (source[key] !== undefined) assert.equal(windowsEnvironment[key], source[key], `${key} is preserved on Windows`);
  }
  const posixEnvironment = buildServiceEnvironment("public-site", source, "linux");
  for (const key of platformEnvironmentVariableNames.posix) {
    if (source[key] !== undefined) assert.equal(posixEnvironment[key], source[key], `${key} is preserved on POSIX`);
  }
});

test("Chromium receives only required platform variables and never BielOS secrets", () => {
  const source = {
    PATH: "safe-system-path",
    PATHEXT: ".EXE;.CMD;.BAT",
    HOME: "caller-home",
    TMPDIR: "caller-tmpdir",
    TEMP: "caller-temp",
    TMP: "caller-tmp",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    SystemRoot: "C:\\Windows",
    WINDIR: "C:\\Windows",
    ComSpec: "C:\\Windows\\System32\\cmd.exe",
    USERPROFILE: "C:\\Users\\e2e",
    HOMEDRIVE: "C:",
    HOMEPATH: "\\Users\\e2e",
    APPDATA: "C:\\Users\\e2e\\AppData\\Roaming",
    LOCALAPPDATA: "C:\\Users\\e2e\\AppData\\Local",
    ProgramFiles: "C:\\Program Files",
    "ProgramFiles(x86)": "C:\\Program Files (x86)",
    ProgramW6432: "C:\\Program Files",
    SYSTEMDRIVE: "C:",
    NODE_OPTIONS: "--require caller-controlled-preload.cjs",
    NODE_EXTRA_CA_CERTS: "private-test-ca.pem",
    DATABASE_URL: "postgresql://must-not-reach-browser",
    BIELOS_CSRF_SIGNING_KEY: "must-not-reach-browser",
    BIELOS_TOTP_ENCRYPTION_KEY: "must-not-reach-browser",
    BIELOS_EMAIL_OUTBOX_KEY: "must-not-reach-browser",
    BIELOS_E2E_ACCESS_SIGNING_KEY_FILE: "private-signing-key.json"
  };

  const linux = buildChromiumEnvironment(source, "linux", "/private/e2e/chromium-home");
  assert.equal(linux.HOME, "/private/e2e/chromium-home");
  assert.equal(linux.PATH, source.PATH);
  assert.equal(linux.TMPDIR, source.TMPDIR);

  const windows = buildChromiumEnvironment(source, "win32");
  assert.equal(windows.PATH, source.PATH);
  assert.equal(windows.SystemRoot, source.SystemRoot);
  assert.equal(windows.USERPROFILE, source.USERPROFILE);

  for (const environment of [linux, windows]) {
    for (const name of ["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "DATABASE_URL", "BIELOS_CSRF_SIGNING_KEY", "BIELOS_TOTP_ENCRYPTION_KEY", "BIELOS_EMAIL_OUTBOX_KEY", "BIELOS_E2E_ACCESS_SIGNING_KEY_FILE"]) {
      assert.equal(Object.hasOwn(environment, name), false, `${name} is excluded from Chromium`);
    }
  }
});
