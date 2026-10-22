import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildChromiumEnvironment, buildServiceEnvironment, getServiceCommand, platformEnvironmentVariableNames } from "./isolated-service.mjs";
import { createE2eOidcPrivateConfiguration, readE2eOidcPrivateConfiguration } from "./oidc-private-config.mjs";
import { runCleanupSteps, validateAuditCleanupDatabase } from "./global-setup.mts";

const repositoryRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));

test("private OIDC configuration exists before Playwright webServer starts the Hub", () => {
  const playwrightSource = readFileSync(resolve(repositoryRoot, "playwright.config.mts"), "utf8");
  const globalSetupSource = readFileSync(resolve(repositoryRoot, "scripts/e2e/global-setup.mts"), "utf8");
  const creation = playwrightSource.indexOf("createE2eOidcPrivateConfiguration(oidcPrivateConfigPath)");
  const webServers = playwrightSource.indexOf("webServer: [");
  assert.ok(creation >= 0 && creation < webServers, "the private configuration must be generated before webServer startup");
  assert.doesNotMatch(globalSetupSource, /writeFile\(oidcPrivateConfigFile,/u, "globalSetup must reuse rather than create a late private configuration");
});

test("private OIDC fixture is generated once with isolated signing and cookie keys", (t) => {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "virki-e2e-private-oidc-"));
  t.after(() => rmSync(temporaryDirectory, { recursive: true, force: true }));
  const file = join(temporaryDirectory, "issuer-config.json");
  createE2eOidcPrivateConfiguration(file);
  const config = readE2eOidcPrivateConfiguration(file);
  assert.match(config.adapterKey, /^[0-9a-f]{64}$/u);
  assert.match(config.cookieKey, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(config.signingKeyId, /^[0-9a-f-]{36}$/u);
  assert.equal(config.signingJwks.keys[0].alg, "ES256");
  assert.equal(config.signingJwks.keys[0].crv, "P-256");
  if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.throws(() => createE2eOidcPrivateConfiguration(file), { code: "EEXIST" }, "existing signing material must not be overwritten");
  writeFileSync(file, "{}", { encoding: "utf8" });
  assert.throws(() => readE2eOidcPrivateConfiguration(file), /configuration is invalid/u, "malformed private material fails closed");
});

test("audit fixture cleanup uses the exact validated disposable target and migration role", () => {
  const previousNodeEnv = process.env.NODE_ENV;
  const previousConfirmation = process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM;
  const runtimeDatabaseUrl = ["postgresql:/", "/virki_runtime_test:", "runtime-only@127.0.0.1:55432/virki_e2e_test?schema=public"].join("");
  const cleanupDatabaseUrl = ["postgresql:/", "/virki_migrator:", "migrator-only@127.0.0.1:55432/virki_e2e_test?schema=public"].join("");
  process.env.NODE_ENV = "test";
  process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM = "disposable";
  try {
    const target = validateAuditCleanupDatabase(cleanupDatabaseUrl, runtimeDatabaseUrl);
    assert.equal(target.protocol, "postgresql:");
    assert.equal(target.username, "virki_migrator");
    assert.equal(target.hostname, "127.0.0.1");
    assert.equal(target.port, "55432");
    assert.equal(target.pathname, "/virki_e2e_test");
    assert.equal(target.search, "?schema=public");

    const mismatches = [
      cleanupDatabaseUrl.replace("virki_migrator", "virki_runtime_test"),
      cleanupDatabaseUrl.replace("127.0.0.1:55432", "localhost:55432"),
      cleanupDatabaseUrl.replace(":55432/", ":55433/"),
      cleanupDatabaseUrl.replace("/virki_e2e_test", "/virki_other_test"),
      cleanupDatabaseUrl.replace("schema=public", "schema=other"),
      cleanupDatabaseUrl.replace(":migrator-only@", "@"),
      cleanupDatabaseUrl.replace("?schema=public", "?schema=public#fragment")
    ];
    for (const mismatch of mismatches) {
      assert.throws(
        () => validateAuditCleanupDatabase(mismatch, runtimeDatabaseUrl),
        { message: "E2E audit fixture cleanup requires the migration role on the exact validated disposable database." }
      );
    }
    assert.throws(
      () => validateAuditCleanupDatabase(undefined, runtimeDatabaseUrl),
      { message: "E2E audit fixture cleanup requires the migration role on the exact validated disposable database." }
    );
  } finally {
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
    if (previousConfirmation === undefined) delete process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM;
    else process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM = previousConfirmation;
  }
});

test("fixture cleanup runs in order and reports fixed labels without raw errors", async () => {
  const events = [];
  const rawError = "untrusted database diagnostic sentinel";
  const failures = await runCleanupSteps([
    ["issuer-stop", async () => { events.push("issuer-stop"); }],
    ["fixture-records", async () => { events.push("fixture-records"); throw new Error(rawError); }],
    ["fixture-files", async () => { events.push("fixture-files"); }],
    ["issuer-config", async () => { events.push("issuer-config"); }],
    ["runtime-disconnect", async () => { events.push("runtime-disconnect"); }],
    ["audit-disconnect", async () => { events.push("audit-disconnect"); }]
  ]);
  assert.deepEqual(events, ["issuer-stop", "fixture-records", "fixture-files", "issuer-config", "runtime-disconnect", "audit-disconnect"]);
  assert.deepEqual(failures, ["fixture-records"]);
  assert.equal(JSON.stringify(failures).includes(rawError), false);
});

test("Playwright loads E2E config, setup, and OIDC spec through their ESM entrypoints", () => {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "virki-playwright-loader-"));
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
    const rootCaCountBeforeListing = process.platform === "win32" ? getCurrentUserRootCaCount() : undefined;
    const listingResult = spawnSync(process.execPath, [cliPath, "test", "--list", "--config", configPathUnderTest], options);
    assert.ifError(listingResult.error);
    const listingOutput = `${listingResult.stdout ?? ""}\n${listingResult.stderr ?? ""}`;
    if (rootCaCountBeforeListing !== undefined) {
      assert.equal(getCurrentUserRootCaCount(), rootCaCountBeforeListing, "Playwright test listing must not change the current-user root store");
    }
    assert.equal(listingResult.status, 0, `Playwright could not load the actual ESM config and tests.\n${listingOutput}`);
    assert.match(listingOutput, /oidc-authorization-code\.spec\.mts/u, "the OIDC ESM spec is discoverable from the real config");
    assert.match(listingOutput, /authenticated-journeys\.spec\.mts/u, "the authenticated ESM spec is discoverable from the real config");
    assert.match(listingOutput, /public-entry\.spec\.mts/u, "the public ESM spec is discoverable from the real config");
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

function getCurrentUserRootCaCount() {
  const rootStoreCommand = "$store=[System.Security.Cryptography.X509Certificates.X509Store]::new('Root','CurrentUser'); $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly); try { @($store.Certificates | Where-Object { $_.Subject -like '*CN=Virki E2E Root CA*' }).Count } finally { $store.Close(); $store.Dispose() }";
  const result = spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", rootStoreCommand], { encoding: "utf8", windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, "the Windows current-user root store was readable");
  return Number(result.stdout.trim());
}

test("Hub Next dev receives the private E2E CA for its server worker", () => {
  const tlsDirectory = mkdtempSync(join(tmpdir(), "virki-e2e-next-tls-"));
  const keyPath = join(tlsDirectory, "server-key.pem");
  const certificatePath = join(tlsDirectory, "server-cert.pem");
  const caCertificatePath = join(tlsDirectory, "test-ca-cert.pem");
  try {
    for (const path of [keyPath, certificatePath, caCertificatePath]) {
      writeFileSync(path, "fixture", { encoding: "utf8", flag: "wx", mode: 0o600 });
    }

    const { args } = getServiceCommand("hub", {
      VIRKI_E2E_TLS_KEY_PATH: keyPath,
      VIRKI_E2E_TLS_CERTIFICATE_PATH: certificatePath,
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

test("service children receive only their E2E allowlist and required OS paths", (t) => {
  const privateConfigDirectory = mkdtempSync(join(tmpdir(), "virki-isolated-service-"));
  const privateConfigPath = join(privateConfigDirectory, "issuer-config.json");
  const privateAdapterKey = "b".repeat(64);
  writeFileSync(privateConfigPath, JSON.stringify({ adapterKey: privateAdapterKey, cookieKey: "c".repeat(43), signingJwks: { keys: [{}] } }), { encoding: "utf8", mode: 0o600 });
  t.after(() => rmSync(privateConfigDirectory, { recursive: true, force: true }));

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
    VIRKI_E2E_DATABASE_URL: "must-stay-in-the-runner",
    VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL: "maintenance-must-stay-in-global-setup",
    VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
    VIRKI_E2E_JWKS_REGISTRATION_TOKEN: "fixture-registration-token",
    VIRKI_PORTAL_URL: "https://portal.localhost:3001",
    VIRKI_HUB_HOSTNAME: "hub.localhost",
    VIRKI_PORTAL_HOSTNAME: "portal.localhost",
    VIRKI_HUB_URL: "https://hub.localhost:3001",
    DATABASE_URL: "postgresql://e2e_test@127.0.0.1:5432/virki_test",
    VIRKI_OIDC_PROXY_URL: "http://127.0.0.1:3003",
    VIRKI_OIDC_ISSUER: "https://portal.localhost:3001",
    VIRKI_OIDC_BIND_ADDRESS: "127.0.0.1",
    OIDC_ISSUER_PORT: "3003",
    VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE: privateConfigPath,
    VIRKI_OIDC_ADAPTER_KEY: "parent-environment-key-must-not-be-used",
    VIRKI_OIDC_COOKIE_KEY: "must-stay-in-private-config",
    VIRKI_OIDC_SIGNING_JWKS: "must-stay-in-private-config",
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: "fixture-audience",
    CLOUDFLARE_TEAM_DOMAIN: "http://127.0.0.1:3010",
    VIRKI_E2E_ACCESS_DIAGNOSTICS: "true",
    VIRKI_E2E_LOW05_DIAGNOSTICS: "true",
    VIRKI_E2E_TLS_KEY_PATH: "C:\\Temp\\fixture-key.pem",
    VIRKI_E2E_TLS_CERTIFICATE_PATH: "C:\\Temp\\fixture-cert.pem",
    VIRKI_CSRF_SIGNING_KEY: "a".repeat(64),
    VIRKI_RATE_LIMIT_HASH_SECRET: "r".repeat(64),
    NODE_EXTRA_CA_CERTS: join(tmpdir(), "fixture-ca-cert.pem"),
    VIRKI_TOTP_ENCRYPTION_KEY: "e2e-totp-key-sentinel",
    VIRKI_EMAIL_OUTBOX_KEY: "e2e-email-key-sentinel"
  };

  const services = [
    { name: "jwks", allowed: ["VIRKI_E2E_JWKS_REGISTRATION_TOKEN"] },
    { name: "public-site", allowed: ["NODE_ENV", "NEXT_TELEMETRY_DISABLED", "VIRKI_PORTAL_URL"] },
    {
      name: "hub",
      allowed: [
        "NODE_ENV", "NEXT_TELEMETRY_DISABLED", "VIRKI_HUB_HOSTNAME", "VIRKI_PORTAL_HOSTNAME",
        "VIRKI_HUB_URL", "VIRKI_PORTAL_URL", "DATABASE_URL", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
        "CLOUDFLARE_ACCESS_AUDIENCE", "CLOUDFLARE_TEAM_DOMAIN", "VIRKI_E2E_ACCESS_DIAGNOSTICS", "VIRKI_E2E_LOW05_DIAGNOSTICS", "VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_RATE_LIMIT_HASH_SECRET", "VIRKI_OIDC_PROXY_URL", "VIRKI_E2E_TLS_KEY_PATH",
        "VIRKI_E2E_TLS_CERTIFICATE_PATH", "VIRKI_CSRF_SIGNING_KEY", "NODE_EXTRA_CA_CERTS", "VIRKI_EMAIL_OUTBOX_KEY"
      ]
    },
    { name: "issuer", allowed: ["DATABASE_URL", "VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE", "VIRKI_OIDC_ISSUER", "VIRKI_OIDC_BIND_ADDRESS", "OIDC_ISSUER_PORT", "VIRKI_RATE_LIMIT_HASH_SECRET"] }
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
    if (service.name === "hub") allowedKeys.add("VIRKI_OIDC_ADAPTER_KEY");
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
      assert.equal(result.keys.includes("VIRKI_CORE_TEST_DATABASE_CONFIRM"), false, `${service.name} does not receive the test marker`);
    }
    if (service.name === "hub") {
      assert.equal(environment.VIRKI_CSRF_SIGNING_KEY, source.VIRKI_CSRF_SIGNING_KEY, "all Hub dev workers receive the same E2E-only CSRF key");
      assert.equal(environment.NODE_EXTRA_CA_CERTS, source.NODE_EXTRA_CA_CERTS, "the Hub trusts only the E2E runtime CA bundle");
      assert.equal(environment.VIRKI_OIDC_ADAPTER_KEY, privateAdapterKey, "the Hub receives only the adapter key extracted from private OIDC configuration");
      assert.equal(Object.hasOwn(environment, "VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE"), false, "the Hub does not receive the private config path");
      assert.equal(Object.hasOwn(environment, "VIRKI_OIDC_COOKIE_KEY"), false, "the Hub does not receive the issuer cookie key");
      assert.equal(Object.hasOwn(environment, "VIRKI_OIDC_SIGNING_JWKS"), false, "the Hub does not receive issuer signing keys");
    } else if (service.name === "issuer") {
      assert.equal(environment.VIRKI_RATE_LIMIT_HASH_SECRET, source.VIRKI_RATE_LIMIT_HASH_SECRET, "the issuer receives only the isolated rate-limit HMAC key it requires");
    } else {
      assert.equal(result.keys.includes("VIRKI_CSRF_SIGNING_KEY"), false, `${service.name} does not receive the Hub CSRF key`);
      assert.equal(result.keys.includes("NODE_EXTRA_CA_CERTS"), false, `${service.name} does not receive the Hub CA bundle`);
      assert.equal(result.keys.includes("VIRKI_OIDC_ADAPTER_KEY"), false, `${service.name} does not inherit the adapter key from the parent environment`);
    }
  }

  assert.throws(
    () => buildServiceEnvironment("hub", { ...source, VIRKI_CSRF_SIGNING_KEY: "invalid" }, process.platform),
    /configuration is incomplete/u,
    "the Hub rejects an invalid shared E2E CSRF key"
  );

  assert.throws(
    () => buildServiceEnvironment("issuer", { ...source, VIRKI_OIDC_BIND_ADDRESS: "0.0.0.0" }, process.platform),
    /configuration is incomplete/u,
    "the isolated issuer cannot listen on every network interface"
  );

  const remoteDatabase = {
    ...source,
    DATABASE_URL: "postgresql://production_user@remote.example.invalid:5432/virki"
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
      VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
      VIRKI_OIDC_PROXY_URL: "http://127.0.0.1:3003",
      VIRKI_E2E_TLS_KEY_PATH: "C:\\Temp\\fixture-key.pem",
      VIRKI_E2E_TLS_CERTIFICATE_PATH: "C:\\Temp\\fixture-cert.pem"
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

test("Chromium receives only required platform variables and never Virki secrets", () => {
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
    VIRKI_CSRF_SIGNING_KEY: "must-not-reach-browser",
    VIRKI_TOTP_ENCRYPTION_KEY: "must-not-reach-browser",
    VIRKI_EMAIL_OUTBOX_KEY: "must-not-reach-browser",
    VIRKI_OIDC_ADAPTER_KEY: "d".repeat(64),
    VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE: "private-oidc-config.json",
    VIRKI_E2E_ACCESS_SIGNING_KEY_FILE: "private-signing-key.json",
    VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL: "maintenance-must-not-reach-browser"
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
    for (const name of ["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "DATABASE_URL", "VIRKI_CSRF_SIGNING_KEY", "VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_OIDC_ADAPTER_KEY", "VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE", "VIRKI_E2E_ACCESS_SIGNING_KEY_FILE", "VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL"]) {
      assert.equal(Object.hasOwn(environment, name), false, `${name} is excluded from Chromium`);
    }
  }
});

test("Hub readiness checks its listening port while the browser verifies the private TLS CA", () => {
  const configPath = resolve(repositoryRoot, "playwright.config.mts");
  const configUrl = pathToFileURL(configPath).href;
  assert.equal(fileURLToPath(new URL(configUrl)), configPath);
  assert.match(configUrl, /^file:\/\/\//);
  if (process.platform === "win32") {
    assert.match(configUrl, /^file:\/\/\/[a-z]:\//i);
  }
  const inspector = `
    process.argv.push("--list");
    const { default: config } = await import(${JSON.stringify(configUrl)});
    const hub = config.webServer.find(({ command }) => command.includes("isolated-service.mjs hub"));
    process.stdout.write(JSON.stringify({ port: hub?.port, url: hub?.url, ignoreHTTPSErrors: config.use?.ignoreHTTPSErrors }));
  `;
  const platformNames = platformEnvironmentVariableNames[process.platform === "win32" ? "windows" : "posix"];
  const environment = Object.fromEntries(platformNames
    .filter((key) => typeof process.env[key] === "string")
    .map((key) => [key, process.env[key]]));
  if (process.platform === "win32" && environment.PATH === undefined && process.env.Path) {
    environment.PATH = process.env.Path;
  }
  const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", inspector], {
    cwd: repositoryRoot,
    env: environment,
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `Could not inspect the E2E web server configuration.\n${result.stderr}`);
  assert.deepEqual(JSON.parse(result.stdout), { port: 3001 });
});
