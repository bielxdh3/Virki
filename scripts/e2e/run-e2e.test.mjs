import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { Agent, createServer, request as httpRequest } from "node:http";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertNativeE2eFixture, buildE2ECommand, shouldBuildProductionHub } from "./run-e2e.mjs";
import { buildServiceEnvironment, getServiceCommand } from "./isolated-service.mjs";
import { redactBrowserE2ELog } from "./redact-browser-e2e-log.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../..");

test("RED→GREEN: Docker dependency bootstrap disconnects before private DB attachment", () => {
  const launcher = readFileSync(resolve(scriptDirectory, "run-isolated-linux-docker.ps1"), "utf8");
  const install = launcher.indexOf("Invoke-PinnedDocker exec --workdir /workspace $runnerName npm ci");
  const browserDeps = launcher.indexOf("Invoke-LoggedStage 'chromium-dependencies'");
  const disconnect = launcher.indexOf("Invoke-PinnedDocker network disconnect $bootstrapNetworkName $runnerName");
  const connectPrivate = launcher.indexOf("Invoke-PinnedDocker network connect $networkName $runnerName");
  const deleteBootstrap = launcher.indexOf("Invoke-OwnedDockerCleanup 'bootstrapNetwork'", disconnect);
  const migrate = launcher.indexOf("npm run prisma:migrate:deploy", connectPrivate);
  assert.ok(install > 0 && browserDeps > install && disconnect > browserDeps,
    "package installers must run only on the bootstrap network");
  assert.ok(connectPrivate > disconnect && deleteBootstrap > connectPrivate && migrate > deleteBootstrap,
    "the bootstrap endpoint must be disconnected before the DB attach while preserving Docker HostConfig mode");
  assert.equal(launcher.indexOf("Invoke-PinnedDocker network connect $networkName $runnerName", connectPrivate + 1), -1);
});

test("Windows runs browser E2E in isolated Linux Docker and carries filters as JSON data", () => {
  const playwrightArguments = ["--grep", "OIDC flow with spaces", "value; do-not-run-shell"];
  const command = buildE2ECommand("win32", playwrightArguments, "C:\\Virki");

  assert.equal(command.executable, "powershell.exe");
  assert.deepEqual(command.args, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    "C:\\Virki\\scripts\\e2e\\run-isolated-linux-docker.ps1",
    "-E2EOnly"
  ]);
  assert.deepEqual(JSON.parse(command.environment.VIRKI_E2E_PLAYWRIGHT_ARGUMENTS_JSON), playwrightArguments);
});

test("native Hub E2E is explicitly opt-in, Hub-only and a mandatory non-skipping CI gate", () => {
  const config = readFileSync(resolve(repositoryRoot, "playwright.config.mts"), "utf8");
  const workflow = readFileSync(resolve(repositoryRoot, ".github/workflows/ci.yml"), "utf8");
  const spec = readFileSync(resolve(repositoryRoot, "e2e/native-hub-perimeter.spec.mts"), "utf8");
  const isolatedService = readFileSync(resolve(scriptDirectory, "isolated-service.mjs"), "utf8");
  assert.match(config, /process\.env\.VIRKI_E2E_NATIVE_HUB === "required"/u);
  assert.match(config, /nativeHubGate && \(productionHubMode \|\| !process\.env\.VIRKI_E2E_DATABASE_URL/u);
  assert.doesNotMatch(config, /!process\.env\.VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL/u,
    "Playwright worker imports config after global setup removes privileged cleanup credentials");
  assert.match(config, /nativeHubGate \? \{ VIRKI_HUB_PERIMETER_MODE: "native" \} : \{\}/u);
  assert.match(config, /testMatch: "\*\*\/native-hub-perimeter\.spec\.mts"/u);
  assert.match(config, /testIgnore: "\*\*\/native-hub-perimeter\.spec\.mts"/u);
  assert.match(isolatedService, /hub: \[[\s\S]*?"VIRKI_HUB_PERIMETER_MODE"/u);
  assert.doesNotMatch(isolatedService.match(/"public-site": \[[^\]]+\]/u)?.[0] ?? "", /VIRKI_HUB_PERIMETER_MODE/u);
  assert.match(spec, /"NATIVE HUB: unauthenticated/u);
  assert.match(spec, /"NATIVE HUB: legitimate USER/u);
  assert.match(spec, /"NATIVE HUB: ADMIN password plus genuine queued MFA/u);
  assert.doesNotMatch(spec, /addCloudflareAccessHeader/u);
  const stage = workflow.split("- name: Run mandatory native Hub browser E2E without Cloudflare Access JWT")[1]?.split("- name: Run production Hub core browser E2E")[0];
  assert.ok(stage, "mandatory native Hub stage must exist before production Hub rehearsal");
  assert.match(stage, /VIRKI_E2E_NATIVE_HUB: required/u);
  assert.match(stage, /npm run test:e2e -- e2e\/native-hub-perimeter\.spec\.mts --forbid-only/u);
  assert.match(stage, /3 passed/u);
  assert.match(stage, /set -euo pipefail/u);
  assert.doesNotMatch(stage, /continue-on-error:|if:\s*false/u);
  for (const mutation of [
    workflow.replace("VIRKI_E2E_NATIVE_HUB: required", "VIRKI_E2E_NATIVE_HUB: false"),
    workflow.replace("e2e/native-hub-perimeter.spec.mts --forbid-only", "e2e/public-entry.spec.mts"),
    workflow.replace("3 passed", "0 passed")
  ]) {
    const candidate = mutation.split("- name: Run mandatory native Hub browser E2E without Cloudflare Access JWT")[1]?.split("- name: Run production Hub core browser E2E")[0] ?? "";
    assert.equal(/VIRKI_E2E_NATIVE_HUB: required/u.test(candidate) &&
      /e2e\/native-hub-perimeter\.spec\.mts --forbid-only/u.test(candidate) &&
      /3 passed/u.test(candidate), false, "mutated native Hub CI gate must not look valid");
  }
});

test("native Hub disposable cleanup credential is checked before worker startup but not required in browser workers", () => {
  const fixture = {
    VIRKI_E2E_NATIVE_HUB: "required",
    VIRKI_E2E_DATABASE_URL: ["postgresql://", "virki_runtime_test", "@127.0.0.1:5432/virki_e2e_test"].join(""),
    VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL: ["postgresql://", "virki_migrator", "@127.0.0.1:5432/virki_e2e_test"].join(""),
    VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable"
  };
  assert.doesNotThrow(() => assertNativeE2eFixture(fixture, "linux"));
  assert.doesNotThrow(() => assertNativeE2eFixture({}, "linux"), "non-native E2E remains unchanged");
  for (const key of ["VIRKI_E2E_DATABASE_URL", "VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL", "VIRKI_CORE_TEST_DATABASE_CONFIRM"]) {
    assert.throws(() => assertNativeE2eFixture({ ...fixture, [key]: "" }, "linux"), /exclusive disposable database/u);
  }
  assert.throws(() => assertNativeE2eFixture({ ...fixture, VIRKI_E2E_NATIVE_HUB: "false" }, "linux"), /explicit non-production opt-in/u);
  assert.throws(() => assertNativeE2eFixture({ ...fixture, VIRKI_E2E_HUB_MODE: "production" }, "linux"), /explicit non-production opt-in/u);
  assert.throws(() => assertNativeE2eFixture({ ...fixture, VIRKI_E2E_DATABASE_URL: "postgresql://test@remote.invalid/other" }, "linux"), /local or isolated CI host/u);
  assert.doesNotThrow(() => assertNativeE2eFixture(fixture, "win32"), "the signed Windows Docker runner provisions an exclusive DB itself");
});

test("Windows native Hub opt-in reaches its isolated Docker browser and cannot become a silent Access-suite green", () => {
  const runner = readFileSync(resolve(scriptDirectory, "run-isolated-linux-docker.ps1"), "utf8");
  const firstDockerProbe = runner.indexOf("$dockerProbe = Invoke-PinnedDocker version");
  const nativeOptInValidation = runner.indexOf("if ($env:VIRKI_E2E_NATIVE_HUB -and $env:VIRKI_E2E_NATIVE_HUB -cne 'required')");
  const nativeProdDenial = runner.indexOf("if ($env:VIRKI_E2E_NATIVE_HUB -ceq 'required' -and $env:VIRKI_E2E_HUB_MODE -eq 'production')");
  const nativeDockerFlag = runner.indexOf("if ($env:VIRKI_E2E_NATIVE_HUB -ceq 'required') { $e2eEnvironment += @('--env', 'VIRKI_E2E_NATIVE_HUB=required') }");
  const browserInvoke = runner.indexOf("Invoke-Stage -Name 'browser-e2e' -Command $playwrightCommand -Environment $e2eEnvironment");
  assert.ok(nativeOptInValidation > 0 && nativeOptInValidation < firstDockerProbe, "invalid native opt-in must fail before Docker probing");
  assert.ok(nativeProdDenial > nativeOptInValidation && nativeProdDenial < firstDockerProbe, "production-mode native E2E must fail before resource creation");
  assert.ok(nativeDockerFlag > 0 && nativeDockerFlag < browserInvoke, "only the explicitly required native opt-in reaches the Linux browser process");
  assert.match(runner, /VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL=' \+ \$urls\.migrator/u,
    "the disposable Linux worker still receives its scoped audit cleanup fixture");
  assert.ok(!runner.includes("'VIRKI_HUB_PERIMETER_MODE=native'"), "never set native mode in a shared non-browser service");
});

test("isolated Windows launcher rejects remote Docker context overrides before creating any fixture", {
  skip: process.platform !== "win32" && "Windows-only PowerShell launch guard",
}, () => {
  const script = resolve(scriptDirectory, "run-isolated-linux-docker.ps1");
  for (const override of [
    { DOCKER_CONTEXT: "remote-untrusted" },
    { DOCKER_HOST: "tcp://198.51.100.22:2375" },
    { DOCKER_CONFIG: "C:\\remote-docker-config" },
  ]) {
    const child = spawnSync("powershell.exe", [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-File", script, "-UnitOnly",
    ], {
      cwd: repositoryRoot, encoding: "utf8", timeout: 15_000,
      env: {
        ...process.env,
        DOCKER_CONTEXT: "", DOCKER_HOST: "", DOCKER_CONFIG: "",
        ...override,
      },
    });
    assert.equal(child.error, undefined);
    assert.notEqual(child.status, 0);
    assert.match(child.stderr, /unoverridden local Docker Desktop Linux context/u);
    assert.doesNotMatch(child.stdout, /ISOLATED_RUN_ID|SOURCE_HEAD|\[RESULT\]/u,
      "unsafe context must be rejected before recording or running a fixture");
  }
});

test("direct Playwright runs on Windows are rejected except for side-effect-free discovery", async () => {
  const policy = await import("./run-e2e.mjs");
  assert.equal(typeof policy.assertDirectPlaywrightPlatform, "function");
  assert.doesNotThrow(() => policy.assertDirectPlaywrightPlatform("linux", false));
  assert.doesNotThrow(() => policy.assertDirectPlaywrightPlatform("win32", true));
  assert.throws(() => policy.assertDirectPlaywrightPlatform("win32", false), /isolated Linux Docker/u);
});

test("Linux executes the repository Playwright CLI directly with argv boundaries preserved", () => {
  const playwrightArguments = ["--grep", "OIDC flow with spaces"];
  const command = buildE2ECommand("linux", playwrightArguments, "/workspace/virki");

  assert.equal(command.executable, process.execPath);
  assert.deepEqual(command.args, [
    "/workspace/virki/node_modules/playwright/cli.js",
    "test",
    "--config=playwright.config.mts",
    ...playwrightArguments
  ]);
  assert.deepEqual(command.environment, {});
});

test("an isolated runner can skip a duplicate production Hub build after its build stage", () => {
  assert.equal(shouldBuildProductionHub({ VIRKI_E2E_HUB_MODE: "production" }), true);
  assert.equal(shouldBuildProductionHub({ VIRKI_E2E_HUB_MODE: "production", VIRKI_E2E_HUB_BUILD_READY: "true" }), false);
  assert.equal(shouldBuildProductionHub({ VIRKI_E2E_HUB_BUILD_READY: "true" }), false);
});

test("production browser E2E refuses to silently skip the authenticated fixture", async () => {
  const { assertProductionE2eFixture } = await import("./run-e2e.mjs");
  assert.equal(typeof assertProductionE2eFixture, "function");
  const fixture = {
    VIRKI_E2E_HUB_MODE: "production",
    VIRKI_E2E_DATABASE_URL: "postgresql://runtime-test@127.0.0.1:5432/virki_e2e_test",
    VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL: "postgresql://migrator@127.0.0.1:5432/virki_e2e_test",
    VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable"
  };
  assert.doesNotThrow(() => assertProductionE2eFixture(fixture));
  assert.doesNotThrow(() => assertProductionE2eFixture({ VIRKI_E2E_HUB_MODE: "development" }));
  assert.doesNotThrow(() => assertProductionE2eFixture({ VIRKI_E2E_HUB_MODE: "production" }, "win32"), "Windows creates the fixture inside its isolated Docker runner");
  for (const key of ["VIRKI_E2E_DATABASE_URL", "VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL", "VIRKI_CORE_TEST_DATABASE_CONFIRM"]) {
    assert.throws(() => assertProductionE2eFixture({ ...fixture, [key]: "" }, "linux"), /disposable database fixture/u);
  }
  assert.throws(() => assertProductionE2eFixture({ ...fixture, VIRKI_E2E_DATABASE_URL: "postgresql://admin@remote.invalid/virki" }, "linux"), /local or isolated CI host/u);
});

test("CI runs production build/start core browser journeys after preserving the development suite", () => {
  const workflow = readFileSync(resolve(repositoryRoot, ".github/workflows/ci.yml"), "utf8");
  const e2eJob = workflow.slice(workflow.indexOf("  authenticated-e2e:"));
  assert.match(e2eJob, /node-version: 22\.20\.0/u);
  assert.match(e2eJob, /Verify Node 22 and npm 10 E2E toolchain/u);
  assert.match(e2eJob, /run: npm ci/u);
  const dev = workflow.indexOf("- name: Run browser E2E");
  const passkey = workflow.indexOf("- name: Run isolated passkey recovery browser E2E");
  const production = workflow.indexOf("- name: Run production Hub core browser E2E");
  const cleanup = workflow.indexOf("- name: Remove disposable PostgreSQL");
  assert.ok(dev > 0 && passkey > dev && production > passkey && cleanup > production);
  const stage = workflow.slice(production, cleanup);
  const passkeyStage = workflow.slice(passkey, production);
  const devStage = workflow.slice(dev, production);
  assert.doesNotMatch(devStage, /rm -f -- "\$VIRKI_E2E_AUDIT_CLEANUP_URL_FILE"/u, "the production step must be able to read the disposable cleanup fixture");
  assert.match(stage, /rm -f -- "\$VIRKI_E2E_AUDIT_CLEANUP_URL_FILE"/u, "the production step must remove its temporary credential");
  assert.match(stage, /VIRKI_E2E_HUB_MODE: production/u);
  assert.match(passkeyStage, /VIRKI_E2E_PASSKEYS: "true"/u);
  assert.match(passkeyStage, /VIRKI_E2E_ADMIN_PASSKEYS: "true"/u);
  assert.match(passkeyStage, /VIRKI_E2E_REQUIRE_RECOVERY_PASSKEYS: "true"/u);
  assert.match(passkeyStage, /npm run test:e2e -- --grep 'PASSKEY_\|USER virtual authenticator'/u,
    "mandatory opt-in must run recovery/passkey E2E and the real USER credential-inventory lifecycle");
  assert.doesNotMatch(stage, /VIRKI_E2E_ADMIN_PASSKEYS: "true"/u,
    "privileged test-only passkey opt-in must never leak into the production-mode browser stage");
  assert.match(stage, /VIRKI_HUB_HOSTNAME: hub\.localhost/u);
  assert.match(stage, /VIRKI_PORTAL_HOSTNAME: portal\.localhost/u);
  assert.match(stage, /VIRKI_OIDC_PROXY_URL: http:\/\/127\.0\.0\.1:3003/u);
  assert.match(stage, /127\.0\.0\.1 access\.e2e\.invalid/u, "the server-side Access JWKS fetch needs local DNS");
  assert.match(stage, /net\.ipv4\.ip_unprivileged_port_start=0/u, "the unprivileged Hub process must bind HTTPS port 443");
  assert.match(stage, /VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL="\$cleanup_url" npm run test:e2e -- e2e\/authenticated-journeys\.spec\.mts e2e\/oidc-authorization-code\.spec\.mts/u);
  assert.doesNotMatch(stage, /VIRKI_E2E_HUB_BUILD_READY/u, "the CI gate must build from source in its clean checkout");
});

test("production Hub E2E uses the production start adapter", () => {
  const tlsDirectory = mkdtempSync(resolve(tmpdir(), "virki-prod-hub-command-"));
  const keyPath = resolve(tlsDirectory, "server-key.pem");
  const certificatePath = resolve(tlsDirectory, "server-cert.pem");
  const caCertificatePath = resolve(tlsDirectory, "test-ca-cert.pem");
  try {
    for (const path of [keyPath, certificatePath, caCertificatePath]) writeFileSync(path, "fixture", { flag: "wx" });
    const command = getServiceCommand("hub", {
      VIRKI_E2E_HUB_MODE: "production",
      VIRKI_E2E_TLS_KEY_PATH: keyPath,
      VIRKI_E2E_TLS_CERTIFICATE_PATH: certificatePath,
      NODE_EXTRA_CA_CERTS: caCertificatePath
    });
    assert.equal(command.cwd, repositoryRoot);
    assert.deepEqual(command.args, [resolve(scriptDirectory, "start-production-hub.mjs")]);
  } finally {
    rmSync(tlsDirectory, { recursive: true, force: true });
  }
});

test("production Hub E2E aligns issuer and Hub cookie runtime modes", () => {
  const tlsDirectory = mkdtempSync(resolve(tmpdir(), "virki-prod-hub-env-"));
  const tlsPath = (name) => resolve(tlsDirectory, name);
  const privateAdapterKey = "b".repeat(64);
  const privateOidcConfigPath = tlsPath("issuer-config.json");
  writeFileSync(privateOidcConfigPath, JSON.stringify({ adapterKey: privateAdapterKey }), { encoding: "utf8", mode: 0o600 });
  const source = {
    PATH: process.env.PATH ?? process.env.Path ?? "",
    HOME: process.env.HOME ?? "",
    TMPDIR: process.env.TMPDIR ?? "",
    TMP: process.env.TMP ?? "",
    TEMP: process.env.TEMP ?? "",
    LANG: process.env.LANG ?? "C.UTF-8",
    LC_ALL: process.env.LC_ALL ?? "C.UTF-8",
    NODE_ENV: "production",
    DATABASE_URL: "postgresql://virki_runtime_test@127.0.0.1:5432/virki_e2e_test",
    VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
    VIRKI_OIDC_PROXY_URL: "http://127.0.0.1:3003",
    VIRKI_E2E_TLS_KEY_PATH: tlsPath("server-key.pem"),
    VIRKI_E2E_TLS_CERTIFICATE_PATH: tlsPath("server-cert.pem"),
    NODE_EXTRA_CA_CERTS: tlsPath("test-ca-cert.pem"),
    VIRKI_CSRF_SIGNING_KEY: "a".repeat(64),
    VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE: privateOidcConfigPath,
    VIRKI_OIDC_ISSUER: "https://portal.localhost",
    VIRKI_OIDC_BIND_ADDRESS: "127.0.0.1",
    OIDC_ISSUER_PORT: "3003",
    VIRKI_RATE_LIMIT_HASH_SECRET: "a".repeat(64),
    VIRKI_E2E_HUB_MODE: "production"
  };
  try {
    const hub = buildServiceEnvironment("hub", source, process.platform);
    const issuer = buildServiceEnvironment("issuer", { ...source, NODE_ENV: "development" }, process.platform);
    const publicSite = buildServiceEnvironment("public-site", source, process.platform);
    assert.equal(hub.NODE_ENV, "production");
    assert.equal(issuer.NODE_ENV, "production", "the production Hub and OIDC issuer must select the same host-only session cookie name");
    assert.equal(hub.VIRKI_E2E_HUB_MODE, "production");
    assert.equal(issuer.VIRKI_RATE_LIMIT_HASH_SECRET, source.VIRKI_RATE_LIMIT_HASH_SECRET, "production OIDC rate limits must receive their isolated HMAC key");
    assert.equal(hub.VIRKI_OIDC_ADAPTER_KEY, privateAdapterKey);
    assert.equal(Object.hasOwn(hub, "VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE"), false);
    assert.equal(Object.hasOwn(hub, "VIRKI_CORE_TEST_DATABASE_CONFIRM"), false);
    assert.equal(publicSite.NODE_ENV, "development");
    assert.equal(Object.hasOwn(publicSite, "VIRKI_E2E_HUB_MODE"), false);
    assert.equal(Object.hasOwn(publicSite, "VIRKI_OIDC_ADAPTER_KEY"), false);
    assert.throws(
      () => buildServiceEnvironment("hub", { ...source, VIRKI_CORE_TEST_DATABASE_CONFIRM: undefined }, process.platform),
      /explicit disposable-database marker/u,
      "production Hub E2E still requires the explicit disposable-database marker"
    );
    assert.throws(
      () => buildServiceEnvironment("issuer", { ...source, VIRKI_RATE_LIMIT_HASH_SECRET: undefined }, process.platform),
      /OIDC issuer E2E configuration is incomplete/u,
      "production OIDC issuer refuses to start without its rate-limit HMAC key"
    );
    assert.throws(
    () => buildServiceEnvironment("hub", { ...source, DATABASE_URL: "postgresql://virki_test@remote.example.invalid:5432/virki_e2e_test" }, process.platform),
      /local or isolated CI host/u,
      "production Hub E2E still refuses a remote database target"
    );
  } finally {
    rmSync(tlsDirectory, { recursive: true, force: true });
  }
});

test("production Hub proxy preserves no-store responses and forwards the browser's secure host", async () => {
  const productionHub = await import("./start-production-hub.mjs").catch(() => null);
  assert.ok(productionHub, "the production Hub adapter is available");
  assert.equal(typeof productionHub.createProductionHubProxyRequestHandler, "function");

  let forwardedHeaders;
  const upstream = createServer((request, response) => {
    forwardedHeaders = {
      host: request.headers.host,
      forwardedHost: request.headers["x-forwarded-host"],
      forwardedProto: request.headers["x-forwarded-proto"],
      forwardedFor: request.headers["x-forwarded-for"],
      cfConnectingIp: request.headers["cf-connecting-ip"]
    };
    response.writeHead(200, { "cache-control": "private, no-store, max-age=0, must-revalidate" });
    response.end("ready");
  });
  await new Promise((resolveListen, rejectListen) => {
    upstream.once("error", rejectListen);
    upstream.listen(0, "127.0.0.1", resolveListen);
  });
  const upstreamPort = upstream.address().port;
  const proxy = createServer(productionHub.createProductionHubProxyRequestHandler(upstreamPort));
  await new Promise((resolveListen, rejectListen) => {
    proxy.once("error", rejectListen);
    proxy.listen(0, "127.0.0.1", resolveListen);
  });

  try {
    const response = await new Promise((resolveResponse, rejectResponse) => {
      const request = httpRequest({
        hostname: "127.0.0.1",
        port: proxy.address().port,
        path: "/account/security",
        headers: {
          host: "portal.localhost:3001",
          "x-forwarded-proto": "http",
          "x-forwarded-for": "198.51.100.42",
          "cf-connecting-ip": "198.51.100.42"
        }
      }, (incoming) => {
        const chunks = [];
        incoming.on("data", (chunk) => chunks.push(chunk));
        incoming.on("end", () => resolveResponse({ statusCode: incoming.statusCode, cacheControl: incoming.headers["cache-control"], body: Buffer.concat(chunks).toString("utf8") }));
      });
      request.once("error", rejectResponse);
      request.end();
    });
    assert.deepEqual(forwardedHeaders, {
      host: "portal.localhost:3001",
      forwardedHost: "portal.localhost:3001",
      forwardedProto: "https",
      forwardedFor: "127.0.0.1",
      cfConnectingIp: "127.0.0.1"
    });
    assert.equal(response.statusCode, 200);
    assert.equal(response.cacheControl, "private, no-store, max-age=0, must-revalidate");
    assert.equal(response.body, "ready");
  } finally {
    await Promise.all([upstream, proxy].map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  }
});

test("production Hub E2E proxy establishes a fresh upstream TCP connection per request", async () => {
  const { createProductionHubProxyRequestHandler } = await import("./start-production-hub.mjs");
  const upstreamPorts = [];
  const upstream = createServer((request, response) => {
    upstreamPorts.push(request.socket.remotePort);
    request.resume();
    response.writeHead(200, { "cache-control": "no-store" });
    response.end("ok");
  });
  await new Promise((resolveListen, rejectListen) => {
    upstream.once("error", rejectListen);
    upstream.listen(0, "127.0.0.1", resolveListen);
  });
  const proxy = createServer(createProductionHubProxyRequestHandler(upstream.address().port));
  await new Promise((resolveListen, rejectListen) => {
    proxy.once("error", rejectListen);
    proxy.listen(0, "127.0.0.1", resolveListen);
  });

  const fetchThroughProxy = () => new Promise((resolveResponse, rejectResponse) => {
    const request = httpRequest({
      hostname: "127.0.0.1",
      port: proxy.address().port,
      path: "/api/health",
      headers: { host: "portal.localhost" }
    }, (response) => {
      response.resume();
      response.on("end", () => resolveResponse(response.statusCode));
    });
    request.once("error", rejectResponse);
    request.end();
  });

  try {
    assert.equal(await fetchThroughProxy(), 200);
    assert.equal(await fetchThroughProxy(), 200);
    assert.equal(upstreamPorts.length, 2);
    assert.equal(new Set(upstreamPorts).size, 2, "the proxy must not pool stale upstream sockets");
  } finally {
    await Promise.all([upstream, proxy].map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  }
});

test("production Hub E2E proxy closes OIDC interaction issuer sockets between GETs", async () => {
  const { createProductionHubProxyRequestHandler } = await import("./start-production-hub.mjs");
  const issuerSockets = [];
  const nextConnectionHeaders = [];
  const issuer = createServer((request, response) => {
    issuerSockets.push({ path: request.url, socket: request.socket });
    response.writeHead(303, { location: "/next", "cache-control": "no-store" });
    response.end();
  });
  await new Promise((resolveListen) => issuer.listen(0, "127.0.0.1", resolveListen));
  const issuerAgent = new Agent({ keepAlive: true });
  const next = createServer((request, response) => {
    nextConnectionHeaders.push({ path: request.url, connection: request.headers.connection });
    const issuerRequest = httpRequest({
      hostname: "127.0.0.1",
      port: issuer.address().port,
      path: request.url,
      method: request.method,
      headers: { ...request.headers, host: `127.0.0.1:${issuer.address().port}` },
      agent: issuerAgent
    }, (issuerResponse) => {
      response.writeHead(issuerResponse.statusCode, issuerResponse.headers);
      issuerResponse.pipe(response);
    });
    issuerRequest.once("error", (error) => response.destroy(error));
    request.pipe(issuerRequest);
  });
  await new Promise((resolveListen) => next.listen(0, "127.0.0.1", resolveListen));
  const proxy = createServer(createProductionHubProxyRequestHandler(next.address().port));
  await new Promise((resolveListen) => proxy.listen(0, "127.0.0.1", resolveListen));

  const fetch = (path) => new Promise((resolveResponse, rejectResponse) => {
    const request = httpRequest({
      hostname: "127.0.0.1",
      port: proxy.address().port,
      path,
      method: "GET",
      headers: { host: "portal.localhost", connection: "keep-alive" }
    }, (response) => {
      response.resume();
      response.once("end", () => resolveResponse(response.statusCode));
      response.once("error", rejectResponse);
    });
    request.once("error", rejectResponse);
    request.end();
  });
  try {
    for (const path of ["/api/health", "/api/health", "/interaction/abcdefgh", "/interaction/abcdefgh"]) {
      assert.equal(await fetch(path), 303);
    }
    assert.deepEqual(nextConnectionHeaders.map((item) => item.connection), ["keep-alive", "keep-alive", "close", "close"]);
    assert.equal(issuerSockets[0].socket, issuerSockets[1].socket, "ordinary GETs still reuse the issuer's live keep-alive socket");
    assert.notEqual(issuerSockets[2].socket, issuerSockets[3].socket, "consecutive interactions use different issuer sockets");
  } finally {
    issuerAgent.destroy();
    await Promise.all([proxy, next, issuer].map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  }
});

test("production Hub proxy records only sanitized upstream socket phase when OIDC interaction resets before headers", async () => {
  const { createProductionHubProxyRequestHandler } = await import("./start-production-hub.mjs");
  const attempts = [];
  const observedFailures = [];
  const upstream = createServer((request) => {
    attempts.push(request.method);
    request.socket.destroy();
  });
  await new Promise((resolveListen, rejectListen) => {
    upstream.once("error", rejectListen);
    upstream.listen(0, "127.0.0.1", resolveListen);
  });
  const proxy = createServer(createProductionHubProxyRequestHandler(
    upstream.address().port,
    undefined,
    (details) => observedFailures.push(details)
  ));
  await new Promise((resolveListen, rejectListen) => {
    proxy.once("error", rejectListen);
    proxy.listen(0, "127.0.0.1", resolveListen);
  });

  const marker = "HIGHLY_PRIVATE_E2E_INTERACTION_MARKER";
  const secretBody = "code=HIGHLY_PRIVATE_E2E_POST_BODY";
  try {
    const response = await new Promise((resolveResponse, rejectResponse) => {
      const request = httpRequest({
        hostname: "127.0.0.1",
        port: proxy.address().port,
        method: "POST",
        path: `/interaction/${marker}?state=${marker}`,
        headers: { host: "portal.localhost", "content-type": "application/x-www-form-urlencoded" }
      }, (incoming) => {
        const chunks = [];
        incoming.on("data", (chunk) => chunks.push(chunk));
        incoming.on("end", () => resolveResponse({ status: incoming.statusCode, cacheControl: incoming.headers["cache-control"], body: Buffer.concat(chunks).toString("utf8") }));
      });
      request.on("error", rejectResponse);
      request.end(secretBody);
    });
    assert.deepEqual(response, { status: 502, cacheControl: "no-store", body: "Hub unavailable" });
    assert.deepEqual(attempts, ["POST"], "a potentially state-changing OIDC interaction is never retried");
    assert.equal(observedFailures.length, 1);
    assert.equal(observedFailures[0].code, "ECONNRESET");
    assert.equal(observedFailures[0].method, "POST");
    assert.equal(observedFailures[0].route, "oidc-interaction");
    assert.equal(observedFailures[0].phase, "connected-before-headers");
    assert.equal(observedFailures[0].clientAborted, false);
    assert.equal(JSON.stringify(observedFailures).includes(marker), false);
    assert.equal(JSON.stringify(observedFailures).includes(secretBody), false);
    assert.deepEqual(Object.keys(observedFailures[0]).sort(), ["clientAborted", "code", "method", "phase", "route"]);
  } finally {
    await Promise.all([upstream, proxy].map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  }
});

test("production Hub proxy differentiates connection failure before TCP connect without leaking URL queries", async () => {
  const { createProductionHubProxyRequestHandler } = await import("./start-production-hub.mjs");
  const unused = createServer();
  await new Promise((resolveListen, rejectListen) => {
    unused.once("error", rejectListen);
    unused.listen(0, "127.0.0.1", resolveListen);
  });
  const disconnectedPort = unused.address().port;
  await new Promise((resolveClose) => unused.close(resolveClose));

  const observedFailures = [];
  const proxy = createServer(createProductionHubProxyRequestHandler(disconnectedPort, undefined, (details) => observedFailures.push(details)));
  await new Promise((resolveListen, rejectListen) => {
    proxy.once("error", rejectListen);
    proxy.listen(0, "127.0.0.1", resolveListen);
  });
  try {
    const response = await new Promise((resolveResponse, rejectResponse) => {
      const request = httpRequest({ hostname: "127.0.0.1", port: proxy.address().port, path: "/api/health?password=HIGHLY_PRIVATE", headers: { host: "portal.localhost" } }, (incoming) => {
        incoming.resume();
        incoming.on("end", () => resolveResponse(incoming.statusCode));
      });
      request.on("error", rejectResponse);
      request.end();
    });
    assert.equal(response, 502);
    assert.equal(observedFailures.length, 1);
    assert.equal(observedFailures[0].code, "ECONNREFUSED");
    assert.equal(observedFailures[0].phase, "tcp-connect-pending");
    assert.equal(observedFailures[0].route, "other");
    assert.equal(JSON.stringify(observedFailures).includes("HIGHLY_PRIVATE"), false);
  } finally {
    await new Promise((resolveClose) => proxy.close(resolveClose));
  }
});

test("Next child diagnostic preloader activates only in an isolated production E2E child", () => {
  const script = pathToFileURL(resolve(scriptDirectory, "start-production-hub.mjs")).href;
  const childCode = 'import http from "node:http"; process.stdout.write(String(http.request.name) + "\\n");';
  const runChild = (enabled) => spawnSync(process.execPath, ["--import", script, "--input-type=module", "-e", childCode], {
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_ENV: "production",
      VIRKI_E2E_HUB_MODE: "production",
      VIRKI_E2E_NEXT_ISSUER_DIAGNOSTICS: enabled ? "1" : "0"
    }
  });
  const enabled = runChild(true);
  assert.equal(enabled.status, 0, enabled.stderr);
  assert.match(enabled.stderr, /E2E_NEXT_ISSUER \{"event":"instrumented"\}/u);
  assert.match(enabled.stdout, /diagnosticHttpRequest/u);
  const disabled = runChild(false);
  assert.equal(disabled.status, 0, disabled.stderr);
  assert.doesNotMatch(disabled.stderr, /E2E_NEXT_ISSUER/u);
  assert.doesNotMatch(disabled.stdout, /diagnosticHttpRequest/u);
  const source = readFileSync(new URL("./start-production-hub.mjs", import.meta.url), "utf8");
  assert.match(source, /"--import",\s*pathToFileURL\(fileURLToPath\(import\.meta\.url\)\)\.href/u);
  assert.match(source, /VIRKI_E2E_NEXT_ISSUER_DIAGNOSTICS:\s*"1"/u);
});

test("Next child diagnostic records local upstream socket reuse and response lifecycle without credentials", async () => {
  const { installNextIssuerTransportDiagnostics } = await import("./start-production-hub.mjs");
  const captured = [];
  const received = [];
  const upstream = createServer((req, res) => {
    received.push({ path: req.url, cookie: req.headers.cookie, authorization: req.headers.authorization, peerPort: req.socket.remotePort });
    req.resume();
    res.writeHead(303, { location: "/auth?code=PRIVATE_RESPONSE_CODE", "set-cookie": "private=PRIVATE_RESPONSE_COOKIE" });
    res.end();
  });
  await new Promise((resolveListen) => upstream.listen(0, "127.0.0.1", resolveListen));
  const agent = new Agent({ keepAlive: true });
  const mockHttp = { request: (...args) => httpRequest(...args) };
  const original = mockHttp.request;
  const stop = installNextIssuerTransportDiagnostics({
    httpModule: mockHttp,
    issuerPort: upstream.address().port,
    emit: (item) => captured.push(item)
  });
  const syntheticMarker = "fixture-sensitive-payload-marker";
  const send = () => new Promise((resolveResponse, rejectResponse) => {
    const req = mockHttp.request({
      hostname: "127.0.0.1",
      port: upstream.address().port,
      agent,
      method: "POST",
      path: `/interaction/abcdefgh?state=${syntheticMarker}`,
      headers: { cookie: `virki_session=${syntheticMarker}`, authorization: `Bearer ${syntheticMarker}`, "content-type": "text/plain" }
    }, (res) => {
      res.resume();
      res.on("end", () => resolveResponse(res.statusCode));
    });
    req.once("error", rejectResponse);
    req.end(syntheticMarker);
  });
  try {
    assert.equal(await send(), 303);
    assert.equal(await send(), 303);
    assert.equal(received.length, 2);
    assert.equal(received[0].peerPort, received[1].peerPort, "real agent reused its upstream socket");
    assert.ok(received.every((entry) => entry.cookie?.includes(syntheticMarker) && entry.authorization?.includes(syntheticMarker) && entry.path?.includes(syntheticMarker)), "request semantics unchanged");
    assert.ok(captured.some((event) => event.event === "socket" && event.reused === true), "reused socket detected");
    assert.equal(captured.filter((event) => event.event === "response" && event.status === 303).length, 2);
    assert.equal(captured.filter((event) => event.event === "response-end").length, 2);
    assert.ok(captured.every((event) => Object.keys(event).every((key) => ["event", "request", "socket", "route", "method", "reused", "connecting", "status", "code", "hadError", "complete"].includes(key))));
    const serialized = JSON.stringify(captured);
    for (const sensitive of [syntheticMarker, "PRIVATE_RESPONSE_CODE", "PRIVATE_RESPONSE_COOKIE", "Bearer", "virki_session", "127.0.0.1", String(upstream.address().port)]) {
      assert.equal(serialized.includes(sensitive), false, `no diagnostic leakage: ${sensitive}`);
    }
    assert.ok(captured.every((event) => !Object.values(event).some((value) => typeof value === "string" && value.includes("/interaction/"))));
  } finally {
    stop();
    assert.equal(mockHttp.request, original, "installed hook is reversible");
    agent.destroy();
    await new Promise((resolveClose) => upstream.close(resolveClose));
  }
});

test("Next child diagnostic classifies true issuer reset without swallowing errors, request retry or leaking errors", async () => {
  const { installNextIssuerTransportDiagnostics } = await import("./start-production-hub.mjs");
  let attempts = 0;
  const upstream = createServer((req) => {
    attempts++;
    req.socket.destroy(Object.assign(new Error("PRIVATE_ERROR_MESSAGE"), { code: "ECONNRESET" }));
  });
  await new Promise((resolveListen) => upstream.listen(0, "127.0.0.1", resolveListen));
  const captured = [];
  const httpModule = { request: (...args) => httpRequest(...args) };
  const stop = installNextIssuerTransportDiagnostics({ httpModule, issuerPort: upstream.address().port, emit: (event) => captured.push(event) });
  try {
    const error = await new Promise((resolveError, rejectError) => {
      const request = httpModule.request({ hostname: "127.0.0.1", port: upstream.address().port, path: "/interaction/abcdefgh?token=PRIVATE_ERROR_MESSAGE" }, () => rejectError(new Error("unexpected response")));
      request.once("error", resolveError);
      request.end();
    });
    assert.equal(error.code, "ECONNRESET", "caller observes unchanged transport failure");
    assert.equal(attempts, 1, "diagnostic never retries OAuth");
    assert.ok(captured.some((event) => event.event === "request-error" && event.code === "ECONNRESET"));
    assert.equal(JSON.stringify(captured).includes("PRIVATE_ERROR_MESSAGE"), false);
  } finally {
    stop();
    await new Promise((resolveClose) => upstream.close(resolveClose));
  }
});

test("production Hub proxy exposes only the synthetic Access fixture endpoints on its dedicated host", async () => {
  const productionHub = await import("./start-production-hub.mjs");
  const accessRequests = [];
  const hubRequests = [];
  const accessFixture = createServer((request, response) => {
    accessRequests.push({ method: request.method, url: request.url });
    if (request.method === "GET" && request.url === "/cdn-cgi/access/certs") {
      response.writeHead(200, { "cache-control": "no-store", "content-type": "application/json" }).end('{"keys":[]}');
      return;
    }
    if (request.method === "POST" && request.url === "/__test__/keys") {
      request.resume();
      response.writeHead(204).end();
      return;
    }
    response.writeHead(404).end();
  });
  const hub = createServer((request, response) => {
    hubRequests.push({ method: request.method, url: request.url, host: request.headers.host });
    response.writeHead(200).end("hub-fixture");
  });
  for (const server of [accessFixture, hub]) {
    await new Promise((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(0, "127.0.0.1", resolveListen);
    });
  }
  const proxy = createServer(productionHub.createProductionHubProxyRequestHandler(hub.address().port, accessFixture.address().port));
  await new Promise((resolveListen, rejectListen) => {
    proxy.once("error", rejectListen);
    proxy.listen(0, "127.0.0.1", resolveListen);
  });

  const request = (method, path, host) => new Promise((resolveResponse, rejectResponse) => {
    const incoming = httpRequest({
      hostname: "127.0.0.1",
      port: proxy.address().port,
      method,
      path,
      headers: { host }
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolveResponse({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    incoming.once("error", rejectResponse);
    incoming.end();
  });

  try {
    assert.deepEqual(await request("GET", "/cdn-cgi/access/certs", "access.e2e.invalid"), {
      status: 200,
      body: '{"keys":[]}'
    });
    assert.deepEqual(await request("POST", "/__test__/keys", "access.e2e.invalid"), { status: 204, body: "" });
    assert.deepEqual(await request("GET", "/__test__/keys", "access.e2e.invalid"), { status: 200, body: "hub-fixture" });
    assert.deepEqual(await request("GET", "/cdn-cgi/access/certs", "other.e2e.invalid"), { status: 200, body: "hub-fixture" });
    assert.deepEqual(accessRequests, [
      { method: "GET", url: "/cdn-cgi/access/certs" },
      { method: "POST", url: "/__test__/keys" }
    ]);
    assert.deepEqual(hubRequests, [
      { method: "GET", url: "/__test__/keys", host: "access.e2e.invalid" },
      { method: "GET", url: "/cdn-cgi/access/certs", host: "other.e2e.invalid" }
    ]);
  } finally {
    await Promise.all([accessFixture, hub, proxy].map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  }
});

test("production E2E runner resolves its synthetic Access host to container loopback", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  assert.match(script, /if \(\$env:VIRKI_E2E_HUB_MODE -eq 'production'\)\s*\{\s*\$runnerCreateArguments \+= @\('--add-host', 'access\.e2e\.invalid:127\.0\.0\.1'\)/u);
  const playwrightConfig = readFileSync(new URL("../../playwright.config.mts", import.meta.url), "utf8");
  assert.match(playwrightConfig, /productionHubMode \? "https:\/\/access\.e2e\.invalid" : "http:\/\/127\.0\.0\.1:3010"/u);
  assert.match(playwrightConfig, /subjectAltName=DNS:portal\.localhost,DNS:hub\.localhost,DNS:access\.e2e\.invalid,IP:127\.0\.0\.1/u);
});

test("isolated Chromium and Node route.fetch agree on runner-local Portal and Hub addresses", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  const normalized = script.replace(/\r\n/gu, "\n");
  const createStart = normalized.indexOf("$runnerCreateArguments = @('create'");
  const createEnd = normalized.indexOf("$runnerName = Invoke-CreateOwnedDockerResource 'runner'", createStart);
  assert.ok(createStart >= 0 && createEnd > createStart,
    "inspect only the actual owned runner creation arguments, never an earlier unrelated stage guard");
  const runnerCreation = normalized.slice(createStart, createEnd);
  assert.match(runnerCreation, /if \(-not \$IntegrationOnly -and -not \$UnitOnly\) \{\n(?:\s*#[^\n]*\n)*\s*\$runnerCreateArguments \+= @\('--add-host', 'portal\.localhost:127\.0\.0\.1',\s*'--add-host', 'hub\.localhost:127\.0\.0\.1'\)\n\s*\}/u,
    "both Node aliases must be inside the explicit browser-only guard on the disposable runner");
  assert.equal((runnerCreation.match(/'portal\.localhost:127\.0\.0\.1'/gu) ?? []).length, 1,
    "a browser-only alias must not also appear unguarded in the runner arguments");
  assert.equal((runnerCreation.match(/'hub\.localhost:127\.0\.0\.1'/gu) ?? []).length, 1,
    "the Hub alias must not also appear outside the browser-only guard");
  const config = readFileSync(new URL("../../playwright.config.mts", import.meta.url), "utf8");
  assert.match(config, /--host-resolver-rules=MAP portal\.localhost 127\.0\.0\.1,MAP hub\.localhost 127\.0\.0\.1/u);
});

test("isolated Linux runner clones the current local branch instead of a fixed repository branch", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  assert.match(script, /git -C \$repoRoot branch --show-current/u);
  assert.match(script, /git clone --branch \$repositoryBranch/u);
  const clonedHeadCheckIndex = script.indexOf("$clonedHeadOutput = Invoke-PinnedDocker exec --workdir /workspace $runnerName git rev-parse HEAD");
  const patchApplyIndex = script.indexOf("git apply --binary /tmp/staged.patch");
  assert.ok(clonedHeadCheckIndex !== -1 && patchApplyIndex > clonedHeadCheckIndex, "the cloned base HEAD is verified before local patches are applied");
  assert.ok(script.includes("$clonedHead -cne $sourceHead"), "the isolated clone must match the captured source commit");
  assert.doesNotMatch(script, /--branch cdx\/virki-open-issues/u);
});

test("isolated Linux runner snapshots every local Git input from the resolved repository root", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  for (const command of ["bundle create", "diff --cached", "diff --binary", "ls-files --others"]) {
    assert.ok(script.includes(`git -C $repoRoot ${command}`), command);
  }
  assert.doesNotMatch(script, /& git (?:bundle|diff|ls-files)/u);
});

test("isolated Linux snapshot explicitly permits this remediation's new source and test files", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  for (const file of [
    "apps/hub/src/lib/login-redirect.test.ts",
    "apps/hub/src/lib/login-redirect.ts",
    "apps/issuer/src/interaction-error.test.ts",
    "apps/issuer/src/interaction-error.ts",
    "apps/issuer/src/provider-audit.test.ts",
    "apps/issuer/src/provider-audit.ts",
    "apps/public-site/src/app/public-origin.test.ts",
    "apps/public-site/src/app/public-origin.ts",
    "packages/auth/src/elevation-authorization.ts",
    "packages/auth/src/legacy-data-inventory.integration.test.ts",
    "scripts/e2e/redact-browser-e2e-log.mjs",
    "scripts/e2e/start-production-hub.mjs",
    "scripts/admin-elevation-boundary.test.mjs"
  ]) assert.ok(script.includes(`'${file}'`), file);
});

test("isolated runner journals reviewed Docker create operations and removes verified resource identities", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  for (const kind of ["network", "bootstrapNetwork", "database", "browserSeed", "runner"]) {
    assert.ok(script.includes(`Invoke-CreateOwnedDockerResource '${kind}'`), `${kind} creation is reviewed`);
    assert.ok(script.includes(`'${kind}'`), `${kind} has a named owner record`);
  }
  assert.match(script, /Write-DockerMutationJournal 'MUTATION_PENDING'/u);
  assert.match(script, /Write-DockerMutationJournal 'MUTATION_ACKNOWLEDGED'/u);
  assert.match(script, /Write-DockerMutationJournal 'RECONCILIATION_REQUIRED'/u);
  assert.match(script, /Assert-OwnedDockerIdentity \$Kind \$name \$id \$id/u);
  assert.match(script, /Invoke-PinnedDocker container rm --force --volumes \$id/u);
  assert.match(script, /type=volume,target=\/ms-playwright\/chromium_headless_shell-1243/u);
  assert.match(script, /Docker-managed anonymous browser volume was not removed/u);
  assert.doesNotMatch(script, /Invoke-PinnedDocker volume rm/u,
    "Docker volume names are mutable; cleanup must use the owned seed's immutable ID");
  assert.match(script, /if \(-not \$script:ownedResources\[\$Kind\]\) \{ return \}/u);
});

test("isolated Windows Docker runner pins a signed absolute CLI and local endpoint on every invocation", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  assert.match(script, /C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker\.exe/u);
  assert.match(script, /Get-AuthenticodeSignature/u);
  assert.match(script, /npipe:\/\/\/\/\.\/pipe\/dockerDesktopLinuxEngine/u);
  assert.match(script, /function Invoke-PinnedDocker/u);
  assert.match(script, /& \$script:dockerCli --host \$script:dockerHost @args/u);
  assert.doesNotMatch(script, /& docker(?:\s|\r|\n)/u, "no mutable PATH Docker command may remain");
});

test("isolated Windows runner refuses cleanup by mutable Docker resource names", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  assert.match(script, /function Invoke-OwnedDockerCleanup/u);
  assert.match(script, /org\.virki\.e2e\.owner/u);
  assert.match(script, /MUTATION_PENDING/u);
  assert.doesNotMatch(script, /docker rm --force --volumes \$runnerName/u);
  assert.doesNotMatch(script, /docker rm --force --volumes \$databaseName/u);
  assert.doesNotMatch(script, /docker volume rm \$browserVolumeName/u);
  assert.doesNotMatch(script, /docker network rm \$networkName/u);
});

test("isolated runner retains complete TAP output for integration and production-operations stages", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  assert.ok(/Write-Output \("ISOLATED_RUN_ID=" \+ \$runId\)/u.test(script), "runner emits its unique run ID");
  assert.ok(/durationMs\s*=/u.test(script), "stage manifest records elapsed time");
  assert.ok(script.includes("STAGE_MANIFEST_JSON="), "runner emits a machine-readable stage manifest");
  assert.ok(script.includes("production-operations-tests.tap.log"), "complete TAP output has a durable artifact path");
  assert.ok(script.includes("integration-tests.tap.log"), "integration TAP output has a durable artifact path");
  assert.ok(script.includes("function Get-TapFailureManifest"), "retained TAP failures are parsed into structured entries");
  assert.match(script, /productionOperationsFailures\s*=\s*@\(\$script:productionOperationsFailures\)/u, "the durable manifest includes named TAP failures and nesting data");
  assert.match(script, /productionOperationsFailureCount\s*=\s*\$script:productionOperationsFailures\.Count/u, "the durable manifest counts every TAP failure entry");
  assert.match(script, /integrationTestsFailures\s*=\s*@\(\$script:integrationTestFailures\)/u, "the durable manifest includes named integration TAP failures");
  assert.match(script, /integrationTestsLog\s*=\s*if \(Test-Path -LiteralPath \$integrationTestsEvidencePath\)/u, "the durable manifest points to the integration TAP artifact");
  assert.match(script, /integrationTestsFailureCount\s*=\s*\$script:integrationTestFailures\.Count/u, "the durable manifest counts integration TAP failures");
  assert.ok(script.includes("run-manifest.json"), "run metadata has a durable artifact path");
  assert.ok(script.includes(".virki-mission-tmp/isolated-runs"), "artifacts are stored in the ignored mission evidence area");
  assert.ok(script.includes("An isolated integration test file requires -IntegrationOnly."), "targeted integration runs are restricted to the integration-only stage");
  assert.ok(script.includes("*.integration.test.ts"), "targeted integration runs accept only integration test files");
  assert.ok(script.includes("Join-Path $evidenceRoot $runId"), "each run gets a unique artifact directory");
  assert.ok(/Invoke-LoggedStage -Name 'production-operations-tests'[^\r\n]*-EvidenceLogPath \$productionOperationsEvidencePath -CaptureFullOutput/u.test(script), "production-operations output is retained without truncation");
  assert.ok(/Invoke-LoggedStage -Name 'integration-tests'[^\r\n]*-EvidenceLogPath \$integrationTestsEvidencePath -CaptureFullOutput/u.test(script), "integration output is retained without truncation");
  assert.ok(/\[System\.IO\.File\]::WriteAllLines\(\$EvidenceLogPath, \$stageLines/u.test(script), "captured output is written to the artifact");
  for (const field of ["runId", "sourceBranch", "sourceHead", "startedUtc", "finishedUtc", "nodeVersion", "npmVersion", "stagedPatchSha256", "workingTreePatchSha256", "untrackedFiles", "exitCode", "failedStages", "stages"]) {
    assert.match(script, new RegExp(`\\b${field}\\s*=`, "u"), `run manifest includes ${field}`);
  }
  assert.match(script, /Get-FileSha256 -LiteralPath \$stagedPatchPath/u, "staged changes are identified by content hash");
  assert.match(script, /Get-FileSha256 -LiteralPath \$workingPatchPath/u, "unstaged changes are identified by content hash");
  assert.match(script, /Copy-Item -LiteralPath \(Join-Path \$repoRoot \$relativePath\) -Destination \$snapshotPath/u, "untracked source bytes are frozen before hashing");
  assert.match(script, /Get-FileSha256 -LiteralPath \$untrackedPath/u, "the copied untracked snapshot is identified by content hash");
  assert.match(script, /path = \$relativePath\.Replace\('\\', '\/'\)/u, "untracked paths are normalized for the manifest");
  assert.match(script, /Assert-RunnerFileSha256 '\/tmp\/staged\.patch' \$script:stagedPatchSha256/u, "the staged patch hash is verified after Docker copy");
  assert.match(script, /Assert-RunnerFileSha256 '\/tmp\/working-tree\.patch' \$script:workingTreePatchSha256/u, "the unstaged patch hash is verified after Docker copy");
  assert.match(script, /Assert-RunnerFileSha256 \('\/workspace\/' \+ \$relativeManifestPath\) \$expectedFile\.sha256/u, "each untracked file hash is verified after Docker copy");
  assert.match(script, /Sort-Object -Property path -Culture 'en-US' -CaseSensitive/u, "untracked provenance is deterministically sorted");
  const manifestWriteIndex = script.indexOf("[System.IO.File]::WriteAllText($runManifestPath");
  const cleanupIndex = script.indexOf("Invoke-OwnedDockerCleanup $resourceKind");
  assert.ok(manifestWriteIndex !== -1 && cleanupIndex > manifestWriteIndex, "artifacts are persisted before owned-container cleanup");
  assert.match(script, /WriteAllText\(\$runManifestPath[\s\S]*?\} finally \{\s*Write-Output "[^\r\n]*Removing only independently verified owned Docker IDs\."/u, "owned-resource cleanup has its own finally block around evidence persistence");
});

test("A02 must exercise first ADMIN bootstrap with a real cloned virgin PostgreSQL database", () => {
  const runner = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  const testSource = readFileSync(new URL("../../packages/auth/src/bootstrap-first-admin.integration.test.ts", import.meta.url), "utf8");
  assert.match(runner, /CREATE DATABASE virki_bootstrap_virgin WITH TEMPLATE virki_e2e_test/u);
  assert.match(runner, /REVOKE ALL ON DATABASE virki_bootstrap_virgin FROM PUBLIC/u);
  assert.match(runner, /GRANT CONNECT ON DATABASE virki_bootstrap_virgin TO virki_runtime_test/u);
  assert.match(runner, /VIRKI_BOOTSTRAP_TEST_DATABASE_CONFIRM=virgin/u);
  assert.match(runner, /npm run test:integration -- packages\/auth\/src\/bootstrap-first-admin\.integration\.test\.ts/u);
  assert.match(testSource, /current_database\(\) AS database/u);
  assert.match(testSource, /virki_bootstrap_virgin/u);
  const migrated = runner.indexOf("Committed migrations did not apply to the disposable database.");
  const cloned = runner.indexOf("CREATE DATABASE virki_bootstrap_virgin WITH TEMPLATE virki_e2e_test");
  const executed = runner.indexOf("-Name 'bootstrap-virgin-tests'");
  const shared = runner.indexOf("-Name 'integration-tests'");
  assert.ok(migrated !== -1 && cloned > migrated && executed > cloned && shared > executed,
    "real bootstrap must use the freshly migrated schema before the shared integration suite");
  assert.match(runner, /Invoke-OwnedDockerCleanup/u, "the independent database must remain confined to owned Docker cleanup");
});

test("browser E2E output redacts URL queries, fragments and credential-bearing headers", () => {
  const input = [
    'Error: page.goto failed at https://hub.localhost/recover/open?request=SAFE_TEST_VALUE&next=%2Fadmin#one-time-proof',
    'Relative path /auth/callback?code=SAFE_TEST_CODE&state=SAFE_TEST_STATE was rejected.',
    'Authorization: Bearer SAFE_TEST_BEARER',
    'Set-Cookie: session=SAFE_TEST_COOKIE; Secure; HttpOnly',
    'ordinary failure: net::ERR_CONNECTION_REFUSED at https://hub.localhost/admin/connections'
  ].join("\n");

  const actual = redactBrowserE2ELog(input);

  assert.equal(actual, [
    'Error: page.goto failed at https://hub.localhost/recover/open?[REDACTED_QUERY]',
    'Relative path /auth/callback?[REDACTED_QUERY] was rejected.',
    'Authorization: [REDACTED]',
    'Set-Cookie: [REDACTED]',
    'ordinary failure: net::ERR_CONNECTION_REFUSED at https://hub.localhost/admin/connections'
  ].join("\n"));
  for (const marker of ["SAFE_TEST_VALUE", "SAFE_TEST_CODE", "SAFE_TEST_STATE", "SAFE_TEST_BEARER", "SAFE_TEST_COOKIE", "one-time-proof"]) {
    assert.equal(actual.includes(marker), false, `log output does not retain ${marker}`);
  }
});

test("full isolated runner stores complete browser output only after redaction", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  assert.match(script, /npm run test:e2e -- "\$@" 2>&1 \| node scripts\/e2e\/redact-browser-e2e-log\.mjs > \/tmp\/browser-e2e\.log/u);
  assert.match(script, /status=\$\?; cat \/tmp\/browser-e2e\.log; exit \$status/u);
});

test("isolated tooling stage redirects the entire compound command, never loses its first failure", () => {
  const script = readFileSync(new URL("./run-isolated-linux-docker.ps1", import.meta.url), "utf8");
  assert.match(script, /\$shellCommand = '\( ' \+ \$CommandText \+ ' \) > \/tmp\/' \+ \$LogName \+ '\.log 2>&1; status=\$\?; ' \+ \$logOutputCommand/u);
  assert.match(script, /'tooling-policy-tests' 'tooling-policy' 'node scripts\/tooling-audit-policy\.mjs && node --test scripts\/tooling-audit-policy\.test\.mjs'/u);
  assert.doesNotMatch(script, /\$shellCommand = \$CommandText \+ ' > \/tmp\/'/u,
    "a failing first command must not leave the log absent");
});
