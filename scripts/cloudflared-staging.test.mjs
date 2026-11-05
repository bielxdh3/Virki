import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { assertLocalDockerEndpoint, assertTlsVerification, cleanupDisposableHelpers, cleanupDisposableProject, helperDockerRunArgs, latestQuickHostname, validateNamedStaging, verifyStagingAccount } from "./cloudflared-staging.mjs";

const id = "fe2d9637-ab64-422a-bc7b-9da9b5bdc926";
const accountId = "a".repeat(32);
const zoneId = "b".repeat(32);
const makeToken = (t = id) => Buffer.from(JSON.stringify({ a: accountId, t, s: "fake-test-secret" })).toString("base64url");
const valid = {
  VIRKI_PR92_STAGING_TUNNEL_TOKEN: makeToken(),
  VIRKI_PR92_STAGING_TUNNEL_ID: id,
  VIRKI_PR92_STAGING_ACCOUNT_ID: accountId,
  VIRKI_PR92_STAGING_ZONE_ID: zoneId,
  VIRKI_PR92_STAGING_READ_TOKEN: "dummy-test-read-only-token",
  VIRKI_PR92_STAGING_PURPOSE: "isolated-disposable-issue-92",
  VIRKI_PR92_PUBLIC_HOST: "pr92-public.check123.staging.example.net",
  VIRKI_PR92_HUB_HOST: "pr92-hub.check123.staging.example.net",
  VIRKI_PR92_ISSUER_HOST: "pr92-issuer.check123.staging.example.net",
};

test("named-tunnel mode refuses absent staging token and attestation before Docker", () => {
  assert.throws(() => validateNamedStaging({ ...valid, VIRKI_PR92_STAGING_TUNNEL_TOKEN: "" }), /staging tunnel token/i);
  assert.throws(() => validateNamedStaging({ ...valid, VIRKI_PR92_STAGING_PURPOSE: "" }), /isolated disposable/i);
});

test("named-tunnel mode requires a separate exact tunnel identity and never accepts mismatched tokens", () => {
  assert.throws(() => validateNamedStaging({ ...valid, VIRKI_PR92_STAGING_TUNNEL_ID: "af807478-f3a8-4fd1-9b22-923649c6ee89" }), /tunnel identity mismatch/i);
  assert.throws(() => validateNamedStaging({ ...valid, VIRKI_PR92_STAGING_TUNNEL_TOKEN: "bogus" }), /staging tunnel token/i);
  assert.equal(validateNamedStaging(valid).tunnelId, id);
});

test("all hosts must be unique, staged, exact-service and share their own disposable suffix", () => {
  const negatives = [
    { VIRKI_PR92_HUB_HOST: "hub.biel.dev.br" },
    { VIRKI_PR92_PUBLIC_HOST: "biel.dev.br" },
    { VIRKI_PR92_ISSUER_HOST: "pr92-hub.check123.staging.example.net" },
    { VIRKI_PR92_ISSUER_HOST: "pr92-issuer.other.staging.example.net" },
    { VIRKI_PR92_PUBLIC_HOST: "pr92-public.check123.staging.example.net:443" },
    { VIRKI_PR92_HUB_HOST: "pr92-hub.check123.stage.example.net" },
  ];
  for (const mutation of negatives) assert.throws(() => validateNamedStaging({ ...valid, ...mutation }), /staging host/i);
});

test("read-only account attestation accepts exact 3 routes, tenant, tunnel and proxied tunnel CNAMEs", async () => {
  const { routes, tunnelId } = validateNamedStaging(valid);
  const seen = [];
  const answer = (url) => {
    seen.push(url);
    if (url.endsWith(`/cfd_tunnel/${id}`)) return { id, account_tag: accountId, config_src: "cloudflare", name: "virki-pr92-disposable-test" };
    if (url.endsWith(`/cfd_tunnel/${id}/configurations`)) return { config: { ingress: [
      ...routes.map(({ hostname, target }) => ({ hostname, service: target })), { service: "http_status:404" },
    ] } };
    return [{ name: decodeURIComponent(new URL(url).searchParams.get("name")), type: "CNAME", proxied: true, content: `${tunnelId}.cfargotunnel.com` }];
  };
  const requester = async (url, init) => {
    assert.equal(init.redirect, "error");
    assert.equal(init.headers.Authorization, "Bearer dummy-test-read-only-token");
    return { ok: true, json: async () => ({ success: true, result: answer(url) }) };
  };
  await verifyStagingAccount(validateNamedStaging(valid), valid.VIRKI_PR92_STAGING_READ_TOKEN, requester);
  assert.equal(seen.length, 5);
  assert.ok(seen.every((url) => url.startsWith("https://api.cloudflare.com/client/v4/")));
});

test("read-only attestation rejects another tunnel, extra production routes and misrouted CNAME", async () => {
  const expected = validateNamedStaging(valid);
  const cases = [
    { mutation: "metadata", message: /ownership\/name\/config/u },
    { mutation: "ingress", message: /ingress/u },
    { mutation: "dns", message: /staging DNS/u },
  ];
  for (const { mutation, message } of cases) {
    const requester = async (url) => {
      if (url.endsWith(`/cfd_tunnel/${id}`)) return { ok: true, json: async () => ({ success: true, result: {
        id, account_tag: accountId, config_src: "cloudflare", name: mutation === "metadata" ? "live-production" : "virki-pr92-isolated",
      } }) };
      if (url.endsWith(`/cfd_tunnel/${id}/configurations`)) return { ok: true, json: async () => ({ success: true, result: { config: { ingress: [
        ...expected.routes.map((item) => ({ hostname: item.hostname, service: item.target })),
        ...(mutation === "ingress" ? [{ hostname: "hub.biel.dev.br", service: "http://hub:3001" }] : []),
        { service: "http_status:404" },
      ] } } }) };
      return { ok: true, json: async () => ({ success: true, result: [{
        name: new URL(url).searchParams.get("name"), type: "CNAME", proxied: true,
        content: mutation === "dns" ? "other-tunnel.cfargotunnel.com" : `${id}.cfargotunnel.com`,
      }] }) };
    };
    await assert.rejects(() => verifyStagingAccount(expected, "token", requester), message);
  }
});

test("Quick Tunnel restart waits for the newest URL and cannot reuse stale log entries", () => {
  const first = "first-example.trycloudflare.com";
  const second = "second-example.trycloudflare.com";
  const initial = `https://${first}`;
  const appended = `${initial}\nhttps://${second}`;
  assert.equal(latestQuickHostname(initial), first);
  assert.equal(latestQuickHostname(initial, first), null);
  assert.equal(latestQuickHostname(appended, first), second);
  assert.equal(latestQuickHostname(appended, second), null);
});

test("Docker guard refuses remote SSH/TCP contexts, remote host overrides and TLS before daemon operations", () => {
  const safeWindows = "npipe:////./pipe/dockerDesktopLinuxEngine";
  const safeLinux = "unix:///var/run/docker.sock";
  assert.doesNotThrow(() => assertLocalDockerEndpoint(safeWindows, {}));
  assert.doesNotThrow(() => assertLocalDockerEndpoint(safeLinux, {}));
  assert.throws(() => assertLocalDockerEndpoint("ssh://admin@live-production", {}), /remote or unknown Docker context/i);
  assert.throws(() => assertLocalDockerEndpoint("tcp://127.0.0.1:2375", {}), /remote or unknown Docker context/i);
  assert.throws(() => assertLocalDockerEndpoint(safeWindows, { DOCKER_HOST: "tcp://10.0.0.5:2376" }), /remote or unknown DOCKER_HOST/i);
  assert.throws(() => assertLocalDockerEndpoint(safeLinux, { DOCKER_HOST: "ssh://example" }), /remote or unknown DOCKER_HOST/i);
  assert.throws(() => assertLocalDockerEndpoint(safeWindows, { DOCKER_CONTEXT: "production-ssh" }), /DOCKER_CONTEXT override/i);
  assert.throws(() => assertLocalDockerEndpoint(safeWindows, { DOCKER_CONFIG: "C:\\remote-config" }), /DOCKER_CONFIG override/i);
  assert.throws(() => assertLocalDockerEndpoint(safeWindows, { DOCKER_TLS_VERIFY: "1" }), /TLS\/certificate override/i);
});

test("Cloudflare evidence refuses disabled Node TLS certificate verification", () => {
  assert.doesNotThrow(() => assertTlsVerification({}));
  assert.throws(() => assertTlsVerification({ NODE_TLS_REJECT_UNAUTHORIZED: "0" }), /TLS certificate validation must remain enabled/u);
});

test("failed Compose down or surviving labeled containers/networks is fatal, even after successful tests", async () => {
  const project = "vrkpr92f00d1234567890";
  const compose = ["compose", "--project-name", project];
  const downFails = async (args) => {
    if (args.includes("down")) throw new Error("simulated Docker daemon unavailable during cleanup");
    return { stdout: "" };
  };
  await assert.rejects(() => cleanupDisposableProject(compose, project, {}, downFails), /cleanup could not be verified/u);

  const remnants = async (args) => {
    if (args.includes("down")) return { stdout: "" };
    if (args[0] === "ps") return { stdout: "stale-container-id" };
    return { stdout: "stale-network-id" };
  };
  await assert.rejects(() => cleanupDisposableProject(compose, project, {}, remnants), /cleanup left labeled resources/u);
});

test("standalone helper cleanup targets only exact per-run owned Docker container IDs and verifies no survivor", async () => {
  const project = "vrkpr92f00d1234567890";
  assert.deepEqual(helperDockerRunArgs(project), ["--label", `org.virki.pr92.project=${project}`]);
  assert.throws(() => helperDockerRunArgs("other-project"), /Invalid isolated/u);
  const ownedId = "a".repeat(12);
  const argsSeen = [];
  let removed = false;
  const runner = async (args) => {
    argsSeen.push(args);
    if (args[0] === "ps") return { stdout: removed ? "" : ownedId };
    if (args[0] === "rm") {
      assert.deepEqual(args, ["rm", "-f", ownedId]);
      removed = true;
    }
    return { stdout: "" };
  };
  await cleanupDisposableHelpers(project, {}, runner);
  assert.equal(argsSeen.filter((args) => args[0] === "ps").length, 2);
  assert.ok(argsSeen.every((args) => args[0] !== "ps" || args.includes(`label=org.virki.pr92.project=${project}`)));
  await assert.rejects(() => cleanupDisposableHelpers(project, {}, async (args) => ({
    stdout: args[0] === "ps" ? ownedId : "",
  })), /helper cleanup left containers/u);
});

test("disposable mock rejects wrong Host and nonce and never returns useful non-probe responses", async () => {
  const program = fileURLToPath(new URL("../infra/cloudflare/staging/mock-origin.mjs", import.meta.url));
  const child = spawn(process.execPath, [program], {
    env: { ...process.env, VIRKI_PR92_MOCK_SERVICE: "hub", VIRKI_PR92_MOCK_HOST: valid.VIRKI_PR92_HUB_HOST, VIRKI_PR92_MOCK_NONCE: "random-test-nonce", VIRKI_PR92_MOCK_PORT: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let port;
  try {
    port = await Promise.race([
      new Promise((resolvePort, reject) => {
        child.stdout.setEncoding("utf8");
        child.stdout.once("data", (data) => {
          const found = data.match(/^READY (\d+)/u);
          if (!found) reject(new Error("mock did not report readiness"));
          else resolvePort(Number(found[1]));
        });
        child.once("exit", (code) => reject(new Error(`mock exited ${code}`)));
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("mock startup timeout")), 5000)),
    ]);
    const request = (host, route) => new Promise((resolveResponse, reject) => {
      const req = httpRequest({ hostname: "127.0.0.1", port, path: route, method: "GET", headers: { Host: host } }, (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolveResponse({
          status: response.statusCode,
          headers: { get: (key) => response.headers[key.toLowerCase()] },
          json: async () => JSON.parse(Buffer.concat(chunks).toString("utf8")),
        }));
      });
      req.once("error", reject);
      req.end();
    });
    const path = "/__virki_pr92_probe/random-test-nonce";
    const allowed = await request(valid.VIRKI_PR92_HUB_HOST, path);
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers.get("cache-control"), "no-store");
    assert.deepEqual(await allowed.json(), { service: "hub", nonce: "random-test-nonce" });
    assert.equal((await request(valid.VIRKI_PR92_PUBLIC_HOST, path)).status, 421);
    assert.equal((await request(valid.VIRKI_PR92_HUB_HOST, "/__virki_pr92_probe/old-nonce")).status, 404);
    assert.equal((await request(valid.VIRKI_PR92_HUB_HOST, "/")).status, 404);
  } finally {
    child.kill();
    if (child.exitCode === null) await once(child, "exit");
  }
});
