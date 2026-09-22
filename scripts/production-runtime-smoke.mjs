import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const image = process.env.BIELOS_RUNTIME_IMAGE?.trim();
if (!image) throw new Error("Runtime smoke requires BIELOS_RUNTIME_IMAGE.");

const suffix = `${process.pid}-${Date.now()}`;
const network = `bielos-runtime-${suffix}`;
const containers = {
  publicSite: `bielos-runtime-public-${suffix}`,
  hub: `bielos-runtime-hub-${suffix}`,
  issuer: `bielos-runtime-issuer-${suffix}`,
};
const publicHost = "portal.runtime.invalid";
const hubHost = "hub.runtime.invalid";
const signingJwks = JSON.stringify({ keys: [createSigningKey()] });
const cookieKey = randomBytes(32).toString("base64url");
const adapterKey = randomBytes(32).toString("hex");

try {
  runDocker(["network", "create", network]);

  runDocker([
    "run", "--detach", "--name", containers.publicSite, "--network", network,
    "--publish", "127.0.0.1::3000", "--env", "NODE_ENV=production",
    "--env", `NEXT_PUBLIC_PORTAL_URL=https://${publicHost}`,
    image, "npm", "run", "start", "--workspace", "@bielos/public-site",
  ]);
  const publicPort = readLoopbackPort(containers.publicSite, "3000/tcp");

  runDocker([
    "run", "--detach", "--name", containers.issuer, "--network", network,
    "--network-alias", "oidc-issuer", "--env", "NODE_ENV=production",
    "--env", "OIDC_ISSUER_PORT=3003", "--env", `BIELOS_OIDC_ISSUER=https://${publicHost}`,
    "--env", `BIELOS_OIDC_SIGNING_JWKS=${signingJwks}`,
    "--env", `BIELOS_OIDC_COOKIE_KEY=${cookieKey}`,
    "--env", `BIELOS_OIDC_ADAPTER_KEY=${adapterKey}`,
    "--env", `BIELOS_TOTP_ENCRYPTION_KEY=${randomBytes(32).toString("hex")}`,
    "--env", "DATABASE_URL=postgresql://bielos_app:local-validation-only@database:5432/bielos",
    image, "npm", "run", "start", "--workspace", "@bielos/issuer",
  ]);

  runDocker([
    "run", "--detach", "--name", containers.hub, "--network", network,
    "--publish", "127.0.0.1::3001", "--env", "NODE_ENV=production",
    "--env", `NEXT_PUBLIC_HUB_URL=https://${hubHost}`,
    "--env", `NEXT_PUBLIC_PORTAL_URL=https://${publicHost}`,
    "--env", `BIELOS_HUB_HOSTNAME=${hubHost}`,
    "--env", `BIELOS_PORTAL_HOSTNAME=${publicHost}`,
    "--env", "BIELOS_OIDC_PROXY_URL=http://oidc-issuer:3003",
    "--env", "DATABASE_URL=postgresql://bielos_app:local-validation-only@database:5432/bielos",
    "--env", `BIELOS_RATE_LIMIT_HASH_SECRET=${randomBytes(32).toString("hex")}`,
    "--env", `BIELOS_TOTP_ENCRYPTION_KEY=${randomBytes(32).toString("hex")}`,
    "--env", `BIELOS_EMAIL_OUTBOX_KEY=${randomBytes(32).toString("hex")}`,
    "--env", `BIELOS_OIDC_ADAPTER_KEY=${adapterKey}`,
    "--env", "CLOUDFLARE_ACCESS_JWT_REQUIRED=true",
    "--env", "CLOUDFLARE_ACCESS_AUDIENCE=runtime-smoke-audience",
    "--env", "CLOUDFLARE_TEAM_DOMAIN=runtime.example.invalid",
    image,
  ]);
  const hubPort = readLoopbackPort(containers.hub, "3001/tcp");

  await assertStatus(`http://127.0.0.1:${publicPort}/`, 200);
  await assertStatus(`http://127.0.0.1:${hubPort}/api/health`, 200);
  await assertStatus(`http://127.0.0.1:${hubPort}/admin/accounts`, 403, { host: hubHost });
  await assertStatus(`http://127.0.0.1:${hubPort}/login`, 403, { host: hubHost, "cf-access-jwt-assertion": "forged" });
  await assertStatus(`http://127.0.0.1:${hubPort}/admin/accounts`, 403, { host: hubHost, "cf-access-jwt-assertion": "forged" });
  const response = await waitForResponse(`http://127.0.0.1:${hubPort}/.well-known/openid-configuration`, { host: publicHost });
  const discovery = await response.json();
  if (
    discovery.issuer !== `https://${publicHost}` ||
    !Array.isArray(discovery.code_challenge_methods_supported) ||
    !discovery.code_challenge_methods_supported.includes("S256") ||
    !Array.isArray(discovery.response_types_supported) ||
    !discovery.response_types_supported.includes("code")
  ) {
    throw new Error("Portal OIDC discovery did not expose the required authorization-code and PKCE profile.");
  }
} finally {
  for (const name of Object.values(containers)) {
    spawnSync("docker", ["rm", "--force", "--volumes", name], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
  }
  spawnSync("docker", ["network", "rm", network], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
}

function createSigningKey() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = privateKey.export({ format: "jwk" });
  return { ...jwk, alg: "ES256", use: "sig", kid: randomUUID() };
}

async function assertStatus(url, expectedStatus, headers = {}) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(5_000) });
      response.body?.cancel();
      if (response.status === expectedStatus) return;
    } catch {
      // The container may still be starting.
    }
    await delay(1_000);
  }
  throw new Error(`Runtime smoke endpoint did not return ${expectedStatus}.`);
}

async function waitForResponse(url, headers = {}) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(5_000) });
      if (response.ok) return response;
      response.body?.cancel();
    } catch {
      // The container may still be starting.
    }
    await delay(1_000);
  }
  throw new Error("Runtime smoke endpoint did not become available.");
}

function readLoopbackPort(container, target) {
  const result = spawnSync("docker", ["port", container, target], { encoding: "utf8", windowsHide: true, timeout: 10_000 });
  if (result.status !== 0) throw new Error("Runtime smoke port could not be read.");
  const match = result.stdout.match(/^127\.0\.0\.1:(\d+)$/mu);
  if (!match) throw new Error("Runtime smoke detected a non-loopback published port.");
  return match[1];
}

function runDocker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error("Production runtime smoke Docker command failed.");
}
