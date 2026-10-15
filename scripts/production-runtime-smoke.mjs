import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { setTimeout as delay } from "node:timers/promises";

const image = process.env.VIRKI_RUNTIME_IMAGE?.trim();
if (!image) throw new Error("Runtime smoke requires VIRKI_RUNTIME_IMAGE.");

const suffix = `${process.pid}-${Date.now()}`;
const network = `virki-runtime-${suffix}`;
const containers = {
  publicSite: `virki-runtime-public-${suffix}`,
  hub: `virki-runtime-hub-${suffix}`,
  issuer: `virki-runtime-issuer-${suffix}`,
};
const publicHost = "portal.biel.dev.br";
const hubHost = "hub.biel.dev.br";
const signingJwks = JSON.stringify({ keys: [createSigningKey()] });
const cookieKey = randomBytes(32).toString("base64url");
const adapterKey = randomBytes(32).toString("hex");
const runtimeSafetyArgs = [
  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
  "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
];

try {
  runDocker(["network", "create", network]);

  runDocker([
    "run", ...runtimeSafetyArgs, "--tmpfs", "/app/apps/public-site/.next/cache:rw,noexec,nosuid,nodev,size=128m", "--detach", "--name", containers.publicSite, "--network", network,
    "--publish", "127.0.0.1::3000", "--env", "NODE_ENV=production",
    "--env", `VIRKI_PORTAL_URL=https://${publicHost}`,
    image, "npm", "run", "start", "--workspace", "@virki/public-site",
  ]);
  const publicPort = readLoopbackPort(containers.publicSite, "3000/tcp");

  runDocker([
    "run", ...runtimeSafetyArgs, "--detach", "--name", containers.issuer, "--network", network,
    "--network-alias", "oidc-issuer", "--env", "NODE_ENV=production",
    "--env", "OIDC_ISSUER_PORT=3003", "--env", `VIRKI_OIDC_ISSUER=https://${publicHost}`,
    "--env", `VIRKI_OIDC_SIGNING_JWKS=${signingJwks}`,
    "--env", `VIRKI_OIDC_COOKIE_KEY=${cookieKey}`,
    "--env", `VIRKI_OIDC_ADAPTER_KEY=${adapterKey}`,
    "--env", `VIRKI_TOTP_ENCRYPTION_KEY=${randomBytes(32).toString("hex")}`,
    "--env", "DATABASE_URL=postgresql://virki_app:local-validation-only@database:5432/virki",
    image, "npm", "run", "start", "--workspace", "@virki/issuer",
  ]);

  runDocker([
    "run", ...runtimeSafetyArgs, "--tmpfs", "/app/apps/hub/.next/cache:rw,noexec,nosuid,nodev,size=128m", "--detach", "--name", containers.hub, "--network", network,
    "--publish", "127.0.0.1::3001", "--env", "NODE_ENV=production",
    "--env", `VIRKI_HUB_URL=https://${hubHost}`,
    "--env", `VIRKI_PORTAL_URL=https://${publicHost}`,
    "--env", `VIRKI_HUB_HOSTNAME=${hubHost}`,
    "--env", `VIRKI_PORTAL_HOSTNAME=${publicHost}`,
    "--env", "VIRKI_OIDC_PROXY_URL=http://oidc-issuer:3003",
    "--env", "DATABASE_URL=postgresql://virki_app:local-validation-only@database:5432/virki",
    "--env", `VIRKI_RATE_LIMIT_HASH_SECRET=${randomBytes(32).toString("hex")}`,
    "--env", `VIRKI_AUDIT_HASH_SECRET=${randomBytes(32).toString("hex")}`,
    "--env", `VIRKI_CSRF_SIGNING_KEY=${randomBytes(32).toString("hex")}`,
    "--env", `VIRKI_TOTP_ENCRYPTION_KEY=${randomBytes(32).toString("hex")}`,
    "--env", `VIRKI_EMAIL_OUTBOX_KEY=${randomBytes(32).toString("hex")}`,
    "--env", `VIRKI_OIDC_ADAPTER_KEY=${adapterKey}`,
    "--env", "CLOUDFLARE_ACCESS_JWT_REQUIRED=true",
    "--env", "CLOUDFLARE_ACCESS_AUDIENCE=runtime-smoke-audience",
    "--env", "CLOUDFLARE_TEAM_DOMAIN=runtime.example.invalid",
    image,
  ]);
  const hubPort = readLoopbackPort(containers.hub, "3001/tcp");

  const publicResponse = await assertStatus(`http://127.0.0.1:${publicPort}/`, 200);
  assertSecurityHeaders(publicResponse.headers);
  const hubHealth = await assertStatus(`http://127.0.0.1:${hubPort}/api/health`, 200);
  assertSecurityHeaders(hubHealth.headers, "strict-origin");
  await assertStatus(`http://127.0.0.1:${hubPort}/admin/accounts`, 403, { host: hubHost });
  await assertStatus(`http://127.0.0.1:${hubPort}/login`, 403, { host: hubHost, "cf-access-jwt-assertion": "forged" });
  await assertStatus(`http://127.0.0.1:${hubPort}/admin/accounts`, 403, { host: hubHost, "cf-access-jwt-assertion": "forged" });
  const response = await waitForResponse(`http://127.0.0.1:${hubPort}/.well-known/openid-configuration`, { host: publicHost });
  assertSecurityHeaders(response.headers);
  const discovery = JSON.parse(response.body);
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
  let observedStatus = "unreachable";
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await requestOnce(url, headers);
      observedStatus = String(response.statusCode);
      if (response.statusCode === expectedStatus) return response;
    } catch {
      // The container may still be starting.
    }
    await delay(1_000);
  }
  throw new Error(`Runtime smoke endpoint ${new URL(url).pathname} returned ${observedStatus}; expected ${expectedStatus}.`);
}

function assertSecurityHeaders(headers, referrerPolicy = "no-referrer") {
  const csp = (headers["content-security-policy"] ?? "").split(";").map((directive) => directive.trim());
  for (const directive of ["frame-ancestors 'none'", "base-uri 'none'"]) {
    if (!csp.includes(directive)) throw new Error(`Runtime smoke is missing CSP directive ${directive}.`);
  }
  if (!csp.includes("object-src 'none'") && !csp.includes("default-src 'none'")) throw new Error("Runtime smoke CSP does not block plugin content.");
  const expected = {
    "permissions-policy": "camera=(), geolocation=(), microphone=()",
    "referrer-policy": referrerPolicy,
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  };
  for (const [name, value] of Object.entries(expected)) {
    if (headers[name] !== value) throw new Error(`Runtime smoke is missing security header ${name}.`);
  }
}

async function waitForResponse(url, headers = {}) {
  let observedStatus = "unreachable";
  let redirectPath = "";
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await requestOnce(url, headers);
      observedStatus = String(response.statusCode);
      const location = response.headers.location;
      if (location) {
        try {
          redirectPath = new URL(location, url).pathname;
        } catch {
          redirectPath = "invalid-location";
        }
      }
      if (response.statusCode >= 200 && response.statusCode < 300) return response;
    } catch {
      // The container may still be starting.
    }
    await delay(1_000);
  }
  throw new Error(`Runtime smoke endpoint ${new URL(url).pathname} returned ${observedStatus}; expected a successful response${redirectPath ? ` (redirect ${redirectPath})` : ""}.`);
}

function requestOnce(url, headers) {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const request = httpRequest(target, { headers }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => resolve({
        statusCode: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.setTimeout(5_000, () => request.destroy(new Error("Runtime smoke request timed out.")));
    request.on("error", reject);
    request.end();
  });
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
