#!/usr/bin/env node
// Disposable Cloudflared verification. Never invokes the repository production Compose files.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { promises as dns } from "node:dns";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createAdmittedOidcDockerClient } from "./lib/disposable-docker-session.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const base = path.join(root, "infra/cloudflare/staging.compose.yml");
const named = path.join(root, "infra/cloudflare/staging.named.compose.yml");
const quick = path.join(root, "infra/cloudflare/staging.quick.compose.yml");
const cloudflaredImage = "cloudflare/cloudflared:2026.9.3@sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c";
const nodeImage = "node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402";
const routes = [
  { service: "public-site", variable: "VIRKI_PR92_PUBLIC_HOST", prefix: "pr92-public" },
  { service: "hub", variable: "VIRKI_PR92_HUB_HOST", prefix: "pr92-hub" },
  { service: "oidc-issuer", variable: "VIRKI_PR92_ISSUER_HOST", prefix: "pr92-issuer" },
];

export function validateHosts(env) {
  const output = routes.map(({ service, variable, prefix }) => {
    const hostname = env[variable];
    const match = typeof hostname === "string" && hostname.match(new RegExp(`^${prefix}\\.([a-z0-9-]{6,40}\\.staging\\.[a-z0-9-]+(?:\\.[a-z0-9-]+)+)$`, "u"));
    if (!match) throw new Error(`Unsafe PR92 staging host for ${service}`);
    return { service, hostname, suffix: match[1], target: `http://${service}:8080` };
  });
  if (new Set(output.map((item) => item.suffix)).size !== 1 || new Set(output.map((item) => item.hostname)).size !== 3) {
    throw new Error("PR92 staging hosts must share a unique disposable staging domain");
  }
  return output;
}

function readTunnelToken(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_+/-]+={0,2}$/u.test(value)) throw new Error("Isolated staging tunnel token required");
  try {
    const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (!/^[0-9a-f-]{36}$/iu.test(decoded.t ?? "") || !/^[a-f0-9]{32}$/iu.test(decoded.a ?? "")) {
      throw new Error("invalid fields");
    }
    return decoded;
  } catch {
    throw new Error("Invalid isolated staging tunnel token");
  }
}

export function validateNamedStaging(env) {
  const token = readTunnelToken(env.VIRKI_PR92_STAGING_TUNNEL_TOKEN);
  if (env.VIRKI_PR92_STAGING_PURPOSE !== "isolated-disposable-issue-92") throw new Error("Explicit isolated disposable PR92 purpose required");
  const tunnelId = String(env.VIRKI_PR92_STAGING_TUNNEL_ID ?? "").toLowerCase();
  const accountId = String(env.VIRKI_PR92_STAGING_ACCOUNT_ID ?? "").toLowerCase();
  const zoneId = String(env.VIRKI_PR92_STAGING_ZONE_ID ?? "").toLowerCase();
  if (tunnelId !== String(token.t).toLowerCase() || accountId !== String(token.a).toLowerCase()) {
    throw new Error("Staging tunnel identity mismatch (decoded token versus operator-provided account/tunnel)");
  }
  if (!/^[0-9a-f]{32}$/u.test(zoneId)) throw new Error("Cloudflare staging zone ID required");
  if (typeof env.VIRKI_PR92_STAGING_READ_TOKEN !== "string" || !env.VIRKI_PR92_STAGING_READ_TOKEN.trim()) {
    throw new Error("Scoped read-only Cloudflare staging API token required");
  }
  return { tunnelId, accountId, zoneId, routes: validateHosts(env) };
}

export async function verifyStagingAccount({ tunnelId, accountId, zoneId, routes: stages }, apiToken, requester = fetch) {
  const call = async (url) => {
    const response = await requester(`https://api.cloudflare.com/client/v4${url}`, {
      headers: { Authorization: `Bearer ${apiToken}` },
      redirect: "error",
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error(`Cloudflare staging read-only API HTTP ${response.status}`);
    const body = await response.json();
    if (!body.success || !body.result) throw new Error("Cloudflare staging read-only API failed");
    return body.result;
  };

  const metadata = await call(`/accounts/${accountId}/cfd_tunnel/${tunnelId}`);
  if (String(metadata.id).toLowerCase() !== tunnelId || String(metadata.account_tag).toLowerCase() !== accountId ||
      !/^virki-pr92-[a-z0-9-]+$/u.test(metadata.name ?? "") || metadata.config_src !== "cloudflare" || metadata.deleted_at) {
    throw new Error("Cloudflare staging tunnel ownership/name/config are not isolated for PR92");
  }
  const config = await call(`/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`);
  const ingress = config.config?.ingress;
  if (!Array.isArray(ingress) || ingress.length !== 4 ||
      ingress[3].service !== "http_status:404" || ingress[3].hostname) {
    throw new Error("Cloudflare staging tunnel ingress must be only 3 mock origins plus final 404");
  }
  for (let i = 0; i < stages.length; i++) {
    if (ingress[i].hostname !== stages[i].hostname || ingress[i].service !== stages[i].target ||
        ingress[i].originRequest?.noTLSVerify === true) {
      throw new Error(`Cloudflare staging ingress does not exactly match ${stages[i].service}`);
    }
  }
  for (const item of stages) {
    const dnsRecords = await call(`/zones/${zoneId}/dns_records?type=CNAME&name=${encodeURIComponent(item.hostname)}&per_page=100`);
    if (!Array.isArray(dnsRecords) || dnsRecords.length !== 1 || dnsRecords[0].name !== item.hostname ||
        dnsRecords[0].type !== "CNAME" || dnsRecords[0].proxied !== true ||
        dnsRecords[0].content?.toLowerCase().replace(/\.$/u, "") !== `${tunnelId}.cfargotunnel.com`) {
      throw new Error(`Cloudflare staging DNS must be a proxied CNAME to the isolated PR92 tunnel: ${item.service}`);
    }
  }
}

function isLocalDockerEndpoint(value) {
  if (typeof value !== "string") return false;
  return /^npipe:\/\/\/\/\.\/pipe\/dockerDesktopLinuxEngine$/iu.test(value) ||
    /^unix:\/\/\/var\/run\/docker\.sock$/u.test(value);
}

export function assertLocalDockerEndpoint(endpoint, env) {
  if (env.DOCKER_HOST && !isLocalDockerEndpoint(env.DOCKER_HOST)) {
    throw new Error("Remote or unknown DOCKER_HOST is forbidden for disposable PR92 Docker experiments");
  }
  if (env.DOCKER_TLS_VERIFY || env.DOCKER_CERT_PATH) {
    throw new Error("Docker TLS/certificate override is forbidden for disposable PR92 experiments");
  }
  if (env.DOCKER_CONTEXT && !["default", "desktop-linux"].includes(env.DOCKER_CONTEXT)) {
    throw new Error("Untrusted DOCKER_CONTEXT override is forbidden for disposable PR92 experiments");
  }
  if (env.DOCKER_CONFIG) {
    throw new Error("DOCKER_CONFIG override is forbidden for disposable PR92 experiments");
  }
  if (!isLocalDockerEndpoint(endpoint)) {
    throw new Error("Remote or unknown Docker context endpoint is forbidden; use a local Unix socket or Docker Desktop named pipe");
  }
}

export function assertTlsVerification(env) {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("TLS certificate validation must remain enabled for Cloudflare staging verification");
  }
}

function pinLocalDockerEngine(env) {
  // This repository's existing Docker admission pins the absolute client and OS-local
  // engine socket, strips DOCKER_* and verifies Linux/arch before any mutation.
  const admittedHost = process.platform === "win32" ? "npipe:////./pipe/dockerDesktopLinuxEngine" : "unix:///var/run/docker.sock";
  assertLocalDockerEndpoint(admittedHost, env);
  const client = createAdmittedOidcDockerClient({ env });
  for (const key of Object.keys(env)) if (/^DOCKER_/iu.test(key)) delete env[key];
  env.DOCKER_HOST = client.subprocessEnv.DOCKER_HOST;
  env.VIRKI_PR92_PINNED_DOCKER_CLI = client.subprocessEnv.VIRKI_OIDC_DOCKER_BINARY;
  env.VIRKI_PR92_PINNED_DOCKER_HOST = client.subprocessEnv.DOCKER_HOST;
  console.log("PASS pinned local Docker Desktop Linux endpoint and architecture admission");
}

function mask(output, env) {
  let text = String(output ?? "");
  for (const secret of [env.VIRKI_PR92_STAGING_TUNNEL_TOKEN, env.VIRKI_PR92_STAGING_READ_TOKEN]) {
    if (typeof secret === "string" && secret.length > 5) text = text.replaceAll(secret, "[REDACTED]");
  }
  return text.slice(-40000);
}

async function docker(args, env, { timeout = 90000, allowFailure = false } = {}) {
  if (!env.VIRKI_PR92_PINNED_DOCKER_CLI || !env.VIRKI_PR92_PINNED_DOCKER_HOST) {
    throw new Error("Pinned local Docker engine must be admitted before any daemon operation");
  }
  return new Promise((resolve, reject) => {
    const child = spawn(env.VIRKI_PR92_PINNED_DOCKER_CLI, ["--host", env.VIRKI_PR92_PINNED_DOCKER_HOST, ...args],
      { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const append = (chunk, current) => (current + chunk.toString("utf8")).slice(-40000);
    child.stdout.on("data", (chunk) => { stdout = append(chunk, stdout); });
    child.stderr.on("data", (chunk) => { stderr = append(chunk, stderr); });
    const timer = setTimeout(() => child.kill(), timeout);
    child.once("error", (error) => { clearTimeout(timer); reject(new Error(`Docker executable unavailable: ${error.code}`)); });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code !== 0 && !allowFailure) reject(new Error(`Docker command exited ${code}: ${mask(stderr || stdout, env).slice(-2200)}`));
      else resolve({ code, stdout: mask(stdout, env), stderr: mask(stderr, env) });
    });
  });
}

const pr92HelperLabel = "org.virki.pr92.project";

export function helperDockerRunArgs(project) {
  if (!/^vrkpr92[a-f0-9]{14}$/u.test(project)) throw new Error("Invalid isolated PR92 project for helper ownership");
  return ["--label", `${pr92HelperLabel}=${project}`];
}

export async function cleanupDisposableHelpers(project, env, runner = docker) {
  helperDockerRunArgs(project);
  const filter = `label=${pr92HelperLabel}=${project}`;
  const list = () => runner(["ps", "-a", "--filter", filter, "--format", "{{.ID}}"], env);
  const initial = (await list()).stdout.trim().split(/\s+/u).filter(Boolean);
  for (const id of initial) {
    if (!/^[a-f0-9]{12,64}$/iu.test(id)) throw new Error("Invalid Docker helper ID in scoped cleanup response");
    await runner(["rm", "-f", id], env, { timeout: 15000 });
  }
  if ((await list()).stdout.trim()) throw new Error(`Disposable PR92 helper cleanup left containers in project ${project}`);
}

export async function cleanupDisposableProject(compose, project, env, runner = docker) {
  let helperError;
  try { await cleanupDisposableHelpers(project, env, runner); }
  catch (error) { helperError = error; }
  let composeError;
  try { await runner([...compose, "down", "--remove-orphans", "--timeout", "10"], env, { timeout: 90000 }); }
  catch (error) { composeError = error; }
  const [containers, networks, helpers] = await Promise.all([
    runner(["ps", "-a", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.ID}}"], env),
    runner(["network", "ls", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.ID}}"], env),
    runner(["ps", "-a", "--filter", `label=${pr92HelperLabel}=${project}`, "--format", "{{.ID}}"], env),
  ]);
  if (containers.stdout.trim() || networks.stdout.trim() || helpers.stdout.trim()) {
    throw new Error(`Disposable Compose cleanup left labeled resources in project ${project}`);
  }
  if (helperError || composeError) throw new AggregateError([helperError, composeError].filter(Boolean),
    `Disposable project ${project} cleanup could not be verified after a Docker failure`);
}

async function waitFor(check, title, timeout = 60000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await check();
      if (result) return result;
    } catch (error) { lastError = error; }
    await delay(2500);
  }
  throw new Error(`${title} failed after ${Math.round(timeout / 1000)}s: ${lastError?.message ?? "not ready"}`);
}

async function assertContainerHardening(containerId, env) {
  const result = await docker(["inspect", "--format", "{{json .HostConfig}}", containerId], env);
  const hostConfig = JSON.parse(result.stdout);
  const user = JSON.parse((await docker(["inspect", "--format", "{{json .Config.User}}", containerId], env)).stdout);
  assert.equal(user, "65532:65532", "cloudflared UID/GID must remain non-root");
  assert.equal(hostConfig.ReadonlyRootfs, true);
  assert.ok(hostConfig.CapDrop?.some((item) => item.toUpperCase() === "ALL"));
  assert.ok(hostConfig.SecurityOpt?.includes("no-new-privileges:true"));
  assert.equal(Object.keys(hostConfig.PortBindings ?? {}).length, 0, "No host ports may be published");
  assert.equal((hostConfig.Binds ?? []).length, 0, "No host binds allowed for Cloudflared");
}

async function probeInternal(project, stages, nonce, env) {
  const js = `const http=await import('node:http');const routes=JSON.parse(process.argv[1]);const nonce=process.argv[2];
    const send=(service,host,route)=>new Promise((resolve,reject)=>{
      const request=http.request({hostname:service,port:8080,path:route,headers:{Host:host},signal:AbortSignal.timeout(5000)},response=>{
        const chunks=[];response.on('data',chunk=>chunks.push(chunk));
        response.on('end',()=>resolve({status:response.statusCode,headers:response.headers,body:Buffer.concat(chunks).toString('utf8')}));
      });request.on('error',reject);request.end();
    });
    for(const route of routes){
      const routePath='/__virki_pr92_probe/'+nonce;
      const response=await send(route.service,route.hostname,routePath);
      if(response.status!==200||response.headers['x-virki-pr92-origin']!==route.service)process.exit(41);
      const data=JSON.parse(response.body);if(data.nonce!==nonce||data.service!==route.service)process.exit(42);
      const wrong=await send(route.service,'wrong.invalid',routePath);if(wrong.status!==421)process.exit(43);
      const stale=await send(route.service,route.hostname,'/__virki_pr92_probe/stale');
      if(stale.status!==404)process.exit(44);
    }`;
  await docker(["run", "--rm", ...helperDockerRunArgs(project), "--pull", "never", "--network", `${project}_staging`, "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true", nodeImage, "node", "--input-type=module", "-e", js, JSON.stringify(stages), nonce], env);
}

async function proveFilesystemDenied(project, env) {
  const code = `const fs=require('node:fs');try{fs.writeFileSync('/pr92-should-be-readonly','no');process.exit(19)}catch(error){if(!['EROFS','EACCES','EPERM'].includes(error.code))process.exit(20)}`;
  await docker(["run", "--rm", ...helperDockerRunArgs(project), "--pull", "never", "--network", "none", "--user", "65532:65532", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", nodeImage, "node", "-e", code], env);
  const version = await docker(["run", "--rm", ...helperDockerRunArgs(project), "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true", cloudflaredImage, "--version"], env);
  assert.match(version.stdout, /2026\.9\.3/u);
}

async function assertPublicDNS(hostname) {
  const resolved = await dns.lookup(hostname, { all: true });
  if (!resolved.length || resolved.some(({ address }) => /^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fc|fd)/iu.test(address))) {
    throw new Error(`Staging DNS is missing or points to private/loopback addresses: ${hostname}`);
  }
}

async function probeEdge(hostname, service, nonce) {
  const url = `https://${hostname}/__virki_pr92_probe/${nonce}`;
  const response = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(7000), headers: { "Cache-Control": "no-store" } });
  if (response.status !== 200 || response.headers.get("x-virki-pr92-origin") !== service) return false;
  const data = await response.json();
  return data.service === service && data.nonce === nonce;
}

async function containerId(compose, service, env) {
  const id = (await docker([...compose, "ps", "-q", service], env)).stdout.trim();
  if (!/^[a-f0-9]{12,64}$/iu.test(id)) throw new Error(`Could not identify disposable ${service} container`);
  return id;
}

export function latestQuickHostname(logs, previous = null) {
  // Parse the complete HTTPS token and hostname. A partial regex match would
  // accept an attacker-controlled suffix such as trycloudflare.com.evil.test.
  const tokens = logs.split(/\s+/u);
  for (let index = tokens.length - 1; index >= 0; index--) {
    const raw = tokens[index].replaceAll("|", "");
    if (!raw.startsWith("https://")) continue;
    let url;
    try { url = new URL(raw); }
    catch { continue; }
    const parts = url.hostname.split(".");
    if (url.protocol !== "https:" || url.username || url.password || url.port ||
        url.pathname !== "/" || url.search || url.hash || parts.length !== 3 ||
        parts[1] !== "trycloudflare" || parts[2] !== "com" ||
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(parts[0])) continue;
    return url.hostname === previous ? null : url.hostname;
  }
  return null;
}

async function quickHostname(id, env, previous = null) {
  return waitFor(async () => {
    const result = await docker(["logs", "--tail", "120", id], env, { allowFailure: true });
    return latestQuickHostname(`${result.stdout}\n${result.stderr}`, previous);
  }, "Cloudflare temporary Quick Tunnel URL", 60000);
}

async function run(mode) {
  assertTlsVerification(process.env);
  const nonce = randomBytes(18).toString("hex");
  const project = `vrkpr92${randomBytes(7).toString("hex")}`;
  const env = { ...process.env, VIRKI_PR92_MOCK_NONCE: nonce, VIRKI_PR92_MOCK_ALLOW_QUICK: mode === "quick" ? "true" : "false",
    VIRKI_PR92_QUICK_TARGET: "public-site" };
  const stages = mode === "named" ? validateNamedStaging(env).routes : validateHosts({
    VIRKI_PR92_PUBLIC_HOST: "pr92-public.local123.staging.invalid.net",
    VIRKI_PR92_HUB_HOST: "pr92-hub.local123.staging.invalid.net",
    VIRKI_PR92_ISSUER_HOST: "pr92-issuer.local123.staging.invalid.net",
  });
  if (mode === "named") {
    const validated = validateNamedStaging(env);
    await verifyStagingAccount(validated, env.VIRKI_PR92_STAGING_READ_TOKEN);
    console.log("PASS read-only Cloudflare ownership, ingress and DNS record attestation");
  }
  pinLocalDockerEngine(env);
  for (const route of routes) env[route.variable] = stages.find((item) => item.service === route.service).hostname;
  const compose = ["compose", "--project-name", project, "-f", base];
  if (mode === "named") compose.push("-f", named);
  if (mode === "quick") compose.push("-f", quick);
  const owned = await docker(["ps", "-a", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.ID}}"], env);
  if (owned.stdout.trim()) throw new Error("Disposable Compose project collision: refusing to touch pre-existing containers");
  let started = false;
  try {
    started = true;
    await docker([...compose, "up", "-d", "--no-build", "public-site", "hub", "oidc-issuer"], env);
    await waitFor(async () => { await probeInternal(project, stages, nonce, env); return true; }, "3 isolated mock origins", 45000);
    console.log("PASS isolated Docker network, 3 mock origins, Host separation, nonce and deny-by-default routes");
    await proveFilesystemDenied(project, env);
    console.log("PASS Cloudflared pinned image under hardening and kernel-enforced read-only write denial");
    if (mode === "local") return;

    if (mode === "named") {
      for (const item of stages) await assertPublicDNS(item.hostname);
      await docker([...compose, "up", "-d", "--no-build", "cloudflared"], env);
      const id = await containerId(compose, "cloudflared", env);
      await assertContainerHardening(id, env);
      await waitFor(async () => (await Promise.all(stages.map((item) => probeEdge(item.hostname, item.service, nonce)))).every(Boolean),
        "3 named tunnel hosts through Cloudflare edge", 120000);
      console.log("PASS 3 real HTTPS named-tunnel routes, TLS, DNS and Cloudflared container security");
      await docker(["stop", id], env);
      await waitFor(async () => !(await probeEdge(stages[0].hostname, stages[0].service, nonce)), "isolated tunnel stop", 40000);
      await docker(["start", id], env);
      await waitFor(async () => (await Promise.all(stages.map((item) => probeEdge(item.hostname, item.service, nonce)))).every(Boolean),
        "named tunnel reconnection", 120000);
      console.log("PASS named tunnel stop, loss of route and reconnection with all 3 hosts");
    }

    if (mode === "quick") {
      for (const item of stages) {
        env.VIRKI_PR92_QUICK_TARGET = item.service;
        await docker([...compose, "up", "-d", "--no-build", "--force-recreate", "--no-deps", "cloudflared"], env);
        const id = await containerId(compose, "cloudflared", env);
        await assertContainerHardening(id, env);
        const hostname = await quickHostname(id, env);
        await waitFor(async () => { await assertPublicDNS(hostname); return true; },
          `${item.service} Quick Tunnel public DNS propagation`, 90000);
        await waitFor(async () => probeEdge(hostname, item.service, nonce), `${item.service} Quick Tunnel through Cloudflare edge`, 90000);
        await docker(["stop", id], env);
        await waitFor(async () => !(await probeEdge(hostname, item.service, nonce)), `${item.service} Quick Tunnel stop`, 40000);
        await docker(["start", id], env);
        const reconnected = await quickHostname(id, env, hostname);
        await waitFor(async () => { await assertPublicDNS(reconnected); return true; },
          `${item.service} restarted Quick Tunnel public DNS propagation`, 90000);
        await waitFor(async () => probeEdge(reconnected, item.service, nonce), `${item.service} Quick Tunnel restart`, 90000);
        console.log(`PASS ${item.service} anonymous Quick Tunnel hardened start, stop and reconnect (temporary URL)`);
      }
      console.log("LIMIT: Quick Tunnel does not establish named-tunnel ingress or production Compose compatibility");
    }
  } finally {
    if (started) {
      await cleanupDisposableProject(compose, project, env);
    }
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const mode = args.length === 0 || args[0] === "--named-edge" ? "named" :
    args[0] === "--quick-edge" ? "quick" : args[0] === "--local-only" ? "local" : null;
  if (!mode || args.length > 1) {
    console.error("Usage: node scripts/cloudflared-staging.mjs [--named-edge | --quick-edge | --local-only]");
    process.exitCode = 2;
  } else {
    run(mode).catch((error) => { console.error(`FAIL PR92 disposable Cloudflared test: ${error.message}`); process.exitCode = 1; });
  }
}
