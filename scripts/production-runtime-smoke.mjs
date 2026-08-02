import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const image = process.env.BIELOS_RUNTIME_IMAGE?.trim();
if (!image) {
  throw new Error("Runtime smoke requires BIELOS_RUNTIME_IMAGE.");
}

const suffix = `${process.pid}-${Date.now()}`;
const containers = {
  publicSite: `bielos-runtime-public-${suffix}`,
  hub: `bielos-runtime-hub-${suffix}`,
  intake: `bielos-runtime-intake-${suffix}`
};

try {
  runDocker([
    "run",
    "--detach",
    "--name",
    containers.publicSite,
    "--publish",
    "127.0.0.1::3000",
    "--env",
    "NODE_ENV=production",
    "--env",
    "NEXT_PUBLIC_HUB_URL=https://hub.example.invalid",
    image,
    "npm",
    "run",
    "start",
    "--workspace",
    "@bielos/public-site"
  ]);
  const publicPort = readLoopbackPort(containers.publicSite, "3000/tcp");

  runDocker([
    "run",
    "--detach",
    "--name",
    containers.hub,
    "--publish",
    "127.0.0.1::3001",
    "--env",
    "NODE_ENV=production",
    "--env",
    "NEXT_PUBLIC_HUB_URL=https://hub.example.invalid",
    "--env",
    "DATABASE_URL=postgresql://127.0.0.1/bielos",
    "--env",
    "BIELOS_RATE_LIMIT_HASH_SECRET=replace-with-test-secret",
    "--env",
    "CLOUDFLARE_ACCESS_JWT_REQUIRED=true",
    "--env",
    "CLOUDFLARE_ACCESS_AUDIENCE=runtime-smoke-audience",
    "--env",
    "CLOUDFLARE_TEAM_DOMAIN=team.example.invalid",
    image
  ]);
  const hubPort = readLoopbackPort(containers.hub, "3001/tcp");

  runDocker([
    "run",
    "--detach",
    "--name",
    containers.intake,
    "--publish",
    "127.0.0.1::3002",
    "--env",
    "NODE_ENV=production",
    "--env",
    "INTAKE_PORT=3002",
    "--env",
    "PUBLIC_SITE_ORIGIN=https://www.example.invalid",
    "--env",
    "BIELOS_INTAKE_ENABLED=false",
    image,
    "npm",
    "run",
    "start",
    "--workspace",
    "@bielos/intake"
  ]);
  const intakePort = readLoopbackPort(containers.intake, "3002/tcp");

  await assertStatus(`http://127.0.0.1:${publicPort}/`, 200);
  await assertStatus(`http://127.0.0.1:${publicPort}/apply`, 200);
  await assertStatus(`http://127.0.0.1:${hubPort}/api/health`, 200);
  await assertStatus(`http://127.0.0.1:${hubPort}/`, 403);
  await assertStatus(`http://127.0.0.1:${intakePort}/api/catalog`, 503);
} finally {
  for (const name of Object.values(containers)) {
    spawnSync("docker", ["rm", "--force", name], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 60_000
    });
  }
}

async function assertStatus(url, expectedStatus) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(url, { redirect: "manual" });
      if (response.status === expectedStatus) {
        response.body?.cancel();
        return;
      }
    } catch {
      // The container may still be starting.
    }
    await delay(1_000);
  }
  throw new Error(`Runtime smoke endpoint did not return ${expectedStatus}.`);
}

function readLoopbackPort(container, target) {
  const result = spawnSync("docker", ["port", container, target], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 10_000
  });
  if (result.status !== 0) {
    throw new Error("Runtime smoke port could not be read.");
  }
  const match = result.stdout.match(/^127\.0\.0\.1:(\d+)$/mu);
  if (!match) {
    throw new Error("Runtime smoke detected a non-loopback published port.");
  }
  return match[1];
}

function runDocker(args) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error("Production runtime smoke Docker command failed.");
  }
}
