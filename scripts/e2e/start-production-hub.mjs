import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createServer as createHttpsServer } from "node:https";
import { request as httpRequest } from "node:http";
import { fileURLToPath } from "node:url";
import { classifyLow05Url, summarizeLow05ProxyBoundary } from "./low05-diagnostics.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../..");
const hubDirectory = join(repositoryRoot, "apps", "hub");
const requireFromRepository = createRequire(join(repositoryRoot, "package.json"));
const hubHost = "127.0.0.1";
const hubPort = 443;
const nextPort = 3002;
const startTimeoutMs = 120_000;

export function createProductionHubProxyRequestHandler(targetPort = nextPort) {
  return (incomingRequest, outgoingResponse) => {
    const requestHost = incomingRequest.headers.host;
    if (!requestHost) {
      outgoingResponse.writeHead(400, { "cache-control": "no-store" });
      outgoingResponse.end();
      return;
    }

    const forwardedHeaders = { ...incomingRequest.headers };
    forwardedHeaders.host = requestHost;
    forwardedHeaders["x-forwarded-host"] = requestHost;
    forwardedHeaders["x-forwarded-proto"] = "https";
    forwardedHeaders["x-forwarded-for"] = incomingRequest.socket.remoteAddress ?? "127.0.0.1";
    forwardedHeaders["cf-connecting-ip"] = incomingRequest.socket.remoteAddress ?? "127.0.0.1";

    const upstreamRequest = httpRequest({
      hostname: hubHost,
      port: targetPort,
      method: incomingRequest.method,
      path: incomingRequest.url,
      headers: forwardedHeaders
    }, (upstreamResponse) => {
      const low05Route = classifyLow05Url(incomingRequest.url ?? "/", process.env.VIRKI_PORTAL_URL ?? "https://portal.localhost").route;
      if (process.env.VIRKI_E2E_LOW05_DIAGNOSTICS === "true" && ["account-security", "login"].includes(low05Route)) {
        process.stdout.write(`LOW05_PROXY_BOUNDARY ${JSON.stringify(summarizeLow05ProxyBoundary({
          request: incomingRequest,
          response: upstreamResponse,
          forwardedHeaders,
          environment: process.env,
          portalUrl: process.env.VIRKI_PORTAL_URL ?? "https://portal.localhost"
        }))}\n`);
      }
      outgoingResponse.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(outgoingResponse);
    });

    upstreamRequest.on("error", () => {
      if (!outgoingResponse.headersSent) outgoingResponse.writeHead(502, { "cache-control": "no-store" });
      outgoingResponse.end("Hub unavailable");
    });
    incomingRequest.on("aborted", () => upstreamRequest.destroy());
    incomingRequest.pipe(upstreamRequest);
  };
}

async function startProductionHub() {
  if (process.env.NODE_ENV !== "production" || process.env.VIRKI_E2E_HUB_MODE !== "production") {
    throw new Error("Production Hub E2E mode is required.");
  }

  const keyPath = process.env.VIRKI_E2E_TLS_KEY_PATH;
  const certificatePath = process.env.VIRKI_E2E_TLS_CERTIFICATE_PATH;
  const caCertificatePath = process.env.NODE_EXTRA_CA_CERTS;
  const expectedCaCertificatePath = certificatePath ? join(dirname(certificatePath), "test-ca-cert.pem") : undefined;
  if (!keyPath || !certificatePath || !caCertificatePath || !isAbsolute(keyPath) || !isAbsolute(certificatePath) || !isAbsolute(caCertificatePath) ||
    !existsSync(keyPath) || !existsSync(certificatePath) || !existsSync(caCertificatePath) || !expectedCaCertificatePath || resolve(caCertificatePath) !== resolve(expectedCaCertificatePath)) {
    throw new Error("Production Hub E2E TLS files are unavailable.");
  }

  const nextCliPath = requireFromRepository.resolve("next/dist/bin/next", { paths: [hubDirectory] });
  const nextProcess = spawn(process.execPath, [nextCliPath, "start", "--hostname", hubHost, "--port", String(nextPort)], {
    cwd: hubDirectory,
    env: process.env,
    stdio: "inherit",
    windowsHide: true
  });
  let proxyServer;
  let stopped = false;

  const stop = () => {
    if (stopped) return;
    stopped = true;
    proxyServer?.close();
    nextProcess.kill("SIGTERM");
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  nextProcess.once("error", () => {
    process.stderr.write("Production Hub E2E server could not start.\n");
    stop();
    process.exitCode = 1;
  });
  nextProcess.once("exit", (code) => {
    if (!stopped) {
      process.exitCode = code ?? 1;
      proxyServer?.close();
    }
  });

  try {
    await waitForNextServer(nextProcess, () => stopped);
    proxyServer = createHttpsServer({
      key: readFileSync(keyPath),
      cert: readFileSync(certificatePath)
    }, createProductionHubProxyRequestHandler());
    await new Promise((resolveListen, rejectListen) => {
      proxyServer.once("error", rejectListen);
      proxyServer.listen(hubPort, hubHost, resolveListen);
    });
  } catch (error) {
    stop();
    throw error;
  }
}

async function waitForNextServer(nextProcess, isStopped) {
  const deadline = Date.now() + startTimeoutMs;
  while (Date.now() < deadline) {
    if (isStopped() || nextProcess.exitCode !== null || nextProcess.signalCode !== null) {
      throw new Error("Production Hub E2E server stopped before it was ready.");
    }
    if (await isNextServerReady()) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error("Production Hub E2E server did not become ready.");
}

function isNextServerReady() {
  return new Promise((resolveReady) => {
    const request = httpRequest({
      hostname: hubHost,
      port: nextPort,
      path: "/api/health",
      headers: { host: "portal.localhost", "x-forwarded-proto": "https" },
      timeout: 1_000
    }, (response) => {
      response.resume();
      resolveReady((response.statusCode ?? 500) < 500);
    });
    request.on("error", () => resolveReady(false));
    request.on("timeout", () => {
      request.destroy();
      resolveReady(false);
    });
    request.end();
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startProductionHub().catch(() => {
    process.stderr.write("Production Hub E2E service could not start.\n");
    process.exitCode = 1;
  });
}
