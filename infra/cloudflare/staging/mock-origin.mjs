import { createServer } from "node:http";

const service = process.env.VIRKI_PR92_MOCK_SERVICE;
const hostname = process.env.VIRKI_PR92_MOCK_HOST;
const nonce = process.env.VIRKI_PR92_MOCK_NONCE;
const port = Number(process.env.VIRKI_PR92_MOCK_PORT ?? 8080);
const allowQuick = process.env.VIRKI_PR92_MOCK_ALLOW_QUICK === "true";

if (!["public-site", "hub", "oidc-issuer"].includes(service) ||
    !hostname || !nonce || !Number.isInteger(port) || port < 0 || port > 65535) {
  throw new Error("Invalid disposable PR92 mock configuration");
}

const server = createServer((request, response) => {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  const host = request.headers.host?.toLowerCase();
  if (host !== hostname && !(allowQuick && /^[a-z0-9-]+\.trycloudflare\.com$/u.test(host ?? ""))) {
    response.writeHead(421).end();
    return;
  }
  if (request.method !== "GET" || request.url !== `/__virki_pr92_probe/${nonce}`) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "Content-Type": "application/json", "X-Virki-Pr92-Origin": service });
  response.end(JSON.stringify({ service, nonce }));
});

server.listen(port, "0.0.0.0", () => {
  process.stdout.write(`READY ${server.address().port}\n`);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => server.close());
}
