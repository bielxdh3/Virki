import { chmodSync, existsSync, lstatSync, realpathSync, unlinkSync } from "node:fs";
import { createServer } from "node:http";
import { isAbsolute, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { IndependentOfflineWitness } from "./lib/offline-independent-witness-service.mjs";

// Exposes only a disposable, private Linux UNIX socket. It is not a production
// witness authority and never communicates with a Docker daemon or host service.
if (process.platform !== "linux" || process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE !== "1") {
  throw new Error("Independent witness socket is available only for disposable Linux tests");
}

process.umask(0o077);
const root = realpathSync(resolve(fileURLToPath(new URL("..", import.meta.url))));
const config = process.env;
const socket = config.VIRKI_WITNESS_SOCKET;
if (!socket || !isAbsolute(socket) || socket.length > 95) throw new Error("private absolute UNIX socket path required");
const socketFolder = realpathSync(resolve(socket, ".."));
const stats = lstatSync(socketFolder);
if (!stats.isDirectory() || (stats.mode & 0o077) || stats.uid !== process.getuid() ||
  socketFolder === root || socketFolder.startsWith(`${root}${sep}`)) {
  throw new Error("UNIX socket directory must be private and outside the repository");
}
if (existsSync(socket)) throw new Error("existing UNIX socket must be reconciled manually");

const witness = new IndependentOfflineWitness({
  directory: config.VIRKI_WITNESS_DB_DIRECTORY,
  anchorDirectory: config.VIRKI_WITNESS_ANCHOR_DIRECTORY,
  keyFile: config.VIRKI_WITNESS_SIGNER_KEY,
  expectedKeyPinSha256: config.VIRKI_WITNESS_SIGNER_PIN,
  hostIdentitySha256: config.VIRKI_WITNESS_HOST_SHA256,
  ledgerIdSha256: config.VIRKI_WITNESS_LEDGER_SHA256,
  repositoryDirectory: root,
});

const server = createServer(async (request, response) => {
  response.setHeader("Content-Type", "application/json");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Connection", "close");
  if (request.method !== "POST" || !["/v1/cas", "/v1/head"].includes(request.url)) {
    response.writeHead(404).end('{"error":"NOT_FOUND"}');
    return;
  }
  try {
    let bytes = 0;
    const chunks = [];
    for await (const chunk of request) {
      bytes += chunk.length;
      if (bytes > 4096) throw new Error("request exceeds 4096-byte limit");
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString("utf8");
    const payload = JSON.parse(raw);
    if (raw !== JSON.stringify(payload)) throw new Error("noncanonical request JSON");
    const result = request.url === "/v1/cas" ? witness.cas(payload) : witness.read(payload);
    response.writeHead(request.url === "/v1/cas" ? 201 : 200).end(JSON.stringify({
      status: "DISPOSABLE_WITNESS_ONLY", witnessCasAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false, receipt: result,
    }));
  } catch (error) {
    const message = String(error.message);
    const conflict = /stale expected state|replayed transition|UNIQUE constraint/u.test(message);
    const corrupted = /rollback:|durable anchor|invalid signed history|nonmonotonic|forked|stored receipt|SQLite integrity/u.test(message);
    response.writeHead(corrupted ? 503 : conflict ? 409 : 400).end(JSON.stringify({
      error: corrupted ? "WITNESS_INTEGRITY_FAILURE" : conflict ? "CAS_CONFLICT" : "WITNESS_REFUSED",
    }));
  }
});
server.requestTimeout = 10000;
server.headersTimeout = 10000;
server.timeout = 10000;
server.maxRequestsPerSocket = 1;
server.listen(socket, () => {
  chmodSync(socket, 0o600);
  process.stdout.write("WITNESS_DISPOSABLE_READY\n");
});
const close = () => {
  server.close(() => {
    witness.close();
    try { unlinkSync(socket); } catch { /* removed by test fixture */ }
    process.exit(0);
  });
};
process.once("SIGTERM", close);
process.once("SIGINT", close);
