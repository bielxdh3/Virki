import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, realpathSync, unlinkSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { isIP } from "node:net";
import { isAbsolute, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { IndependentOfflineWitness, readIndependentWitnessCredential } from "./lib/offline-independent-witness-service.mjs";

// Transport modes share the same signed CAS ledger; only the remote service
// can be deployed on a separately administered, native Linux witness machine.
const remote = process.env.VIRKI_WITNESS_MODE === "remote";
if (process.platform !== "linux" || (!remote && process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE !== "1")) {
  throw new Error("Linux witness requires explicit remote mode or disposable fixture");
}

process.umask(0o077);
const root = realpathSync(resolve(fileURLToPath(new URL("..", import.meta.url))));
const config = process.env;
let socket;
if (!remote) {
  socket = config.VIRKI_WITNESS_SOCKET;
  if (!socket || !isAbsolute(socket) || socket.length > 95) throw new Error("private absolute UNIX socket path required");
  const socketFolder = realpathSync(resolve(socket, ".."));
  const stats = lstatSync(socketFolder);
  if (!stats.isDirectory() || (stats.mode & 0o077) || stats.uid !== process.getuid() ||
    socketFolder === root || socketFolder.startsWith(`${root}${sep}`)) {
    throw new Error("UNIX socket directory must be private and outside the repository");
  }
  if (existsSync(socket)) throw new Error("existing UNIX socket must be reconciled manually");
}

const witness = new IndependentOfflineWitness({
  directory: config.VIRKI_WITNESS_DB_DIRECTORY,
  anchorDirectory: config.VIRKI_WITNESS_ANCHOR_DIRECTORY,
  keyFile: config.VIRKI_WITNESS_SIGNER_KEY,
  expectedKeyPinSha256: config.VIRKI_WITNESS_SIGNER_PIN,
  ownerPublicKeyFile: config.VIRKI_WITNESS_OWNER_PUBLIC_KEY,
  expectedOwnerPinSha256: config.VIRKI_WITNESS_OWNER_PIN,
  hostIdentitySha256: config.VIRKI_WITNESS_HOST_SHA256,
  ledgerIdSha256: config.VIRKI_WITNESS_LEDGER_SHA256,
  repositoryDirectory: root,
});

let pinnedClient;
let listener;
if (remote) {
  if (!isIP(config.VIRKI_WITNESS_BIND_HOST) ||
      !/^\d{1,5}$/u.test(config.VIRKI_WITNESS_BIND_PORT ?? "")) {
    throw new Error("remote TLS witness requires explicit IP and TCP port");
  }
  const port = Number(config.VIRKI_WITNESS_BIND_PORT);
  if (port > 65535 || (!port && config.VIRKI_DISPOSABLE_WITNESS_SERVICE !== "1")) {
    throw new Error("invalid remote TLS port");
  }
  pinnedClient = config.VIRKI_WITNESS_TLS_CLIENT_CERT_SHA256;
  if (!/^[0-9a-f]{64}$/u.test(pinnedClient ?? "")) {
    throw new Error("remote TLS witness requires exact client certificate pin");
  }
  const tlsFile = (name) => {
    const path = config[name];
    if (!path || !isAbsolute(path)) throw new Error(`absolute TLS credential ${name} required`);
    const actual = realpathSync(path);
    if (actual === root || actual.startsWith(`${root}${sep}`)) {
      throw new Error("TLS credentials must remain outside repository");
    }
    return readIndependentWitnessCredential(path);
  };
  listener = { port, hostname: config.VIRKI_WITNESS_BIND_HOST,
    tls: { key: tlsFile("VIRKI_WITNESS_TLS_KEY"), cert: tlsFile("VIRKI_WITNESS_TLS_CERT"),
      ca: tlsFile("VIRKI_WITNESS_TLS_CA"), minVersion: "TLSv1.3", handshakeTimeout: 10000,
      requestCert: true, rejectUnauthorized: true } };
}

const handler = async (request, response) => {
  response.setHeader("Content-Type", "application/json");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Connection", "close");
  if (remote && (!request.socket.authorized || !request.socket.getPeerCertificate()?.raw ||
      createHash("sha256").update(request.socket.getPeerCertificate().raw).digest("hex") !== pinnedClient)) {
    response.writeHead(403).end('{"error":"CLIENT_IDENTITY_REFUSED"}');
    return;
  }
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
      status: remote ? "INDEPENDENT_WITNESS_RECEIPT" : "DISPOSABLE_WITNESS_ONLY", witnessCasAuthorized: false,
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
};
const server = remote ? createTlsServer(listener.tls, handler) : createServer(handler);
server.requestTimeout = 10000;
server.headersTimeout = 10000;
server.timeout = 10000;
server.maxRequestsPerSocket = 1;
server.maxConnections = 64;
if (remote) {
  server.listen(listener.port, listener.hostname, () => {
    process.stdout.write(`WITNESS_REMOTE_READY ${server.address().port}\n`);
  });
} else {
  server.listen(socket, () => {
    chmodSync(socket, 0o600);
    process.stdout.write("WITNESS_DISPOSABLE_READY\n");
  });
}
const close = () => {
  server.close(() => {
    witness.close();
    if (socket) {
      try { unlinkSync(socket); } catch { /* removed by test fixture */ }
    }
    process.exit(0);
  });
};
process.once("SIGTERM", close);
process.once("SIGINT", close);
