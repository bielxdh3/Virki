// Disposable test server ONLY. It never invokes Docker, nor opens a Docker
// daemon socket on the host. All paths are created by the isolated test runner.
import { chmodSync, lstatSync } from "node:fs";
import net from "node:net";

const socketPath = process.argv[2];
if (process.env.VIRKI_DISPOSABLE_PEER_PROBE !== "1" ||
    !socketPath?.startsWith("/tmp/virki-peer-fixture-") ||
    !socketPath.endsWith("/docker.sock") ||
    process.platform !== "linux" || process.getuid() !== 0 ||
    !process.send) process.exit(21);
const active = new Set();
const server = net.createServer((socket) => {
  active.add(socket);
  socket.on("error", () => {});
  socket.on("close", () => active.delete(socket));
});
server.on("error", () => process.exit(22));
server.listen(socketPath, () => {
  chmodSync(socketPath, 0o600);
  const stat = lstatSync(socketPath);
  if (!stat.isSocket() || stat.uid !== 0 || (stat.mode & 0o777) !== 0o600)
    process.exit(23);
  process.send({ ready: true, pid: process.pid });
});
process.on("SIGTERM", () => {
  for (const socket of active) socket.destroy();
  server.close(() => process.exit(0));
});
