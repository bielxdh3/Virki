import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";

const PRIVATE_ROOT = /^\/dev\/shm\/virki59-oidc-store-[A-Za-z0-9]{8}$/u;
const OWNER = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const HEX64 = /^[a-f0-9]{64}$/u;

function refuse() {
  throw new Error("Portable PostgreSQL transport refused: private native socket identity was not verified.");
}

function ownedOrdinary(location, type, uid, stat) {
  let item;
  try { item = stat(location); } catch { refuse(); }
  if (!item || item.isSymbolicLink() || item.uid !== uid ||
      (item.mode & 0o077) !== 0 ||
      (type === "directory" ? !item.isDirectory() : !item.isFile())) {
    refuse();
  }
}

// Only the private, socket-only cluster created by oidc-node-portable-store-proof.sh
// can opt into the Docker-free transport. No ambient PGHOSTADDR, Docker context
// or arbitrary executable override is honored. Dependency injection is for tests.
export function createVerifiedPortableOidcPgClient({
  env = process.env,
  platform = process.platform,
  uid = process.getuid?.(),
  stat = lstatSync,
  read = readFileSync
} = {}) {
  if (platform !== "linux" || !Number.isSafeInteger(uid) || uid < 0 ||
      env.VIRKI_OIDC_PG_TRANSPORT !== "portable-native") refuse();
  const socket = env.VIRKI_OIDC_PG_SOCKET;
  if (typeof socket !== "string" || !socket.endsWith("/socket") ||
      !path.posix.isAbsolute(socket) || path.posix.normalize(socket) !== socket) refuse();
  const root = path.posix.dirname(socket);
  if (!PRIVATE_ROOT.test(root)) refuse();
  const tools = path.posix.join(root, "tools");
  const shim = path.posix.join(tools, "docker");
  const ownerFile = path.posix.join(root, ".owner");
  if (env.VIRKI_OIDC_DOCKER_BINARY !== shim ||
      !/^[0-9]{5}$/u.test(env.PGPORT ?? "") ||
      Number(env.PGPORT) < 23000 || Number(env.PGPORT) >= 59000 ||
      env.PGHOST !== socket ||
      env.VIRKI_OIDC_PG_ROLE !== "rp_oidc_owner" ||
      env.VIRKI_OIDC_PG_DATABASE !== "rp_oidc_proof" ||
      env.VIRKI_OIDC_PG_SCHEMA !== "rp_oidc_private" ||
      !HEX64.test(env.VIRKI_OIDC_PG_PASSWORD ?? "") ||
      typeof env.VIRKI_OIDC_PSQL_BINARY !== "string" ||
      !path.posix.isAbsolute(env.VIRKI_OIDC_PSQL_BINARY) ||
      !env.VIRKI_OIDC_PSQL_BINARY.endsWith("/usr/lib/postgresql/18/bin/psql")) refuse();

  ownedOrdinary(root, "directory", uid, stat);
  ownedOrdinary(socket, "directory", uid, stat);
  ownedOrdinary(path.posix.join(root, "pgdata"), "directory", uid, stat);
  ownedOrdinary(tools, "directory", uid, stat);
  ownedOrdinary(shim, "file", uid, stat);
  ownedOrdinary(ownerFile, "file", uid, stat);
  // An extracted distribution's psql binary is normally mode 0755, unlike
  // the private shim; it need only be a real file at the expected bundle path.
  let psqlState;
  try { psqlState = stat(env.VIRKI_OIDC_PSQL_BINARY); } catch { refuse(); }
  if (!psqlState.isFile() || psqlState.isSymbolicLink()) refuse();
  let owner;
  try { owner = read(ownerFile, "utf8").trim(); } catch { refuse(); }
  if (!OWNER.test(owner) ||
      env.VIRKI_OIDC_PG_CONTAINER !== `virki-oidc-pg18-${owner}`) refuse();

  // Explicit socket arguments in the private shim take precedence over libpq,
  // but scrub all inherited PG* variables anyway (notably PGHOSTADDR).
  const scoped = Object.fromEntries(Object.entries(env).filter(
    ([key]) => !/^PG[A-Z_]/u.test(key) && !/^DOCKER_/iu.test(key)
  ));
  const subprocessEnv = Object.freeze({
    ...scoped, PGHOST: socket, PGPORT: env.PGPORT,
    VIRKI_OIDC_PG_SOCKET: socket, VIRKI_OIDC_DOCKER_BINARY: shim
  });
  return Object.freeze({ binary: shim, subprocessEnv });
}
