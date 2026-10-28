import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// A two-container, DEVELOPMENT-ONLY fixed Docker recipe. The PostgreSQL
// namespace has Docker --network=none. The separate Prisma CLI runner ALSO
// has --network=none and exchanges only a Unix-domain PostgreSQL socket via
// one randomly named, inspected, disposable volume (never PGDATA). This is
// not production host / Docker daemon attestation.
export const POSTGRES = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
export const NODE = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
export const OWNER_LABEL = "dev.virki.prisma-native.owner";
const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const HEX32 = /^[a-f0-9]{32}$/u;
const HEX64 = /^[a-f0-9]{64}$/u;
function refuse() { throw new Error("Disposable no-port Prisma/PostgreSQL fixture refused."); }
function need(ok) { if (!ok) refuse(); }

export function planDisposablePrismaNative(request) {
  need(request && typeof request === "object" && !Array.isArray(request) &&
    Object.keys(request).length === 2 && HEX32.test(request.owner) &&
    request.socketVolume === `virki-prisma-sock-${request.owner}`);
  const { owner, socketVolume } = request;
  const pgName = `virki-prisma-pg-${owner}`;
  const nodeName = `virki-prisma-node-${owner}`;
  const source = realpathSync.native(ROOT);
  // node_modules must belong to this exact repository's parent, never to a
  // Docker-supplied mount or a caller-supplied arbitrary dependency tree.
  const deps = realpathSync.native(path.join(path.dirname(path.dirname(ROOT)), "node_modules"));
  const base = ["run", "--detach", "--rm", "--pull=never", "--platform=linux/amd64"];
  const common = ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128"];
  const pgArgs = [...base, "--name", pgName, "--label", `${OWNER_LABEL}=${owner}`,
    "--network=none", ...common, "--user=postgres",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=70,gid=70,mode=700",
    "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m,uid=70,gid=70,mode=700",
    "--mount", `type=volume,src=${socketVolume},dst=/var/run/postgresql`,
    "--mount", `type=bind,src=${source},dst=/workspace,readonly`, "--workdir", "/workspace",
    "--env", "VIRKI_PRISMA_NATIVE_DISPOSABLE=1", POSTGRES,
    "sh", "/workspace/scripts/fixtures/offline-prisma-native/postgres.sh"];
  const nodeArgs = [...base, "--name", nodeName, "--label", `${OWNER_LABEL}=${owner}`,
    "--network=none", ...common, "--user=70:70",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=70,gid=70,mode=700",
    "--mount", `type=volume,src=${socketVolume},dst=/var/run/postgresql`,
    "--mount", `type=bind,src=${source},dst=/workspace,readonly`,
    "--mount", `type=bind,src=${deps},dst=/usr/local/lib/node_modules,readonly`,
    "--workdir", "/workspace", "--env", "VIRKI_PRISMA_NATIVE_DISPOSABLE=1",
    "--env", "HOME=/tmp", "--env", "PRISMA_HIDE_UPDATE_MESSAGE=1",
    NODE, "sh", "-c", "sleep 600"];
  return Object.freeze({ pg: { name: pgName, image: POSTGRES, args: pgArgs },
    node: { name: nodeName, image: NODE, args: nodeArgs },
    productionProof: false, transferAuthorized: false, deployAuthorized: false });
}

/** Evaluate provider-owned inspect metadata as a consistency check ONLY. */
export function assertPrismaNativeDockerMetadata(actual, expected) {
  need(actual && expected && HEX64.test(expected.id) &&
    actual.Id === expected.id && actual.Name === `/${expected.name}` &&
    actual.Config?.Labels?.[OWNER_LABEL] === expected.owner &&
    actual.Config?.Image === expected.imageRef && actual.Image === expected.imageId &&
    /^sha256:[a-f0-9]{64}$/u.test(actual.Image) &&
    actual.HostConfig?.NetworkMode === expected.network &&
    actual.HostConfig?.Privileged === false &&
    Array.isArray(actual.HostConfig?.CapDrop) &&
    actual.HostConfig.CapDrop.some((v) => v.toLowerCase() === "all") &&
    (actual.HostConfig?.PortBindings == null || Object.keys(actual.HostConfig.PortBindings).length === 0) &&
    (actual.NetworkSettings?.Ports == null || Object.values(actual.NetworkSettings.Ports).every((x) => x == null)) &&
    !actual.HostConfig?.Binds?.length &&
    Array.isArray(actual.Mounts) && actual.Mounts.every((m) =>
      (m.Type === "bind" && m.RW === false && ["/workspace", "/usr/local/lib/node_modules"].includes(m.Destination)) ||
      (m.Type === "tmpfs" && ["/tmp", "/var/lib/postgresql/data"].includes(m.Destination)) ||
      (m.Type === "volume" && m.Destination === "/var/run/postgresql" &&
        m.Name === expected.socketVolume && m.RW === true)));
  return true;
}
