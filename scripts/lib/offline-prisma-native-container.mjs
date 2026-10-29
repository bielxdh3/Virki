import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// A two-container, DEVELOPMENT-ONLY fixed Docker recipe. The PostgreSQL
// namespace has Docker --network=none. The separate Prisma CLI runner ALSO
// has --network=none and exchanges only a Unix-domain PostgreSQL socket via
// one randomly named, inspected, disposable volume (never PGDATA). This is
// not production host / Docker daemon attestation.
// W28 disposable experiment: immutable IDs of images already present locally.
// This variant is for validation only; image receipts are not owner authority.
export const POSTGRES = "sha256:57b23a0326ee442e83b3d3fa027c5a148be0a392d7c91d1ca4e1e70131ee859a";
export const NODE = "sha256:b3836fa4137b0d202cb83631ddf53e76800deac5c3d4af9130db49a1b8690ce4";
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
  const base = ["run", "--detach", "--rm", "--pull=never", "--platform=linux/amd64"];
  const common = ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128"];
  const pgArgs = [...base, "--name", pgName, "--label", `${OWNER_LABEL}=${owner}`,
    "--network=none", ...common, "--user=postgres",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=70,gid=70,mode=700",
    // PG18 image declares /var/lib/postgresql VOLUME. Override the entire
    // directory with tmpfs, otherwise Docker creates anonymous persistent data.
    "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,size=512m,uid=70,gid=70,mode=700",
    "--mount", `type=volume,src=${socketVolume},dst=/var/run/postgresql`,
    "--mount", `type=bind,src=${source},dst=/workspace,readonly`, "--workdir", "/workspace",
    "--env", "VIRKI_PRISMA_NATIVE_DISPOSABLE=1", POSTGRES,
    "sh", "/workspace/scripts/fixtures/offline-prisma-native/postgres.sh"];
  const nodeArgs = [...base, "--name", nodeName, "--label", `${OWNER_LABEL}=${owner}`,
    "--network=none", ...common, "--user=1000:1000",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=700",
    "--mount", `type=volume,src=${socketVolume},dst=/var/run/postgresql`,
    "--mount", `type=bind,src=${source},dst=/workspace,readonly`,
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
        (m.Type === "tmpfs" && ["/tmp", "/var/lib/postgresql"].includes(m.Destination)) ||
      (m.Type === "volume" && m.Destination === "/var/run/postgresql" &&
        m.Name === expected.socketVolume && m.RW === true)));
  return true;
}
