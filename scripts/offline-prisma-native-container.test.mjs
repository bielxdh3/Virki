import assert from "node:assert/strict";
import test from "node:test";
import {
  planDisposablePrismaNative, assertPrismaNativeDockerMetadata,
} from "./lib/offline-prisma-native-container.mjs";
import { runDisposablePrismaNative } from "./offline-prisma-native-run.mjs";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pg = "a".repeat(64);
const owner = "b".repeat(32);
test("no-host-port Prisma and PG both have no network, share only an owned Unix socket volume", () => {
  const plan = planDisposablePrismaNative({ owner, socketVolume: `virki-prisma-sock-${owner}` });
  assert.deepEqual(plan.pg.image,
    "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24");
  assert.deepEqual(plan.node.image,
    "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8");
  assert.ok(plan.pg.args.includes("--network=none"));
  assert.ok(plan.node.args.includes("--network=none"));
  assert.ok(plan.pg.args.includes("--mount"));
  assert.ok(plan.node.args.includes("--mount"));
  assert.ok(plan.pg.args.includes(`type=volume,src=virki-prisma-sock-${owner},dst=/var/run/postgresql`));
  assert.ok(plan.node.args.includes(`type=volume,src=virki-prisma-sock-${owner},dst=/var/run/postgresql`));
  for (const args of [plan.pg.args, plan.node.args]) {
    assert.equal(args.some((x) => /^--(?:publish|publish-all|privileged|network=bridge|network=host)/u.test(x)), false);
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("--cap-drop=ALL"));
    assert.ok(args.includes("--security-opt=no-new-privileges"));
    assert.ok(args.includes("--pull=never"));
  }
  assert.equal(plan.productionProof, false);
  assert.equal(plan.deployAuthorized, false);
});

test("refuses malicious CID and owner-controlled container selection", () => {
  for (const input of [{ owner, socketVolume: "../docker.sock" },
    { owner: "../../demanage", socketVolume: `virki-prisma-sock-${owner}` },
    { owner, socketVolume: `virki-prisma-sock-${owner}`, databaseUrl: "postgresql://foreign" }])
    assert.throws(() => planDisposablePrismaNative(input), /refus/iu);
});

test("Docker inspected container identity and port/network boundaries are mandatory", () => {
  const expected = { id: pg, name: `virki-prisma-pg-${owner}`, owner,
    socketVolume: `virki-prisma-sock-${owner}`,
    imageId: "sha256:" + "c".repeat(64), imageRef: "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24",
    network: "none" };
  const healthy = { Id: pg, Name: `/${expected.name}`,
    Config: { Image: expected.imageRef, Labels: { "dev.virki.prisma-native.owner": owner } },
    Image: expected.imageId,
    HostConfig: { NetworkMode: "none", Privileged: false, PortBindings: {}, Binds: null, CapDrop: ["ALL"] },
    NetworkSettings: { Ports: {} }, Mounts: [{ Type: "volume", Destination: "/var/run/postgresql",
      Name: `virki-prisma-sock-${owner}`, RW: true }] };
  assert.doesNotThrow(() => assertPrismaNativeDockerMetadata(healthy, expected));
  for (const change of [
    { HostConfig: { ...healthy.HostConfig, PortBindings: { "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "5432" }] } } },
    { HostConfig: { ...healthy.HostConfig, NetworkMode: "bridge" } },
    { Image: "sha256:" + "d".repeat(64) },
    { Config: { ...healthy.Config, Labels: {} } },
    { Mounts: [{ Type: "volume", Destination: "/prod", RW: true }] },
  ]) assert.throws(() => assertPrismaNativeDockerMetadata({ ...healthy, ...change }, expected), /refus/iu);
});

test("malicious external DB URL or Docker endpoint are refused BEFORE any invocation", { skip: process.platform !== "win32" }, () => {
  for (const malicious of [{ DATABASE_URL: "postgresql://foreign.invalid/real" },
    { PGHOSTADDR: "203.0.113.42" }, { DOCKER_HOST: "tcp://foreign.invalid:2375" }]) {
    assert.throws(() => runDisposablePrismaNative({
      argv: ["happy"], env: { VIRKI_PRISMA_NATIVE_DISPOSABLE: "1", ...malicious },
    }));
  }
  assert.throws(() => runDisposablePrismaNative({
    argv: ["--url=postgresql://foreign.invalid/real"],
    env: { VIRKI_PRISMA_NATIVE_DISPOSABLE: "1" },
  }));
});

test("Postgres shell script uses ONLY Unix socket, disables TCP, and never accepts external URL", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const script = readFileSync(path.join(root, "scripts/fixtures/offline-prisma-native/postgres.sh"), "utf8");
  assert.match(script, /listen_addresses=''/u);
  assert.match(script, /--auth-host=reject/u);
  assert.match(script, /virki_migrator virki_runtime virki_audit_maintenance/u);
  assert.match(script, /\$\{DATABASE_URL:-\}/u);
  assert.doesNotMatch(script, /listen_addresses=127\.0\.0\.1|listen_addresses=\*/u);
});

test("the committed audit migration's hard prerequisite role is bootstrapped before SQL", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const script = readFileSync(path.join(root, "scripts/fixtures/offline-prisma-native/postgres.sh"), "utf8");
  const requiredMigration = readFileSync(path.join(root,
    "packages/database/prisma/migrations/20261006120000_audit_log_role_boundaries/migration.sql"), "utf8");
  const missingRoleGuard = /IF NOT EXISTS \(SELECT 1 FROM pg_roles WHERE rolname = '([a-z_]+)'\)/gu;
  const required = [...requiredMigration.matchAll(missingRoleGuard)].map((match) => match[1]);
  assert.deepEqual(required, ["virki_audit_maintenance"]);
  const bootstrap = /for role in ([a-z_ ]+); do\s+psql[\s\S]*?CREATE ROLE \$role NOLOGIN/gu.exec(script);
  assert.ok(bootstrap);
  const roles = bootstrap[1].trim().split(/\s+/u);
  assert.ok(required.every((role) => roles.includes(role)));
  assert.ok(script.indexOf("for role in ") < script.indexOf("0_init/migration.sql"));
});

test("schema-engine SIGKILL helper refuses direct invocation outside owned Linux container", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const helper = path.join(root, "scripts/fixtures/offline-prisma-native/interrupt.mjs");
  for (const command of ["run", "kill", "result"]) {
    const result = spawnSync(process.execPath, [helper, command], {
      encoding: "utf8", timeout: 5000, maxBuffer: 2048,
      env: { VIRKI_PRISMA_NATIVE_DISPOSABLE: "" },
    });
    assert.equal(result.error, undefined);
    assert.notEqual(result.status, 0);
  }
});
