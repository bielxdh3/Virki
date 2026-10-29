import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { NODE, POSTGRES, planDisposablePrismaNative } from "./lib/offline-prisma-native-container.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const source = (file) => readFileSync(path.join(root, file), "utf8");

test("disposable prebuilt image inputs use exact locally inspected content identities", () => {
  assert.equal(POSTGRES, "sha256:57b23a0326ee442e83b3d3fa027c5a148be0a392d7c91d1ca4e1e70131ee859a");
  assert.equal(NODE, "sha256:b3836fa4137b0d202cb83631ddf53e76800deac5c3d4af9130db49a1b8690ce4");
  const plan = planDisposablePrismaNative({ owner: "a".repeat(32), socketVolume: `virki-prisma-sock-${"a".repeat(32)}` });
  assert.ok(plan.node.args.includes("--network=none"));
  assert.equal(plan.node.args.some((x) => x.includes("node_modules")), false);
  assert.ok(plan.node.args.includes("--user=1000:1000"));
  assert.ok(plan.node.args.includes("/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=700"));
  assert.ok(plan.pg.args.some((x) => x.startsWith("/var/lib/postgresql:rw,")));
  assert.equal(plan.pg.args.some((x) => x.startsWith("/var/lib/postgresql/data:")), false);
  assert.equal(plan.node.args.some((x) => /^--(?:publish|privileged|network=host)/u.test(x)), false);
});

test("real schema engine SIGKILL probe and CLI paths match the self-contained prebuilt image", () => {
  const script = source("scripts/offline-prisma-native-run.mjs");
  const interrupt = source("scripts/fixtures/offline-prisma-native/interrupt.mjs");
  const snapshot = source("scripts/fixtures/offline-prisma-native/snapshot.mjs");
  for (const text of [script, interrupt]) {
    assert.match(text, /\/app\/node_modules\/prisma\/build\/index\.js/u);
    assert.doesNotMatch(text, /\/usr\/local\/lib\/node_modules/u);
  }
  assert.match(interrupt, /\/opt\/virki-prisma\/schema-engine-linux-musl-openssl-3\.0\.x/u);
  assert.match(interrupt, /getuid\(\) !== 1000/u);
  assert.match(snapshot, /getuid\(\) !== 1000/u);
  assert.match(script, /real_prisma_p3009_after_schema_engine_sigkill/u);
  assert.match(script, /PRISMA_EXIT_MARKER_TIMEOUT/u);
  assert.match(script, /real_prisma_cli_exit_marker_observed/u);
  assert.match(source("scripts/fixtures/offline-prisma-native/postgres.sh"), /mkdir -m 700 \/var\/lib\/postgresql\/data/u);
});
