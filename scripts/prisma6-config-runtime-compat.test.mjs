import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import test from "node:test";

import { deepmerge } from "deepmerge-ts";
import { loadConfig as loadC12 } from "c12";
import { Either, Schema } from "effect";

const require = createRequire(import.meta.url);
const { defineConfig, loadConfigFromFile } = require("@prisma/config");

function withPrismaConfig(t, contents) {
  const root = mkdtempSync(path.join(tmpdir(), "virki-prisma6-compat-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(path.join(root, "package.json"), '{"name":"prisma6-runtime-contract","private":true,"type":"commonjs"}');
  writeFileSync(path.join(root, "prisma.config.cjs"), contents);
  return root;
}

test("vendored Prisma6 actually loads a c12 config with safe deepmerge-ts 8", async (t) => {
  const root = withPrismaConfig(t, 'module.exports = { schema: "./schema.prisma", migrations: { path: "./migrations" }, typedSql: { path: "./queries" }, views: { path: "./views" } };');
  const configFile = path.join(root, "prisma.config.cjs");
  let mergerInvocations = 0;
  const fromC12 = await loadC12({
    cwd: root, name: "prisma", configFile, dotenv: false, rcFile: false,
    giget: false, extend: false, packageJson: false,
    merger: (...values) => {
      mergerInvocations += 1;
      return deepmerge(...values);
    }
  });
  assert.ok(mergerInvocations > 0, "c12 must actually invoke the upgraded deepmerge API, not only accept its option");
  assert.equal(fromC12.config?.schema, "./schema.prisma", "c12 must resolve its config using the upgraded merger");
  const loaded = await loadConfigFromFile({ configRoot: root, configFile });
  assert.equal(loaded.error, undefined, JSON.stringify(loaded.error));
  assert.equal(loaded.resolvedPath, configFile);
  for (const [actual, relative] of [
    [loaded.config.schema, "schema.prisma"],
    [loaded.config.migrations.path, "migrations"],
    [loaded.config.typedSql.path, "queries"],
    [loaded.config.views.path, "views"]
  ]) {
    assert.equal(actual, path.join(root, relative), "Prisma must resolve configured local paths");
  }
});

test("Effect 3.22 schema/Either used by Prisma6 reject malformed config and preserve valid features", async (t) => {
  const good = defineConfig({ experimental: { externalTables: true }, tables: { external: ["existing_table"] } });
  assert.deepEqual(good.tables.external, ["existing_table"]);
  assert.throws(() => defineConfig({ engine: "js" }), /requires.*experimental\.adapter/u);

  const malformedRoot = withPrismaConfig(t, 'module.exports = { schema: 12345 };');
  const malformed = await loadConfigFromFile({ configRoot: malformedRoot, configFile: path.join(malformedRoot, "prisma.config.cjs") });
  assert.equal(malformed.config, undefined, "invalid schema must not produce a trusted Prisma config");
  assert.equal(malformed.error?._tag, "ConfigFileSyntaxError");

  const decoded = Schema.decodeUnknownEither(Schema.Struct({ enabled: Schema.Boolean }))({ enabled: true });
  assert.equal(Either.isRight(decoded), true);
  assert.equal(Either.isLeft(Schema.decodeUnknownEither(Schema.Struct({ enabled: Schema.Boolean }))({ enabled: "yes" })), true);
});

test("deepmerge-ts 8's ordinary JSON-object contract retains nested values without mutation", () => {
  const original = { migrations: { path: "./old", seed: "node seed.js" }, tables: { external: ["users"] } };
  const override = { migrations: { path: "./new" }, tables: { external: ["posts"] } };
  const merged = deepmerge(original, override);
  assert.deepEqual(merged.migrations, { path: "./new", seed: "node seed.js" });
  assert.equal(original.migrations.path, "./old", "upgraded merger must not mutate its caller");
  assert.deepEqual(merged.tables.external, ["users", "posts"], "array merge contract for c12");
  assert.deepEqual(original.tables.external, ["users"]);
});
