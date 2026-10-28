import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../", import.meta.url);
const scripts = JSON.parse(readFileSync(new URL("package.json", root), "utf8")).scripts;
const ci = readFileSync(new URL(".github/workflows/ci.yml", root), "utf8");

test("hosted CI canonical production revision includes new safe Stage4 invariant suites", () => {
  assert.match(ci, /run:\s+npm run test:production-revision/u);
  for (const path of [
    "infra/offline/trusted-witness-admission-preparation.test.mjs",
    "infra/offline/native-supervisor/disposable-killable-stage-invariants.test.mjs",
    "scripts/offline-stage4-test-wiring.test.mjs",
  ]) {
    assert.ok(scripts["test:production-revision"].includes(path),
      `Canonical CI misses required safe non-Docker Stage4 test ${path}`);
  }
  assert.ok(!scripts["test:production-revision"].includes("disposable-killable-stage.test.mjs"),
    "Real Docker native experiments may not run implicitly in hosted CI");
});
