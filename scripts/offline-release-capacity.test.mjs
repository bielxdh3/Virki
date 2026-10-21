import assert from "node:assert/strict";
import test from "node:test";
import {
  assessOfflineReleaseCapacity, requireOfflineReleaseCapacity,
} from "./lib/offline-release-capacity.mjs";

const GiB = 1024 ** 3;
const inputs = {
  freeBytes: 16 * GiB,
  sourceArchiveBytes: 12 * 1024 ** 2,
  runtimeArchiveBytes: 900 * 1024 ** 2,
  migratorArchiveBytes: 1200 * 1024 ** 2,
  runtimeExpandedBytes: 1 * GiB,
  migratorExpandedBytes: 2 * GiB,
  databaseBytes: 500 * 1024 ** 2,
};

test("budget accepts ample space while retaining four full GiB of headroom", () => {
  const budget = requireOfflineReleaseCapacity(inputs);
  assert.equal(budget.ok, true);
  assert.equal(budget.deficitBytes, "0");
  assert.equal(budget.retainedReserveBytes, String(4 * GiB));
  assert.ok(BigInt(budget.requiredBytes) > 13n * BigInt(GiB));
});

test("budget refuses inadequate space even if image layers might be deduplicated", () => {
  const input = { ...inputs, freeBytes: 9 * GiB };
  const budget = assessOfflineReleaseCapacity(input);
  assert.equal(budget.ok, false);
  assert.ok(BigInt(budget.deficitBytes) > 0n);
  assert.throws(() => requireOfflineReleaseCapacity(input), /insufficient target disk/u);
});

test("incomplete, unmeasured, noninteger or huge inputs all fail closed", () => {
  for (const key of Object.keys(inputs)) {
    assert.throws(() => assessOfflineReleaseCapacity({ ...inputs, [key]: undefined }), /missing or unsafe/u);
    assert.throws(() => assessOfflineReleaseCapacity({ ...inputs, [key]: -1 }), /missing or unsafe/u);
    assert.throws(() => assessOfflineReleaseCapacity({ ...inputs, [key]: 0 }), /missing or unsafe/u);
    assert.throws(() => assessOfflineReleaseCapacity({ ...inputs, [key]: 1.5 }), /missing or unsafe/u);
    assert.throws(() => assessOfflineReleaseCapacity({ ...inputs, [key]: Number.MAX_SAFE_INTEGER }), /missing or unsafe/u);
  }
});
