import assert from "node:assert/strict";
import test from "node:test";
import { assertExclusiveWorkerDatabaseTarget, assertMandatoryHolTap } from "./worker-hol.mjs";
import { assertGenericIntegrationSelection, discoverGenericIntegrationTests } from "./discovery.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const suite = "packages/auth/src/email-worker-hol.integration.test.ts";
// Build a synthetic URL from segments to avoid storing anything that looks
// like a usable database credential or a raw URL with userinfo in source.
const fakeDatabase = ["postgresql://", "virki_runtime_test", ":",
  "synthetic-placeholder-only-32-characters", "@127.0.0.1:55678/",
  "virki_email_worker_hol_a1b2c3d4e5f6", "?schema=public"].join("");
const target = {
  NODE_ENV: "test", VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
  VIRKI_EMAIL_WORKER_DEDICATED_DB: "confirmed",
  VIRKI_INTEGRATION_DATABASE_URL: fakeDatabase
};

const tap = `TAP version 13
# Subtest: three exhausted head rows never delay a genuine queued OTP
ok 1 - three exhausted head rows never delay a genuine queued OTP
# Subtest: concurrent workers cannot both claim or deliver the same OTP
ok 2 - concurrent workers cannot both claim or deliver the same OTP
1..2
# tests 2
# suites 0
# pass 2
# fail 0
# cancelled 0
# skipped 0
# todo 0
`;

test("dedicated HOL test is excluded from generic integration discovery", () => {
  assert.equal(discoverGenericIntegrationTests(root).includes(suite), false);
  assert.throws(() => assertGenericIntegrationSelection([suite]), /dedicated PostgreSQL/u);
  assert.doesNotThrow(() => assertGenericIntegrationSelection(["packages/auth/src/email-worker.integration.test.ts"]));
});

test("runner accepts only explicit disposable loopback unique PG role and DB", () => {
  assert.equal(assertExclusiveWorkerDatabaseTarget(target).pathname, "/virki_email_worker_hol_a1b2c3d4e5f6");
  for (const unsafe of [
    { VIRKI_CORE_TEST_DATABASE_CONFIRM: undefined },
    { VIRKI_EMAIL_WORKER_DEDICATED_DB: undefined },
    { NODE_ENV: "production" },
    { VIRKI_INTEGRATION_DATABASE_URL: target.VIRKI_INTEGRATION_DATABASE_URL.replace("127.0.0.1", "db.example.invalid") },
    { VIRKI_INTEGRATION_DATABASE_URL: target.VIRKI_INTEGRATION_DATABASE_URL.replace("virki_runtime_test", "virki_migrator") },
    { VIRKI_INTEGRATION_DATABASE_URL: target.VIRKI_INTEGRATION_DATABASE_URL.replace("virki_email_worker_hol_a1b2c3d4e5f6", "virki_e2e_test") }
  ]) assert.throws(() => assertExclusiveWorkerDatabaseTarget({ ...target, ...unsafe }));
});

test("runner rejects false-green TAP summaries and missing physical regression", () => {
  assert.doesNotThrow(() => assertMandatoryHolTap(tap));
  assert.throws(() => assertMandatoryHolTap(tap.replace("# skipped 0", "# skipped 1")), /must all PASS/u);
  assert.throws(() => assertMandatoryHolTap(tap.replace("# fail 0", "# fail 1")), /must all PASS/u);
  assert.throws(() => assertMandatoryHolTap(tap.replace("# pass 2", "# pass 1")), /must all PASS/u);
  assert.throws(() => assertMandatoryHolTap(tap.replace("# tests 2", "# tests 0")), /must all PASS/u);
  assert.throws(() => assertMandatoryHolTap(tap.replace("ok 1 -", "not ok 1 -")), /did not PASS/u);
  assert.throws(() => assertMandatoryHolTap(tap.replaceAll("concurrent workers cannot both claim or deliver the same OTP", "a different test")), /did not PASS/u);
  assert.throws(() => assertMandatoryHolTap(tap.replace("# skipped 0", "")), /Missing or ambiguous/u);
});
