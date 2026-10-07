import assert from "node:assert/strict";
import test from "node:test";

import {
  assertDisposableCoreTestDatabase,
  CORE_TEST_DATABASE_CONFIRMATION,
  sanitizeCoreTestOutput
} from "./core-test-database-safety.mjs";

const safeEnvironment = {
  NODE_ENV: "test",
  VIRKI_CORE_TEST_DATABASE_CONFIRM: CORE_TEST_DATABASE_CONFIRMATION
};

test("accepts only explicitly disposable local PostgreSQL targets", () => {
  const target = assertDisposableCoreTestDatabase(
    "postgresql://virki_test:local-validation-only@127.0.0.1:55432/virki_core_test",
    safeEnvironment
  );

  assert.equal(target.hostname, "127.0.0.1");
  assert.equal(target.pathname, "/virki_core_test");
});

test("accepts the isolated runtime identity used only by authenticated browser fixtures", () => {
  const target = assertDisposableCoreTestDatabase(
    "postgresql://virki_runtime_test:local-validation-only@127.0.0.1:55432/virki_e2e_test",
    safeEnvironment
  );

  assert.equal(target.username, "virki_runtime_test");
  assert.equal(target.pathname, "/virki_e2e_test");
});

test("rejects production mode, remote hosts, and non-test identities", () => {
  assert.throws(() =>
    assertDisposableCoreTestDatabase(
      "postgresql://virki_test:local-validation-only@127.0.0.1:55432/virki_core_test",
      { ...safeEnvironment, NODE_ENV: "production" }
    )
  );
  assert.throws(() =>
    assertDisposableCoreTestDatabase(
      "postgresql://virki_test:local-validation-only@database.example.invalid:5432/virki_core_test",
      safeEnvironment
    )
  );
  assert.throws(() =>
    assertDisposableCoreTestDatabase(
      "postgresql://virki_app:local-validation-only@127.0.0.1:5432/virki",
      safeEnvironment
    )
  );
});

test("redacts disposable connection details from subprocess output", () => {
  const databaseUrl =
    "postgresql://virki_test:local-validation-only@127.0.0.1:55432/virki_core_test";
  const sanitized = sanitizeCoreTestOutput(`failed at ${databaseUrl}`, databaseUrl);

  assert.equal(sanitized.includes(databaseUrl), false);
  assert.equal(sanitized.includes("local-validation-only"), false);
});
