import assert from "node:assert/strict";
import { test } from "node:test";
import { assertDedicatedSmtpWireTarget, assertSmtpWireTap } from "./email-smtp-wire.mjs";
import { assertLoopbackSmtpAddress } from "./loopback-smtp-sink.mjs";

// Construct a fake disposable credential in memory, never store a literal
// URL containing userinfo in source (including an interpolated password).
const disposableDatabaseUrl = new URL("postgresql://127.0.0.1:5432/virki_e2e_test?schema=public");
disposableDatabaseUrl.username = "virki_runtime_test";
disposableDatabaseUrl.password = "f".repeat(64);

const disposable = {
  NODE_ENV: "test",
  VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
  VIRKI_EMAIL_WIRE_DEDICATED_DB: "confirmed",
  VIRKI_EMAIL_WIRE_NETWORK_ISOLATED: "confirmed",
  VIRKI_INTEGRATION_DATABASE_URL: disposableDatabaseUrl.href
};

test("SMTP wire refuses ambient credentials, production and any non-exclusive DB", () => {
  assert.equal(assertDedicatedSmtpWireTarget(disposable).pathname, "/virki_e2e_test");
  const invalid = [
    { NODE_ENV: "production" },
    { VIRKI_EMAIL_WIRE_NETWORK_ISOLATED: "" },
    { VIRKI_EMAIL_WIRE_DEDICATED_DB: "" },
    { VIRKI_CORE_TEST_DATABASE_CONFIRM: "" },
    { VIRKI_EMAIL_SMTP_HOST: "smtp-relay.example.com" },
    { VIRKI_EMAIL_SMTP_PASSWORD: "ambient-secret" },
    { VIRKI_EMAIL_OUTBOX_KEY: "ambient-key" },
    { NODE_EXTRA_CA_CERTS: "/arbitrary-ca.pem" },
    { VIRKI_INTEGRATION_DATABASE_URL: disposable.VIRKI_INTEGRATION_DATABASE_URL.replace("127.0.0.1", "postgres") },
    { VIRKI_INTEGRATION_DATABASE_URL: disposable.VIRKI_INTEGRATION_DATABASE_URL.replace("virki_e2e_test", "production") },
    { VIRKI_INTEGRATION_DATABASE_URL: disposable.VIRKI_INTEGRATION_DATABASE_URL.replace("virki_runtime_test", "postgres") },
    { VIRKI_INTEGRATION_DATABASE_URL: disposable.VIRKI_INTEGRATION_DATABASE_URL.replace("f".repeat(64), "weak") }
  ];
  for (const change of invalid) {
    assert.throws(() => assertDedicatedSmtpWireTarget({ ...disposable, ...change }));
  }
});

test("SMTP sink refuses external endpoints and real mailbox addresses", () => {
  assert.doesNotThrow(() => assertLoopbackSmtpAddress("127.0.0.1",
    "fixture@integration.invalid", "wire-sender@integration.invalid"));
  for (const value of ["localhost", "::1", "0.0.0.0", "smtp-relay.brevo.com"]) {
    assert.throws(() => assertLoopbackSmtpAddress(value,
      "fixture@integration.invalid", "wire-sender@integration.invalid"));
  }
  assert.throws(() => assertLoopbackSmtpAddress("127.0.0.1",
    "user@gmail.com", "wire-sender@integration.invalid"));
  assert.throws(() => assertLoopbackSmtpAddress("127.0.0.1",
    "fixture@integration.invalid", "no-reply@production.example"));
});

test("SMTP wire runner rejects missing, skipped, duplicated and fake TAP results", () => {
  const name = "real worker sends queued recovery OTP over verified loopback STARTTLS AUTH and rejects replay";
  const valid = `ok 1 - ${name}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n`;
  assert.doesNotThrow(() => assertSmtpWireTap(valid));
  for (const invalid of [
    valid.replace("# pass 1", "# pass 0"),
    valid.replace("# skipped 0", "# skipped 1"),
    valid.replace("# cancelled 0", "# cancelled 1"),
    valid.replace("ok 1 - ", "not ok 1 - "),
    valid.replace("# tests 1", "# tests 2"),
    valid + `ok 1 - ${name}\n`,
    ""
  ]) assert.throws(() => assertSmtpWireTap(invalid));
});
