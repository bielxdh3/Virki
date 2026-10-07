import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { reuseE2eEmailOutboxKey, reuseE2eRuntimeDirectory } from "./runtime-artifacts.mjs";

test("reuses only a complete parent-created E2E runtime directory", () => {
  const directory = mkdtempSync(join(tmpdir(), "virki-e2e-tls-test-"));
  try {
    for (const name of ["server-key.pem", "server-cert.pem", "test-ca-cert.pem", "access-signing-key.json"]) {
      writeFileSync(join(directory, name), "fixture");
    }
    const env = {
      VIRKI_E2E_RUNTIME_READY: "true",
      VIRKI_E2E_RUNTIME_DIRECTORY: directory,
      VIRKI_E2E_TLS_KEY_PATH: join(directory, "server-key.pem"),
      VIRKI_E2E_TLS_CERTIFICATE_PATH: join(directory, "server-cert.pem"),
      VIRKI_E2E_TLS_CA_CERTIFICATE_PATH: join(directory, "test-ca-cert.pem"),
      VIRKI_E2E_ACCESS_SIGNING_KEY_FILE: join(directory, "access-signing-key.json"),
      VIRKI_E2E_OIDC_PRIVATE_CONFIG_FILE: join(directory, "issuer-config.json")
    };

    assert.equal(reuseE2eRuntimeDirectory(env), directory);
    assert.equal(reuseE2eRuntimeDirectory({ ...env, VIRKI_E2E_RUNTIME_READY: "false" }), undefined);
    assert.equal(reuseE2eRuntimeDirectory({ ...env, VIRKI_E2E_TLS_CA_CERTIFICATE_PATH: join(directory, "other-ca.pem") }), undefined);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("does not reuse an ambient email outbox key outside a ready E2E runtime", () => {
  assert.equal(reuseE2eEmailOutboxKey({ VIRKI_E2E_RUNTIME_READY: "false", VIRKI_EMAIL_OUTBOX_KEY: "ambient-value" }), undefined);
  assert.equal(reuseE2eEmailOutboxKey({ VIRKI_E2E_RUNTIME_READY: "true", VIRKI_EMAIL_OUTBOX_KEY: "shared-test-value" }), "shared-test-value");
});
