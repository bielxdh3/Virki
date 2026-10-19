import assert from "node:assert/strict";
import test from "node:test";
import { createWindowsCaTrust } from "./windows-ca-trust.mjs";

test("installs only the generated CA in CurrentUser Root and removes that exact thumbprint once", () => {
  const calls = [];
  const trust = createWindowsCaTrust({
    platform: "win32",
    certificatePath: "C:\\Temp\\virki-e2e\\test-ca-cert.pem",
    thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567",
    runStoreCommand: (operation, scope, thumbprint, certificatePath) => calls.push({ operation, scope, thumbprint, certificatePath })
  });

  trust.install();
  trust.cleanup();
  trust.cleanup();

  assert.deepEqual(calls, [
    { operation: "add", scope: "CurrentUser\\Root", thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567", certificatePath: "C:\\Temp\\virki-e2e\\test-ca-cert.pem" },
    { operation: "remove", scope: "CurrentUser\\Root", thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567", certificatePath: undefined }
  ]);
});

test("surfaces Windows CA cleanup failures with a secret-safe error", () => {
  const trust = createWindowsCaTrust({
    platform: "win32",
    certificatePath: "C:\\Temp\\virki-e2e\\test-ca-cert.pem",
    thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567",
    runStoreCommand: (operation) => { if (operation === "remove") throw new Error("private command output"); }
  });

  trust.install();
  assert.throws(() => trust.cleanup(), /Windows E2E test CA cleanup failed/u);
});

test("keeps a partially completed install eligible for exact cleanup", () => {
  const installed = new Set();
  const calls = [];
  const thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
  const trust = createWindowsCaTrust({
    platform: "win32",
    certificatePath: "C:\\Temp\\virki-e2e\\test-ca-cert.pem",
    thumbprint,
    runStoreCommand: (operation, _scope, requestedThumbprint) => {
      calls.push(operation);
      if (operation === "add") {
        installed.add(requestedThumbprint);
        throw new Error("private command output");
      }
      installed.delete(requestedThumbprint);
    }
  });

  assert.throws(() => trust.install(), /Windows E2E test CA installation failed/u);
  trust.cleanup();

  assert.deepEqual(calls, ["add", "remove"]);
  assert.equal(installed.size, 0);
});

test("does not access a certificate store on non-Windows platforms", () => {
  let calls = 0;
  const trust = createWindowsCaTrust({
    platform: "linux",
    certificatePath: "/tmp/test-ca-cert.pem",
    thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567",
    runStoreCommand: () => { calls += 1; }
  });

  trust.install();
  trust.cleanup();
  assert.equal(calls, 0);
});
