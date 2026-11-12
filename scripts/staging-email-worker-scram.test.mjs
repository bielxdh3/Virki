import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { createEmailWorkerScramVerifier } from "./staging-email-worker-scram.mjs";

test("worker password never appears in SQL-ready client-side SCRAM verifier", () => {
  const password = randomBytes(32).toString("hex");
  const salt = Buffer.alloc(16, 0xa5);
  const a = createEmailWorkerScramVerifier(password, salt);
  const b = createEmailWorkerScramVerifier(password, salt);
  assert.equal(a, b);
  assert.match(a, /^SCRAM-SHA-256\$4096:[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$/u);
  assert.equal(a.includes(password), false);
  assert.notEqual(createEmailWorkerScramVerifier(password), a, "random salt must produce a fresh verifier");
  for (const invalid of ["", "ab", "z".repeat(64), "a".repeat(63)]) {
    assert.throws(() => createEmailWorkerScramVerifier(invalid), /64 hexadecimal/u);
  }
});
