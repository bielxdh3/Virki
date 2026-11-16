import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createEmailWorkerScramVerifier, matchesEmailWorkerScramVerifier } from "./staging-email-worker-scram.mjs";

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

test("operator preflight proves SCRAM verifier matches the exact credential, never an unrelated one", () => {
  const credential = randomBytes(32).toString("hex");
  const wrong = randomBytes(32).toString("hex");
  const verifier = createEmailWorkerScramVerifier(credential);
  assert.equal(matchesEmailWorkerScramVerifier(credential, verifier), true);
  assert.equal(matchesEmailWorkerScramVerifier(wrong, verifier), false);
  assert.equal(matchesEmailWorkerScramVerifier(credential, createEmailWorkerScramVerifier(wrong)), false);
  for (const invalid of ["", "SCRAM-SHA-256$4096:bad$bad:bad", verifier + " ", null]) {
    assert.equal(matchesEmailWorkerScramVerifier(credential, invalid), false);
  }
});

test("operator CLI refuses mismatched SCRAM without logging the credential or verifier", () => {
  const credential = randomBytes(32).toString("hex");
  const verifier = createEmailWorkerScramVerifier(credential);
  const source = fileURLToPath(new URL("./staging-email-worker-scram.mjs", import.meta.url));
  const check = (candidate) => spawnSync(process.execPath, [source], {
    encoding: "utf8", windowsHide: true, timeout: 10_000,
    env: {
      ...process.env, VIRKI_VERIFY_EMAIL_WORKER_SCRAM: "operator-approved",
      VIRKI_GENERATE_EMAIL_WORKER_SCRAM: "",
      VIRKI_EMAIL_WORKER_DB_PASSWORD: credential,
      VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER: candidate
    }
  });
  const good = check(verifier);
  assert.equal(good.status, 0);
  assert.equal(good.stdout.trim(), "SCRAM_VERIFIER_PAIR=VALID");
  const bad = check(createEmailWorkerScramVerifier(randomBytes(32).toString("hex")));
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /password\/verifier mismatch/u);
  for (const output of [good.stdout, good.stderr, bad.stdout, bad.stderr]) {
    assert.equal(output.includes(credential), false);
    assert.equal(output.includes(verifier), false);
  }
});
