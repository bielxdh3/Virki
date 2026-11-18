import assert from "node:assert/strict";
import test from "node:test";
import type { AuditLogInput } from "@virki/auth/audit";
import { createBoundedPreauthDenialAuditWriter } from "./preauth-denial-audit";

const denial: AuditLogInput = {
  eventType: "CSRF_DENIED", result: "DENIED", reason: "csrf", resource: "identity.security",
  metadata: { source: "login-origin" }
};

test("anonymous denial audit has a finite per-process time-window budget and resumes after the window", async () => {
  let clock = 1_000;
  let writes = 0;
  const warnings: string[] = [];
  const record = createBoundedPreauthDenialAuditWriter(async () => { writes += 1; }, {
    now: () => clock, windowMs: 1_000, maxEvents: 4,
    warn: (message) => { warnings.push(message); }
  });
  await Promise.all(Array.from({ length: 100 }, () => record(denial)));
  assert.equal(writes, 4, "a fast database must not turn invalid anonymous requests into unlimited inserts");
  assert.equal(warnings.length, 1, "audit drops should have one sanitized capacity warning per window");
  assert.doesNotMatch(warnings.join(" "), /cookie|password|203\.0\.113/u);

  clock += 1_001;
  await record(denial);
  assert.equal(writes, 5, "new windows must allow security-denial evidence again");
});

test("slow anonymous audit writes retain a strict in-flight ceiling after response deadline", async () => {
  let release!: () => void;
  const pending = new Promise<void>((done) => { release = done; });
  let writes = 0;
  const record = createBoundedPreauthDenialAuditWriter(async () => { writes += 1; await pending; }, {
    waitMs: 10, maxPending: 2, maxEvents: 100, warn: () => {}
  });
  try {
    await Promise.all(Array.from({ length: 50 }, () => record(denial)));
    assert.equal(writes, 2, "the request deadline must not release stuck database slots");
  } finally {
    release();
  }
  await new Promise<void>((resolve) => setImmediate(resolve));
  await record(denial);
  assert.equal(writes, 3);
});
