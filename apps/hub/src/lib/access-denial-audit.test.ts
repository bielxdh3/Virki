import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { createBoundedAccessDenialAuditWriter } from "./access-denial-audit";
import type { AuditLogInput } from "@virki/auth/audit";

const denial: AuditLogInput = {
  eventType: "ACCESS_JWT_MISSING", result: "DENIED", reason: "cloudflare",
  resource: "hub", metadata: { source: "hub-ingress", accessJwtStatus: "missing" }
};

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

test("available audit persistence completes before the Cloudflare denial returns", async () => {
  const completion = deferred();
  const recorded: AuditLogInput[] = [];
  const record = createBoundedAccessDenialAuditWriter(async (input) => {
    await completion.promise;
    recorded.push(input);
  }, { waitMs: 2_000 });

  let responded = false;
  const result = record(denial).then(() => { responded = true; });
  await delay(20);
  assert.equal(responded, false, "the response must await a healthy audit write");
  completion.resolve();
  await result;
  assert.deepEqual(recorded, [denial]);
});

test("stalled persistence has a strict concurrency ceiling, a response deadline, and recovers when writes settle", async () => {
  const completion = deferred();
  let writes = 0;
  const warnings: string[] = [];
  const record = createBoundedAccessDenialAuditWriter(async () => {
    writes += 1;
    await completion.promise;
  }, { waitMs: 30, maxPending: 3, warn: (message) => { warnings.push(message); } });

  const started = Date.now();
  await Promise.all(Array.from({ length: 500 }, () => record(denial)));
  assert.ok(Date.now() - started < 1_500, "even a flood must not delay the deny response");
  assert.equal(writes, 3, "slow writes must remain accounted for after response timeout");
  assert.deepEqual(warnings, ["Hub Access denial audit capacity reached; denial remains enforced."]);
  await record(denial);
  assert.equal(writes, 3, "timed-out requests must not release the in-flight limit");

  completion.resolve();
  await delay(20);
  await record(denial);
  assert.equal(writes, 4, "a recovered database must accept new audit writes");
});

test("unexpected audit writer failures are caught without preventing denial", async () => {
  const warnings: string[] = [];
  const record = createBoundedAccessDenialAuditWriter(async () => {
    throw new Error("synthetic secret must not reach logs");
  }, { warn: (message) => { warnings.push(message); } });
  await record(denial);
  assert.deepEqual(warnings, ["Hub Access denial audit persistence failed."]);
});
