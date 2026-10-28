import test from "node:test";
import assert from "node:assert/strict";
import {
  isVerifiedPrismaInvocationResult,
  isVerifiedSuccessfulCleanup,
} from "./offline-prisma-native-result.mjs";

test("Prisma P1003/P3009 requires a completed nonzero unsignaled CLI exit", () => {
  for (const expectedCode of ["P1003", "P3009"]) {
    const observed = { status: 1, signal: null, error: undefined,
      stdout: `Prisma error ${expectedCode}`, stderr: "" };
    assert.equal(isVerifiedPrismaInvocationResult(observed, { expectedCode }), true);
    assert.equal(isVerifiedPrismaInvocationResult({ ...observed, status: null,
      signal: "SIGKILL" }, { expectedCode }), false);
    assert.equal(isVerifiedPrismaInvocationResult({ ...observed, status: null,
      signal: null }, { expectedCode }), false);
    assert.equal(isVerifiedPrismaInvocationResult({ ...observed, status: 0 }, { expectedCode }), false);
    assert.equal(isVerifiedPrismaInvocationResult({ ...observed, signal: "SIGTERM" }, { expectedCode }), false);
    assert.equal(isVerifiedPrismaInvocationResult({ ...observed, error: { code: "ETIMEDOUT" } }, { expectedCode }), false);
    assert.equal(isVerifiedPrismaInvocationResult({ ...observed, stdout: "P1000" }, { expectedCode }), false);
  }
});

test("Prisma negative divergence and normal success enforce real exit status", () => {
  const failed = { status: 1, signal: null, error: undefined, stdout: "validation failed", stderr: "" };
  assert.equal(isVerifiedPrismaInvocationResult(failed, { expectFailure: true }), true);
  assert.equal(isVerifiedPrismaInvocationResult({ ...failed, status: null, signal: "SIGKILL" },
    { expectFailure: true }), false);
  assert.equal(isVerifiedPrismaInvocationResult({ ...failed, status: 0 }, { expectFailure: true }), false);
  assert.equal(isVerifiedPrismaInvocationResult({ ...failed, status: 0 }, {}), true);
  assert.equal(isVerifiedPrismaInvocationResult(failed, {}), false);
});

test("cleanup uncertainty never permits a successful disposable proof", () => {
  const good = { finished: true, cleaned: true, createdCount: 2,
    volumeAttempted: true, volumeAccepted: true };
  assert.equal(isVerifiedSuccessfulCleanup(good), true);
  for (const failure of [
    { cleaned: false }, { createdCount: 1 }, { volumeAttempted: false },
    { volumeAccepted: false },
  ]) assert.equal(isVerifiedSuccessfulCleanup({ ...good, ...failure }), false);
  // An incomplete/failed migration has no positive proof to suppress.
  assert.equal(isVerifiedSuccessfulCleanup({ ...good, finished: false }), true);
});
