import assert from "node:assert/strict";
import test from "node:test";
import { createHubRenderProof, verifyHubRenderProof } from "./hub-render-provenance";

const env = { VIRKI_CSRF_SIGNING_KEY: "ab".repeat(32), NODE_ENV: "production" };

test("Hub render proof is short-lived and bound to the original server key and session", () => {
  const proof = createHubRenderProof("test-session", env, 1_800_000_000_000);
  assert.ok(proof);
  assert.equal(verifyHubRenderProof(proof, "test-session", env, 1_800_000_000_500), true);
  assert.equal(verifyHubRenderProof(proof, "other-session", env, 1_800_000_000_500), false);
  assert.equal(verifyHubRenderProof(proof, "test-session", { ...env, VIRKI_CSRF_SIGNING_KEY: "ff".repeat(32) }, 1_800_000_000_500), false);
  assert.equal(verifyHubRenderProof(proof, "test-session", env, 1_800_000_121_000), false);
  assert.equal(verifyHubRenderProof(proof, "test-session", env, 1_799_999_969_000), false);
  const altered = `${proof!.slice(0, -1)}${proof!.endsWith("x") ? "y" : "x"}`;
  assert.equal(verifyHubRenderProof(altered, "test-session", env, 1_800_000_000_500), false);
  assert.equal(verifyHubRenderProof(proof, "test-session", { ...env, VIRKI_CSRF_SIGNING_KEY: "ff".repeat(32), VIRKI_CSRF_SIGNING_KEY_PREVIOUS: env.VIRKI_CSRF_SIGNING_KEY }, 1_800_000_000_500), true);
});

test("missing/malformed configuration or client claims cannot manufacture a verified context", () => {
  assert.equal(createHubRenderProof("session", { NODE_ENV: "production" }), null);
  assert.equal(createHubRenderProof("session", { VIRKI_CSRF_SIGNING_KEY: "invalid" }), null);
  assert.equal(createHubRenderProof(undefined, env), null);
  assert.equal(verifyHubRenderProof("forged", "session", env), false);
  assert.equal(verifyHubRenderProof(null, "session", env), false);
  assert.equal(verifyHubRenderProof("forged", undefined, env), false);
});
