import assert from "node:assert/strict";
import test from "node:test";

import {
  isDeclaredCapability,
  negotiateModuleCapabilities,
  validateCapabilityEnvelope,
  validateModuleCapabilityManifest
} from "./capabilities";

const manifest = {
  protocolVersion: 1,
  module: { id: "root.ark", version: "0.1.0" },
  capabilities: [{
    name: "health.read",
    version: 1,
    classification: "status",
    auth: "bielos-session",
    authorization: "principal-scoped",
    audit: "required",
    requestSchema: "HealthRequestV1",
    responseSchema: "HealthResponseV1",
    timeoutMs: 800,
    maxRetries: 1,
    idempotency: "optional",
    freshnessRequired: true
  }]
} as const;

test("accepts a bounded versioned capability manifest", () => {
  const parsed = validateModuleCapabilityManifest(manifest);
  assert.ok(parsed);
  assert.equal(isDeclaredCapability(parsed, "health.read"), true);
  assert.equal(isDeclaredCapability(parsed, "backup.status"), false);
});

test("rejects unsafe or unbounded capability declarations", () => {
  assert.equal(validateModuleCapabilityManifest({ ...manifest, module: { id: "../secret", version: "0.1.0" } }), null);
  assert.equal(validateModuleCapabilityManifest({ ...manifest, capabilities: [{ ...manifest.capabilities[0], timeoutMs: 60_000 }] }), null);
  assert.equal(validateModuleCapabilityManifest({ ...manifest, capabilities: [{ ...manifest.capabilities[0], name: "files.read-all" }] }), null);
  assert.equal(validateModuleCapabilityManifest({ ...manifest, capabilities: [{ ...manifest.capabilities[0], authorization: "unscoped" }] }), null);
  assert.equal(validateModuleCapabilityManifest({ ...manifest, capabilities: [manifest.capabilities[0], manifest.capabilities[0]] }), null);
});

test("negotiates only declared, non-deprecated capability versions", () => {
  const parsed = validateModuleCapabilityManifest(manifest);
  assert.ok(parsed);
  assert.deepEqual(negotiateModuleCapabilities(parsed, [
    { name: "health.read", version: 1 },
    { name: "backup.status", version: 1 }
  ]).map((capability) => capability.name), ["health.read"]);
});

test("validates freshness-tagged capability envelopes without interpreting module data", () => {
  const envelope = validateCapabilityEnvelope({
    protocolVersion: 1,
    moduleId: "gymforge",
    capability: "health.read",
    generatedAt: "2026-09-18T12:00:00.000Z",
    freshnessMs: 5000,
    provenance: { source: "gymforge-health", observedAt: "2026-09-18T12:00:00.000Z", revision: "abc123" },
    data: { state: "healthy", private: "module-owned" }
  });
  assert.equal(envelope?.moduleId, "gymforge");
  assert.equal((envelope?.data as { state: string }).state, "healthy");
  assert.equal(validateCapabilityEnvelope({ protocolVersion: 1, moduleId: "gymforge", capability: "health.read", generatedAt: "now", freshnessMs: -1, provenance: { source: "x", observedAt: "now" }, data: null }), null);
});
