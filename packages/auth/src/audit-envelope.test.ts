import assert from "node:assert/strict";
import test from "node:test";
import { createAuditLogData, createAuditRequestMetadata, runWithAuditContext, hashAuditIdentifier } from "./audit";
import { formatDateTime } from "./date-time";

test("persisted envelope normalizes action and pseudonym without retaining private metadata", () => {
  const data = createAuditLogData({ eventType: "ACCOUNT_STATE_CHANGED", result: "SUCCESS", actorUserId: "actor-123", resource: "account", metadata: { enabled: false, targetRef: "a".repeat(64), arbitrary: "private@example.invalid", password: "synthetic" } });
  assert.equal(data.schemaVersion, 1);
  assert.equal(data.category, "ACCOUNT");
  assert.equal(data.action, "account.state.changed");
  assert.equal(data.actorRef, hashAuditIdentifier("actor-123"));
  assert.equal(data.targetRef, "a".repeat(64));
  assert.equal(data.actorRole, undefined, "an actor id does not prove a role");
  assert.equal(data.networkProvenance, "unavailable");
  assert.deepEqual(data.metadata, { enabled: false, targetRef: "a".repeat(64), password: "[REDACTED]" });
});

test("real request context propagates only generated identifiers and safe route templates", async () => {
  const id = "c2245041-0904-4fa1-a6a8-053df5241d90";
  const data = await runWithAuditContext({ requestId: id, service: "issuer", route: "/token", method: "POST" }, async () => createAuditLogData({ eventType: "SSO_TOKEN_REJECTED", result: "FAILURE" }));
  assert.equal(data.requestId, id);
  assert.equal(data.service, "issuer");
  assert.equal(data.route, "/token");
  assert.equal(data.severity, "WARNING");
  assert.equal(createAuditLogData({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE" }).requestId, undefined);
});

test("request metadata ignores forwarding, cookies and caller correlation headers", () => {
  const metadata = createAuditRequestMetadata(new Headers({ "x-request-id": "spoof", "cf-connecting-ip": "203.0.113.1", "x-forwarded-for": "203.0.113.2", cookie: "synthetic" }), "hub-login");
  assert.equal(metadata.requestId, undefined);
  assert.doesNotMatch(JSON.stringify(metadata), /203\.0\.113|spoof|synthetic/u);
});

test("presentation uses Porto Velho UTC minus four independent of host zone", () => {
  assert.equal(formatDateTime("2026-01-01T02:03:00.000Z"), "31/12/2025, 22:03 (UTC−4)");
});

test("unverified attempted account references are searchable without inventing an actor role", () => {
  const data = createAuditLogData({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", actorEmailHash: "a".repeat(64) });
  assert.equal(data.actorRef, hashAuditIdentifier("a".repeat(64)));
  assert.equal(data.actorRole, undefined);
});
