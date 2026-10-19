import assert from "node:assert/strict";
import test from "node:test";
import { hashAuditIdentifier } from "@virki/auth";
import { createProviderEventAudit } from "./provider-audit";

test("OIDC provider errors are attributed and keep only hashed client references and safe error codes", () => {
  const record = createProviderEventAudit("userinfo.error", {
    oidc: { client: { clientId: "project-client-id" }, session: { accountId: "user-123" } }
  }, { error: "invalid_token", message: "token=raw-secret-value" });

  assert.equal(record?.eventType, "SSO_USERINFO_REJECTED");
  assert.equal(record?.result, "FAILURE");
  assert.equal(record?.actorUserId, "user-123");
  assert.equal(record?.resource, "sso.userinfo");
  assert.deepEqual(record?.metadata, { clientRef: hashAuditIdentifier("project-client-id"), error: "invalid_token" });
  assert.doesNotMatch(JSON.stringify(record), /project-client-id|raw-secret-value|token=/u);
});

test("provider logout and internal errors map to bounded audit events", () => {
  const context = { oidc: { entities: { Grant: { accountId: "grant-owner" } } } };
  const logout = createProviderEventAudit("end_session.success", context);
  const internal = createProviderEventAudit("server_error", context, new Error("database password=not-for-audit"));

  assert.equal(logout?.eventType, "SSO_LOGOUT_COMPLETED");
  assert.equal(logout?.result, "SUCCESS");
  assert.equal(logout?.actorUserId, "grant-owner");
  assert.equal(internal?.eventType, "SSO_PROVIDER_ERROR");
  assert.equal(internal?.result, "FAILURE");
  assert.deepEqual(internal?.metadata, { error: "server_error" });
  assert.doesNotMatch(JSON.stringify(internal), /password=not-for-audit|database/u);
  assert.equal(createProviderEventAudit("unknown.event", context), null);
});
