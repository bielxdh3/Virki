import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { prisma } from "@virki/database";
import { evaluateProxyRequest } from "../../../apps/hub/src/proxy";
import { bootstrapFirstAdmin } from "./bootstrap-first-admin";
import { integrationOptions } from "./integration-fixtures";

test("first ADMIN bootstrap survives an anonymous Hub denial during staged installation", integrationOptions, async () => {
  const hubHost = "hub.integration.invalid";
  const env = {
    NODE_ENV: "production",
    VIRKI_HUB_HOSTNAME: hubHost,
    VIRKI_PORTAL_HOSTNAME: "portal.integration.invalid",
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: "synthetic-audience",
    CLOUDFLARE_TEAM_DOMAIN: "https://access.integration.invalid"
  };
  const health = await evaluateProxyRequest(new NextRequest(`https://${hubHost}/api/health`, { headers: { host: hubHost } }), env);
  assert.equal(health.status, 200, "the staged health probe should pass before the bootstrap ceremony");
  const denied = await evaluateProxyRequest(new NextRequest(`https://${hubHost}/admin/accounts`, {
    headers: { host: hubHost }
  }), env);
  assert.equal(denied.status, 403);
  const requestId = denied.headers.get("x-virki-request-id");
  assert.match(requestId ?? "", /^[a-f0-9-]{36}$/u);

  const denialAudit = await prisma.auditLog.findFirst({
    where: { requestId },
    select: {
      id: true, eventType: true, result: true, resource: true, message: true, reason: true,
      actorUserId: true, actorEmailHash: true, actorRole: true, sessionRef: true, metadata: true
    }
  });
  assert.ok(denialAudit);
  assert.equal(denialAudit.actorUserId, null);
  assert.equal(denialAudit.actorEmailHash, null);
  assert.equal(denialAudit.actorRole, null);
  assert.equal(denialAudit.sessionRef, null);
  assert.equal(denialAudit.reason, "cloudflare");
  assert.deepEqual(denialAudit.metadata && typeof denialAudit.metadata === "object" && !Array.isArray(denialAudit.metadata)
    ? Object.keys(denialAudit.metadata).sort()
    : null, ["accessJwtStatus", "requestId", "source"]);
  assert.deepEqual(denialAudit.metadata && typeof denialAudit.metadata === "object" && !Array.isArray(denialAudit.metadata)
    ? { source: denialAudit.metadata.source, accessJwtStatus: denialAudit.metadata.accessJwtStatus }
    : null, { source: "hub-ingress", accessJwtStatus: "missing" });
  assert.match(String(denialAudit.metadata && typeof denialAudit.metadata === "object" && !Array.isArray(denialAudit.metadata) ? denialAudit.metadata.requestId : ""), /^[a-f0-9-]{36}$/u);

  let createdUser: Record<string, unknown> | undefined;
  const emptyModels = [
    "session", "loginRateLimit", "projectConnection", "userProjectGrant", "oidcArtifact",
    "emailOutboxMessage", "emailDeliveryAttempt", "totpFactor", "recoveryCode", "deviceChallenge",
    "trustedDevice", "accountRecoveryRequest", "sanitizedAuditReference", "administrativeCredential",
    "administrativeRecoveryCode", "securityElevation"
  ];
  const transaction = Object.assign({
    $queryRaw: async () => [{ acquired: 1 }],
    user: {
      count: async () => 0,
      create: async ({ data }: { data: Record<string, unknown> }) => {
        createdUser = data;
        return { id: "synthetic-first-admin" };
      }
    },
    auditLog: {
      count: async () => 1,
      findMany: async () => [denialAudit]
    }
  }, Object.fromEntries(emptyModels.map((model) => [model, { count: async () => 0 }])));
  const database = {
    $transaction: async (callback: (value: typeof transaction) => Promise<unknown>) => callback(transaction)
  };
  const firstAdmin = await bootstrapFirstAdmin({
    email: "owner@integration.invalid",
    displayName: "Owner",
    password: "test-only-password-2026"
  }, {
    database: database as never,
    hashPassword: async () => "synthetic-password-hash",
    hashAdminEmail: () => "a".repeat(64),
    writeAudit: async () => undefined
  });
  assert.equal(firstAdmin.id, "synthetic-first-admin");
  assert.equal(createdUser?.role, "ADMIN");
  assert.equal(createdUser?.emailVerifiedAt, null);
});
