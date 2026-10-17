import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { authenticateUserWithRateLimit } from "./index";
import { hashAuditEmail, writeAuditLogRequired } from "./audit";
import { bootstrapFirstAdmin, FirstAdminBootstrapError } from "./bootstrap-first-admin";
import { integrationOptions } from "./integration-fixtures";

after(() => prisma.$disconnect());

test("legitimate bootstrap survives real pre-account authentication, audit and limiter activity in an otherwise virgin DB", { skip: integrationOptions.skip || (process.env.VIRKI_BOOTSTRAP_TEST_DATABASE_CONFIRM !== "virgin" ? "dedicated virgin bootstrap fixture not configured" : false) }, async () => {
  // A separate freshly migrated fixture is mandatory; this test never erases pre-existing data.
  assert.equal(await prisma.user.count(), 0, "Use a dedicated fresh bootstrap test database.");
  const email = `unknown-${randomUUID()}@integration.invalid`;
  const password = randomBytes(24).toString("base64url");
  for (let attempt = 0; attempt < 35; attempt += 1) {
    const authentication = await authenticateUserWithRateLimit(email, password, new Date(), "192.0.2.10", "USER");
    assert.equal(authentication.user, null);
    await writeAuditLogRequired({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource: "portal", message: authentication.failureMode === "rate-limited" ? "Login rate limit reached." : "Login failed.", actorEmailHash: hashAuditEmail(email), metadata: { source: "portal-login" } });
  }
  const auditCount = await prisma.auditLog.count();
  const rateCount = await prisma.loginRateLimit.count();
  assert.equal(auditCount, 35);
  assert.ok(rateCount > 0);
  const admin = await bootstrapFirstAdmin({ email: `owner-${randomUUID()}@integration.invalid`, password });
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: admin.id } })).role, "ADMIN");
  assert.equal(await prisma.auditLog.count(), auditCount + 1, "Immutable anonymous audit history is preserved.");
  assert.equal(await prisma.loginRateLimit.count(), rateCount, "Rate limits are preserved.");
  await assert.rejects(() => bootstrapFirstAdmin({ email: `other-${randomUUID()}@integration.invalid`, password }), (error) => error instanceof FirstAdminBootstrapError && error.code === "DATABASE_NOT_VIRGIN");
  assert.equal(await prisma.user.count(), 1, "Bootstrap cannot take over an initialized database.");
});
