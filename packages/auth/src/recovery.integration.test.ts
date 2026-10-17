import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl } from "./integration-fixtures";
import {
  approveAccountRecovery,
  consumeApprovedAccountRecovery,
  getAccountRecoveryRequestId,
  getAccountRecoveryState,
  requestAccountRecovery,
  RECOVERY_REQUEST_COOLDOWN_MS,
  verifyAccountRecoveryEmail
} from "./security";
import { verifyPassword } from "./index";

after(() => prisma.$disconnect());

async function openLatestRecovery(email: string, now: Date) {
  const emails = (await queuedEmails(email)).filter((message) => message.kind === "ACCOUNT_RECOVERY");
  const latest = emails.at(-1);
  const requestKey = requestKeyFromActionUrl(latest?.actionUrl);
  const opened = await getAccountRecoveryRequestId(requestKey, now);
  assert.ok(opened, "the newest emailed recovery link opens");
  assert.equal((await getAccountRecoveryState(opened.id, requestKey, now))?.purpose, "RECOVERY");
  return { requestId: opened.id, requestKey, code: latest?.code };
}

test("an anonymous request cannot expire a verified recovery awaiting approval", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-owner" });
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-admin" });
  const start = new Date();
  await requestAccountRecovery(owner.email, "pt-BR", start);
  const legit = await openLatestRecovery(owner.email, start);
  await verifyAccountRecoveryEmail(legit.requestId, legit.requestKey, legit.code ?? "", start);

  const attackerTime = new Date(start.getTime() + RECOVERY_REQUEST_COOLDOWN_MS + 1_000);
  await requestAccountRecovery(owner.email, "pt-BR", attackerTime);

  const state = await getAccountRecoveryState(legit.requestId, legit.requestKey, attackerTime);
  assert.equal(state?.status, "PENDING");
  assert.equal(state?.emailVerified, true);
  await approveAccountRecovery({ id: admin.id, role: "ADMIN" }, legit.requestId, attackerTime);
});

test("an anonymous request after approval cannot expire the approved recovery", integrationOptions, async () => {
  const owner = await createTestUser({ label: "recovery-approved" });
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-approver" });
  const start = new Date();
  await requestAccountRecovery(owner.email, "pt-BR", start);
  const legit = await openLatestRecovery(owner.email, start);
  await verifyAccountRecoveryEmail(legit.requestId, legit.requestKey, legit.code ?? "", start);
  await approveAccountRecovery({ id: admin.id, role: "ADMIN" }, legit.requestId, start);
  const approved = await openLatestRecovery(owner.email, start);
  assert.equal(approved.requestId, legit.requestId);

  const attackerTime = new Date(start.getTime() + RECOVERY_REQUEST_COOLDOWN_MS + 1_000);
  await requestAccountRecovery(owner.email, "pt-BR", attackerTime);

  const newPassword = "integration-new-password-1";
  await consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, newPassword, attackerTime);
  const stored = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { passwordHash: true } });
  assert.equal(await verifyPassword(stored.passwordHash ?? "", newPassword), true);
  await assert.rejects(consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "integration-replayed-password", attackerTime));
});


test("portal recovery abuse does not spend the hub address or source budget", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", label: "recovery-isolation" });
  const security = await import("./security");
  const { createRateLimitIdentifierHash } = await import("./rate-limit-config");
  const base = new Date();
  const uuid = randomUUID().replaceAll("-", "");
  const source = `2001:db8:${uuid.slice(0, 4)}:${uuid.slice(4, 8)}:${uuid.slice(8, 12)}:${uuid.slice(12, 16)}:${uuid.slice(16, 20)}:${uuid.slice(20, 24)}`;
  const rateLimitAttempts = async (identifier: string) => (await prisma.loginRateLimit.findUnique({
    where: { identifierHash: createRateLimitIdentifierHash(identifier) },
    select: { attempts: true }
  }))?.attempts ?? null;
  for (let index = 0; index < 6; index += 1) await security.requestAccountRecovery(admin.email, "pt-BR", new Date(base.getTime() + index * 1000), source);

  assert.equal(await rateLimitAttempts(`recovery-source:USER:${source}`), 6);
  assert.equal(await rateLimitAttempts(`recovery-source:ADMIN:${source}`), null);
  assert.equal(await rateLimitAttempts(`account-recovery-address:USER:${admin.email.toLowerCase()}`), 5);
  assert.equal(await rateLimitAttempts(`account-recovery-address:ADMIN:${admin.email.toLowerCase()}`), null);

  await security.requestAdministrativeAccountRecovery(admin.email, "pt-BR", new Date(base.getTime() + 7000), source);

  assert.equal(await rateLimitAttempts(`recovery-source:USER:${source}`), 6);
  assert.equal(await rateLimitAttempts(`recovery-source:ADMIN:${source}`), 1);
  assert.equal(await rateLimitAttempts(`account-recovery-address:USER:${admin.email.toLowerCase()}`), 5);
  assert.equal(await rateLimitAttempts(`account-recovery-address:ADMIN:${admin.email.toLowerCase()}`), 1);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { userId: admin.id } }), 1);
});
