import assert from "node:assert/strict";
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
