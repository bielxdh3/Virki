import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";

import {
  cleanupInactiveSessions,
  getSessionByToken,
  hashSessionToken
} from "@bielos/auth";
import { prisma } from "@bielos/database";

import {
  CORE_SESSION_LIST_LIMIT,
  CoreSessionMutationError,
  listCoreSessionsForPrincipal,
  revokeAllOtherCoreSessionRecords,
  revokeCoreSessionRecord
} from "../security/session-service";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

let owner: { id: string };
let admin: { id: string };
let member: { id: string };

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
  [owner, admin, member] = await Promise.all([
    createUser("owner@example.invalid", "OWNER"),
    createUser("admin@example.invalid", "ADMIN"),
    createUser("member-a@example.invalid", "MEMBER")
  ]);
});

after(async () => {
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("session display is active-user scoped and excludes token hashes", async () => {
  const now = new Date();
  const ownerCurrent = await createSessionRow(owner.id, "owner-current", now, 60, -20);
  const ownerOther = await createSessionRow(owner.id, "owner-other", now, 60, -10);
  const adminSession = await createSessionRow(admin.id, "admin-current", now, 60, -5);
  const memberSession = await createSessionRow(member.id, "member-current", now, 60, -2);
  await createSessionRow(owner.id, "owner-expired", now, -1, -30);
  await createSessionRow(owner.id, "owner-revoked", now, 60, -25, now);

  const ownerDisplay = await listCoreSessionsForPrincipal(owner, ownerCurrent.id, now);
  const adminDisplay = await listCoreSessionsForPrincipal(admin, adminSession.id, now);
  const memberDisplay = await listCoreSessionsForPrincipal(member, memberSession.id, now);

  assert.deepEqual(ownerDisplay.map((session) => session.id), [ownerOther.id, ownerCurrent.id]);
  assert.equal(ownerDisplay.find((session) => session.id === ownerCurrent.id)?.isCurrent, true);
  assert.equal(ownerDisplay.find((session) => session.id === ownerOther.id)?.isCurrent, false);
  assert.deepEqual(adminDisplay.map((session) => session.id), [adminSession.id]);
  assert.deepEqual(memberDisplay.map((session) => session.id), [memberSession.id]);

  for (const display of [ownerDisplay, adminDisplay, memberDisplay]) {
    for (const session of display) {
      assert.deepEqual(Object.keys(session).sort(), ["createdAt", "expiresAt", "id", "isCurrent"]);
      assert.equal("tokenHash" in session, false);
      assert.equal(JSON.stringify(session).includes("owner-current"), false);
    }
  }

  await prisma.user.update({ where: { id: member.id }, data: { isActive: false } });
  assert.deepEqual(
    await listCoreSessionsForPrincipal(member, memberSession.id, now),
    []
  );
  assert.deepEqual(
    await listCoreSessionsForPrincipal(owner, adminSession.id, now),
    []
  );
});

test("session display remains bounded and always includes the authenticated session", async () => {
  const now = new Date();
  const current = await createSessionRow(
    owner.id,
    "bounded-current",
    now,
    60,
    -CORE_SESSION_LIST_LIMIT * 2
  );
  await prisma.session.createMany({
    data: Array.from({ length: CORE_SESSION_LIST_LIMIT + 5 }, (_, index) => ({
      userId: owner.id,
      tokenHash: hashSessionToken(`bounded-fixture-${index}`),
      expiresAt: new Date(now.getTime() + 60 * 60_000),
      createdAt: new Date(now.getTime() - index * 1_000)
    }))
  });

  const display = await listCoreSessionsForPrincipal(owner, current.id, now);
  const expectedOtherSessions = await prisma.session.findMany({
    where: { userId: owner.id, id: { not: current.id } },
    select: { id: true },
    orderBy: { createdAt: "desc" },
    take: CORE_SESSION_LIST_LIMIT - 1
  });

  assert.equal(display.length, CORE_SESSION_LIST_LIMIT);
  assert.equal(display.filter((session) => session.isCurrent).length, 1);
  assert.equal(display.some((session) => session.id === current.id), true);
  assert.deepEqual(
    display.filter((session) => !session.isCurrent).map((session) => session.id),
    expectedOtherSessions.map((session) => session.id)
  );
});

test("single-session revocation enforces ownership and invalidates authentication", async () => {
  const now = new Date();
  const current = await createSessionRow(owner.id, "fixture-session-token-01", now, 60);
  const ownOther = await createSessionRow(owner.id, "fixture-session-token-02", now, 60);
  const foreign = await createSessionRow(member.id, "foreign-session", now, 60);
  const expired = await createSessionRow(owner.id, "single-expired", now, -1);
  const alreadyRevoked = await createSessionRow(
    owner.id,
    "single-revoked",
    now,
    60,
    0,
    now
  );

  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, current.id, current.id, now)
  );
  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, current.id, foreign.id, now)
  );
  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, current.id, expired.id, now)
  );
  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, current.id, alreadyRevoked.id, now)
  );
  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, current.id, "missing-session", now)
  );

  await revokeCoreSessionRecord(owner, current.id, ownOther.id, now);
  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, current.id, ownOther.id, now)
  );

  assert.equal(await getSessionByToken("fixture-session-token-02"), null);
  assert.notEqual(await getSessionByToken("fixture-session-token-01"), null);
  assert.equal((await prisma.session.findUniqueOrThrow({ where: { id: foreign.id } })).revokedAt, null);

  const audit = await prisma.auditLog.findFirstOrThrow({
    where: { eventType: "AUTH_SESSION_REVOKED", resource: "session" }
  });
  assertSafeSessionAudit(audit.metadata, [
    "fixture-session-token-02",
    "fixture-session-token-01",
    hashSessionToken("fixture-session-token-02"),
    "owner@example.invalid",
    ownOther.id
  ]);
  assert.deepEqual(Object.keys((audit.metadata ?? {}) as object).sort(), ["scope", "sessionRef"]);
});

test("revoke-all preserves current and foreign sessions while cleanup remains compatible", async () => {
  const now = new Date();
  const current = await createSessionRow(owner.id, "all-current", now, 60);
  const firstOther = await createSessionRow(owner.id, "all-other-a", now, 60);
  const secondOther = await createSessionRow(owner.id, "all-other-b", now, 60);
  const foreign = await createSessionRow(member.id, "all-foreign", now, 60);
  const expired = await createSessionRow(owner.id, "all-expired", now, -1);

  await expectSessionMutationRejected(
    revokeAllOtherCoreSessionRecords(owner, current.id, false, now)
  );
  const result = await revokeAllOtherCoreSessionRecords(owner, current.id, true, now);
  assert.equal(result.revokedCount, 2);

  const rows = await prisma.session.findMany({
    where: { id: { in: [current.id, firstOther.id, secondOther.id, foreign.id, expired.id] } },
    select: { id: true, revokedAt: true }
  });
  const byId = new Map(rows.map((row) => [row.id, row.revokedAt]));
  assert.equal(byId.get(current.id), null);
  assert.notEqual(byId.get(firstOther.id), null);
  assert.notEqual(byId.get(secondOther.id), null);
  assert.equal(byId.get(foreign.id), null);
  assert.equal(byId.get(expired.id), null);

  assert.notEqual(await getSessionByToken("all-current"), null);
  assert.equal(await getSessionByToken("all-other-a"), null);
  assert.notEqual(await getSessionByToken("all-foreign"), null);

  assert.equal(await cleanupInactiveSessions(now), 3);
  assert.equal(await prisma.session.count({ where: { id: current.id } }), 1);
  assert.equal(await prisma.session.count({ where: { id: foreign.id } }), 1);

  const audit = await prisma.auditLog.findFirstOrThrow({
    where: { eventType: "AUTH_SESSION_REVOKED", resource: "session" }
  });
  assert.deepEqual(audit.metadata, { scope: "all-other", revokedCount: 2 });
});

test("expired, revoked, inactive, and cross-user current sessions cannot authorize mutations", async () => {
  const now = new Date();
  const ownerCurrent = await createSessionRow(owner.id, "state-current", now, 60);
  const ownerOther = await createSessionRow(owner.id, "state-other", now, 60);
  const memberCurrent = await createSessionRow(member.id, "state-member", now, 60);

  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, memberCurrent.id, ownerOther.id, now)
  );

  await prisma.session.update({
    where: { id: ownerCurrent.id },
    data: { revokedAt: now }
  });
  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, ownerCurrent.id, ownerOther.id, now)
  );

  await prisma.session.update({
    where: { id: ownerCurrent.id },
    data: { revokedAt: null, expiresAt: new Date(now.getTime() - 1) }
  });
  await expectSessionMutationRejected(
    revokeAllOtherCoreSessionRecords(owner, ownerCurrent.id, true, now)
  );

  await prisma.session.update({
    where: { id: ownerCurrent.id },
    data: { expiresAt: new Date(now.getTime() + 60_000) }
  });
  await prisma.user.update({ where: { id: owner.id }, data: { isActive: false } });
  await expectSessionMutationRejected(
    revokeCoreSessionRecord(owner, ownerCurrent.id, ownerOther.id, now)
  );
  assert.equal(await getSessionByToken("state-current"), null);
});

function createUser(email: string, role: "OWNER" | "ADMIN" | "MEMBER") {
  return prisma.user.create({
    data: { email, role, isActive: true },
    select: { id: true }
  });
}

function createSessionRow(
  userId: string,
  syntheticToken: string,
  now: Date,
  expiresInMinutes: number,
  createdMinutesAgo = 0,
  revokedAt: Date | null = null
) {
  return prisma.session.create({
    data: {
      userId,
      tokenHash: hashSessionToken(syntheticToken),
      expiresAt: new Date(now.getTime() + expiresInMinutes * 60_000),
      createdAt: new Date(now.getTime() + createdMinutesAgo * 60_000),
      revokedAt
    },
    select: { id: true }
  });
}

async function expectSessionMutationRejected(operation: Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert.equal(error instanceof CoreSessionMutationError, true);
    assert.equal((error as Error).message, "Core session mutation rejected.");
    return true;
  });
}

function assertSafeSessionAudit(metadata: unknown, forbiddenValues: string[]): void {
  const serialized = JSON.stringify(metadata);

  for (const value of forbiddenValues) {
    assert.equal(serialized.includes(value), false);
  }
}
