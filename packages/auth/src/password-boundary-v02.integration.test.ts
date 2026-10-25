import assert from "node:assert/strict";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { AdministrationMutationError, changeAdministrativePassword } from "./administration";
import {
  approveAccountRecovery,
  consumeApprovedAccountRecovery,
  getAccountRecoveryRequestId,
  requestAdministrativeAccountRecovery,
  SecurityMutationError,
  verifyAccountRecoveryEmail
} from "./security";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl, seedAdminSessionWithElevation } from "./integration-fixtures";
import { hashPassword, verifyPassword } from "./index";
import { hashAuditIdentifier } from "./audit";

after(() => prisma.$disconnect());

const NORMAL_INITIAL = "v02-normal-initial-distinct-1";
const ADMIN_INITIAL = "v02-admin-initial-distinct-1";
const NORMAL_NEXT = "v02-normal-next-distinct-2";
const ADMIN_NEXT = "v02-admin-next-distinct-2";
const ADMIN_RETRY = "v02-admin-retry-distinct-3";

async function waitForWaiter(blockerPid: number, sqlFragment: string): Promise<number> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const rows = await prisma.$queryRaw<Array<{ pid: number }>>`
      SELECT pid::int AS pid FROM pg_stat_activity
      WHERE wait_event_type = 'Lock'
        AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        AND query LIKE ${`%${sqlFragment}%`}
    `;
    if (rows.length > 0) return rows[0]!.pid;
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
  }
  throw Error(`No observed PostgreSQL lock edge for ${sqlFragment}`);
}

type HolderOutcome = { ok: boolean; error: unknown };

async function waitForHolderLock(acquired: Promise<void>, holder: Promise<HolderOutcome>): Promise<void> {
  // The lock-acquired signal never fires if the transaction fails before
  // calling held(). Observe transaction settlement as an independent terminal
  // event; otherwise a failed SQL statement hangs the fixture indefinitely.
  await Promise.race([
    acquired,
    holder.then((result) => {
      throw result.error ?? new Error("Holder settled before acquiring its required lock");
    })
  ]);
}

async function approvedAdminRecovery() {
  const owner = await createTestUser({ role: "ADMIN", password: NORMAL_INITIAL, label: "v02-different-secret-owner" });
  const approver = await createTestUser({ role: "ADMIN", label: "v02-different-secret-approver" });
  const now = new Date();
  await prisma.administrativeCredential.create({
    data: { userId: owner.id, passwordHash: await hashPassword(ADMIN_INITIAL), status: "ACTIVE" }
  });
  const { sessionId: ownerSessionId } = await seedAdminSessionWithElevation(owner.id, "ADMIN_CREDENTIAL_CHANGE", now);
  const { sessionId: approverSessionId } = await seedAdminSessionWithElevation(approver.id, "ACCOUNT_STATE_CHANGE", now);
  await requestAdministrativeAccountRecovery(owner.email, "pt-BR", now);
  const pendingMail = (await queuedEmails(owner.email)).filter((message) => message.kind === "ACCOUNT_RECOVERY").at(-1);
  assert.ok(pendingMail?.code);
  const pendingKey = requestKeyFromActionUrl(pendingMail.actionUrl);
  const pending = await getAccountRecoveryRequestId(pendingKey, now, "ADMIN");
  assert.ok(pending);
  await verifyAccountRecoveryEmail(pending.id, pendingKey, pendingMail.code, now, "ADMIN");
  await approveAccountRecovery({ id: approver.id, role: "ADMIN" }, approverSessionId, pending.id, now);
  const approvedMail = (await queuedEmails(owner.email)).filter((message) => message.kind === "ACCOUNT_RECOVERY").at(-1);
  const approvedKey = requestKeyFromActionUrl(approvedMail?.actionUrl);
  const approved = await getAccountRecoveryRequestId(approvedKey, now, "ADMIN");
  assert.equal(approved?.id, pending.id);
  return { owner, now, ownerSessionId, requestId: pending.id, requestKey: approvedKey };
}

async function storedPasswords(userId: string) {
  const [normal, administrative] = await Promise.all([
    prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { passwordHash: true } }),
    prisma.administrativeCredential.findUniqueOrThrow({ where: { userId }, select: { passwordHash: true, keyVersion: true } })
  ]);
  return { normal: normal.passwordHash ?? "", administrative };
}

async function recoveryAuditCount(requestId: string) {
  const rows = await prisma.auditLog.findMany({
    where: { eventType: "ACCOUNT_RECOVERY_CONSUMED", resource: "identity.recovery" },
    select: { metadata: true }
  });
  return rows.filter((row) => (row.metadata as { requestRef?: string } | null)?.requestRef === hashAuditIdentifier(requestId)).length;
}

test("V02: ADMIN change commits first, then blocked normal recovery commits a different secret", integrationOptions, async () => {
  const fixture = await approvedAdminRecovery();
  const { owner } = fixture;
  let unblock!: () => void;
  let held!: () => void;
  const gate = new Promise<void>((resolve) => { unblock = resolve; });
  const acquired = new Promise<void>((resolve) => { held = resolve; });
  let holderPid = 0;
  // Independent transaction holds only the credential; the genuine ADMIN
  // mutation obtains the User lock before waiting on this row.
  const holder = prisma.$transaction(async (tx) => {
    [{ pid: holderPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    await tx.$queryRaw`SELECT "userId" FROM "AdministrativeCredential" WHERE "userId" = ${owner.id} FOR UPDATE`;
    held();
    await gate;
  }, { timeout: 20_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );
  let adminChange: Promise<HolderOutcome> | undefined;
  let normalRecovery: Promise<{ ok: boolean; error: unknown }> | undefined;
  try {
    await waitForHolderLock(acquired, holder);
    adminChange = changeAdministrativePassword({ id: owner.id, role: "ADMIN" }, fixture.ownerSessionId, ADMIN_NEXT, fixture.now).then(
      () => ({ ok: true as const, error: null }),
      (error: unknown) => ({ ok: false as const, error })
    );
    const adminPid = await waitForWaiter(holderPid, 'FROM "AdministrativeCredential"');
    normalRecovery = consumeApprovedAccountRecovery(fixture.requestId, fixture.requestKey, NORMAL_NEXT, fixture.now, "ADMIN").then(
      () => ({ ok: true, error: null }),
      (error: unknown) => ({ ok: false, error })
    );
    await waitForWaiter(adminPid, 'FROM "User"');
  } finally {
    unblock();
    // A failed lock-observation assertion must never leave an in-flight
    // writer using the disposable database after the test returns.
    await Promise.allSettled([holder, adminChange, normalRecovery]);
  }
  assert.deepEqual(await holder, { ok: true, error: null });
  assert.deepEqual(await adminChange, { ok: true, error: null });
  assert.deepEqual(await normalRecovery, { ok: true, error: null });
  const passwords = await storedPasswords(owner.id);
  assert.equal(await verifyPassword(passwords.normal, NORMAL_NEXT), true);
  assert.equal(await verifyPassword(passwords.normal, ADMIN_NEXT), false);
  assert.equal(await verifyPassword(passwords.administrative.passwordHash, ADMIN_NEXT), true);
  assert.equal(await verifyPassword(passwords.administrative.passwordHash, NORMAL_NEXT), false);
  assert.equal(passwords.administrative.keyVersion, 2);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: fixture.requestId } })).status, "CONSUMED");
  assert.equal(await recoveryAuditCount(fixture.requestId), 1);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: owner.id, eventType: "ADMIN_CREDENTIAL_CHANGED" } }), 1);
});

test("V02: normal recovery wins User lock; aborted credential writer cannot bypass rejection or a fresh retry", integrationOptions, async () => {
  const fixture = await approvedAdminRecovery();
  const { owner } = fixture;
  const poisonHash = await hashPassword("v02-aborted-uncommitted-secret-4");
  let unblock!: () => void;
  let held!: () => void;
  const gate = new Promise<void>((resolve) => { unblock = resolve; });
  const acquired = new Promise<void>((resolve) => { held = resolve; });
  let holderPid = 0;
  const holder = prisma.$transaction(async (tx) => {
    [{ pid: holderPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    await tx.administrativeCredential.update({
      where: { userId: owner.id }, data: { passwordHash: poisonHash, keyVersion: { increment: 1 } }
    });
    held();
    await gate;
    throw Error("V02 deliberately rolled back the uncommitted credential writer");
  }, { timeout: 20_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );
  let recovery: Promise<HolderOutcome> | undefined;
  let adminChange: Promise<{ ok: boolean; error: unknown }> | undefined;
  try {
    await waitForHolderLock(acquired, holder);
    recovery = consumeApprovedAccountRecovery(fixture.requestId, fixture.requestKey, NORMAL_NEXT, fixture.now, "ADMIN").then(
      () => ({ ok: true as const, error: null }),
      (error: unknown) => ({ ok: false as const, error })
    );
    const recoveryPid = await waitForWaiter(holderPid, 'FROM "AdministrativeCredential"');
    adminChange = changeAdministrativePassword({ id: owner.id, role: "ADMIN" }, fixture.ownerSessionId, ADMIN_NEXT, fixture.now).then(
      () => ({ ok: true, error: null }),
      (error: unknown) => ({ ok: false, error })
    );
    await waitForWaiter(recoveryPid, 'FROM "User"');
  } finally {
    unblock();
    await Promise.allSettled([holder, recovery, adminChange]);
  }
  const rolledBack = await holder;
  assert.equal(rolledBack.ok, false);
  assert.match(String(rolledBack.error), /deliberately rolled back/);
  assert.deepEqual(await recovery, { ok: true, error: null });
  const rejectedAdmin = await adminChange;
  assert.equal(rejectedAdmin?.ok, false);
  assert.ok(rejectedAdmin?.error instanceof AdministrationMutationError,
    "the old session must fail authorization, not a transient database error");
  const beforeRetry = await storedPasswords(owner.id);
  assert.equal(await verifyPassword(beforeRetry.normal, NORMAL_NEXT), true);
  assert.equal(await verifyPassword(beforeRetry.administrative.passwordHash, ADMIN_INITIAL), true);
  assert.equal(await verifyPassword(beforeRetry.administrative.passwordHash, "v02-aborted-uncommitted-secret-4"), false);
  assert.equal(beforeRetry.administrative.keyVersion, 1);
  assert.equal(await recoveryAuditCount(fixture.requestId), 1);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: owner.id, eventType: "ADMIN_CREDENTIAL_CHANGED" } }), 0);

  // A rejected old-session attempt must not consume the right to perform
  // a legitimate ADMIN rotation with a fresh session and proof.
  const fresh = await seedAdminSessionWithElevation(owner.id, "ADMIN_CREDENTIAL_CHANGE", new Date());
  await changeAdministrativePassword({ id: owner.id, role: "ADMIN" }, fresh.sessionId, ADMIN_RETRY);
  const afterRetry = await storedPasswords(owner.id);
  assert.equal(await verifyPassword(afterRetry.normal, NORMAL_NEXT), true);
  assert.equal(await verifyPassword(afterRetry.administrative.passwordHash, ADMIN_RETRY), true);
  assert.equal(await verifyPassword(afterRetry.administrative.passwordHash, NORMAL_NEXT), false);
  assert.equal(afterRetry.administrative.keyVersion, 2);
  assert.equal(await recoveryAuditCount(fixture.requestId), 1);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: owner.id, eventType: "ADMIN_CREDENTIAL_CHANGED" } }), 1);
});

test("V02: failed PostgreSQL holder statement before held() aborts the wait and cleans up", integrationOptions, async () => {
  // Real SQL error before the holder can notify acquired. Previously await
  // acquired remained pending forever, outside the test's finally block.
  const acquired = new Promise<void>(() => {});
  let unblock!: () => void;
  const gate = new Promise<void>((resolve) => { unblock = resolve; });
  const holder = prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT "this_column_does_not_exist" FROM "User" LIMIT 1`;
    await gate;
  }, { timeout: 5_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await assert.rejects(
      Promise.race([
        waitForHolderLock(acquired, holder),
        new Promise<never>((_, reject) => {
          timeout = setTimeout(() => reject(Error("holder-acquisition fixture hung")), 3_000);
        })
      ]),
      (error: unknown) => !String(error).includes("fixture hung") && /does_not_exist|column/iu.test(String(error))
    );
  } finally {
    if (timeout) clearTimeout(timeout);
    unblock();
    await Promise.allSettled([holder]);
  }
  assert.equal((await holder).ok, false);
});

test("V02: genuine ADMIN change committed first forbids a matching normal recovery password", integrationOptions, async () => {
  const fixture = await approvedAdminRecovery();
  const { owner } = fixture;
  let held!: () => void;
  let unblock!: () => void;
  const acquired = new Promise<void>((resolve) => { held = resolve; });
  const gate = new Promise<void>((resolve) => { unblock = resolve; });
  let holderPid = 0;
  const holder = prisma.$transaction(async (tx) => {
    [{ pid: holderPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    await tx.$queryRaw`SELECT "userId" FROM "AdministrativeCredential" WHERE "userId" = ${owner.id} FOR UPDATE`;
    held();
    await gate;
  }, { timeout: 20_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );
  let adminChange: Promise<HolderOutcome> | undefined;
  let normalRecovery: Promise<HolderOutcome> | undefined;
  try {
    await waitForHolderLock(acquired, holder);
    // Both real operations attempt the SAME candidate. Serializing the ADMIN
    // commit first must force the normal recovery to re-read the current hash.
    adminChange = changeAdministrativePassword({ id: owner.id, role: "ADMIN" }, fixture.ownerSessionId, NORMAL_NEXT, fixture.now).then(
      () => ({ ok: true as const, error: null }),
      (error: unknown) => ({ ok: false as const, error })
    );
    const adminPid = await waitForWaiter(holderPid, 'FROM "AdministrativeCredential"');
    normalRecovery = consumeApprovedAccountRecovery(fixture.requestId, fixture.requestKey, NORMAL_NEXT, fixture.now, "ADMIN").then(
      () => ({ ok: true as const, error: null }),
      (error: unknown) => ({ ok: false as const, error })
    );
    await waitForWaiter(adminPid, 'FROM "User"');
  } finally {
    unblock();
    await Promise.allSettled([holder, adminChange, normalRecovery]);
  }
  assert.deepEqual(await holder, { ok: true, error: null });
  assert.deepEqual(await adminChange, { ok: true, error: null });
  const rejected = await normalRecovery;
  assert.equal(rejected?.ok, false);
  assert.ok(rejected?.error instanceof SecurityMutationError, "the matching password must fail the security boundary");
  const stored = await storedPasswords(owner.id);
  assert.equal(await verifyPassword(stored.normal, NORMAL_INITIAL), true);
  assert.equal(await verifyPassword(stored.normal, NORMAL_NEXT), false);
  assert.equal(await verifyPassword(stored.administrative.passwordHash, NORMAL_NEXT), true);
  assert.equal(stored.administrative.keyVersion, 2);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: fixture.requestId } })).status, "APPROVED");
  assert.equal(await recoveryAuditCount(fixture.requestId), 0);
  assert.equal(await prisma.auditLog.count({ where: { actorUserId: owner.id, eventType: "ADMIN_CREDENTIAL_CHANGED" } }), 1);
});
