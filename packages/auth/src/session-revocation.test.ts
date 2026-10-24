import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { prisma, type Prisma } from "@virki/database";
import * as auth from "./index";

type RevokeOthers = (userId: string, currentSessionId: string) => Promise<number>;
const revokeOthers = (auth as Record<string, unknown>).revokeOtherAccountSessions as RevokeOthers;

test("single and bulk session revocation use User-first row locks before Session mutations", () => {
  const source = readFileSync(new URL("../../../apps/hub/src/app/account/security/actions.ts", import.meta.url), "utf8");
  const action = source.slice(source.indexOf("export async function revokeAccountSessionAction("), source.indexOf("export async function revokeOtherAccountSessionsAction("));
  const userLock = action.indexOf('FROM "User"');
  const sessionLock = action.indexOf('FROM "Session"');
  const writer = action.indexOf("transaction.session.updateMany");
  assert.ok(userLock >= 0 && sessionLock > userLock && writer > sessionLock, "User lock must always precede Session lock/mutation");
});

test("bulk revoke commits only other active rows and an audit event, then becomes idempotent", async () => {
  assert.equal(typeof revokeOthers, "function");
  const current = { id: "current", revokedAt: null as Date | null, expiresAt: new Date(Date.now() + 60_000) };
  const other = { id: "other", revokedAt: null as Date | null, expiresAt: new Date(Date.now() + 60_000) };
  const expired = { id: "expired", revokedAt: null as Date | null, expiresAt: new Date(Date.now() - 1) };
  let events: Array<Record<string, unknown>> = [];
  const client = prisma as unknown as { $transaction: typeof prisma.$transaction };
  const original = client.$transaction;
  client.$transaction = (async (callback: (transaction: Prisma.TransactionClient) => Promise<number>) => {
    const rows = [current, other, expired].map((row) => ({ ...row }));
    const pending: Array<Record<string, unknown>> = [];
    const transaction = {
      $queryRaw: async () => [{ id: current.id }],
      session: { updateMany: async ({ where, data }: { where: { userId: string; id: { not: string }; revokedAt: null; expiresAt: { gt: Date } }; data: { revokedAt: Date } }) => {
        assert.equal(where.userId, "user-a");
        assert.equal(where.id.not, current.id);
        let count = 0;
        for (const row of rows) if (row.id !== where.id.not && row.revokedAt === null && row.expiresAt > where.expiresAt.gt) { row.revokedAt = data.revokedAt; count++; }
        return { count };
      } },
      auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { pending.push(data); } }
    } as unknown as Prisma.TransactionClient;
    const count = await callback(transaction);
    [current, other, expired].forEach((row, index) => { row.revokedAt = rows[index]!.revokedAt; });
    events = [...events, ...pending];
    return count;
  }) as typeof prisma.$transaction;
  try {
    assert.equal(await revokeOthers("user-a", current.id), 1);
    assert.equal(current.revokedAt, null);
    assert.ok(other.revokedAt);
    assert.equal(expired.revokedAt, null);
    assert.equal(events.length, 1);
    assert.equal(events[0]?.actorRole, "USER");
    assert.equal(events[0]?.sessionRef, auth.hashAuditSessionReference(current.id));
    assert.equal((events[0]?.metadata as { revokedCount?: number })?.revokedCount, 1);
    assert.equal(await revokeOthers("user-a", current.id), 0);
    assert.equal(events.length, 1);
  } finally { client.$transaction = original; }
});

test("failed audit insertion aborts the revocation transaction", async () => {
  assert.equal(typeof revokeOthers, "function");
  let revoked = false;
  const client = prisma as unknown as { $transaction: typeof prisma.$transaction };
  const original = client.$transaction;
  client.$transaction = (async (callback: (transaction: Prisma.TransactionClient) => Promise<number>) => {
    let pending = false;
    const transaction = {
      $queryRaw: async () => [{ id: "current" }],
      session: { updateMany: async () => { pending = true; return { count: 1 }; } },
      auditLog: { create: async () => { throw new Error("audit unavailable"); } }
    } as unknown as Prisma.TransactionClient;
    const result = await callback(transaction);
    revoked = pending;
    return result;
  }) as typeof prisma.$transaction;
  try {
    await assert.rejects(revokeOthers("user-a", "current"), /audit unavailable/u);
    assert.equal(revoked, false);
  } finally { client.$transaction = original; }
});
