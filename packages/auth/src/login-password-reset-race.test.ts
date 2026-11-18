import assert from "node:assert/strict";
import test from "node:test";
import { prisma } from "@virki/database";
import { hashPassword } from "./index";
import { LoginCeremonyStartError, startLoginCeremony } from "./security";

test("ADMIN login ceremony rechecks the current password after acquiring the account lock", async (context) => {
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalTransaction);
  context.after(() => Object.defineProperty(prisma, "$transaction", originalTransaction));

  const userId = "current-admin-id";
  const oldPassword = "previous-normal-admin-password";
  const replacementHash = await hashPassword("new-normal-admin-password");
  let reachedDeviceMutation = false;
  const transaction = {
    user: {
      findUnique: async (query: { select: { passwordHash?: true } }) => query.select.passwordHash
        ? { passwordHash: replacementHash }
        : { id: userId, email: "admin@example.invalid", emailNormalized: "admin@example.invalid", emailVerifiedAt: new Date(), displayName: "Admin", role: "ADMIN", isActive: true, accountStatus: "ACTIVE", secondFactorMethod: "EMAIL", totpFactor: null }
    },
    $queryRaw: async () => [{ id: userId }],
    trustedDevice: { updateMany: async () => { reachedDeviceMutation = true; throw new Error("stale password reached device state"); } }
  };
  Object.defineProperty(prisma, "$transaction", {
    ...originalTransaction,
    value: async (operation: (tx: never) => Promise<unknown>) => operation(transaction as never)
  });

  await assert.rejects(
    startLoginCeremony(userId, undefined, "pt-BR", new Date(), false, "ADMIN", undefined, "REGISTERED", oldPassword),
    (error: unknown) => error instanceof LoginCeremonyStartError && error.stage === "account-password-recheck",
    "the old password must fail at the live hash check before proof creation"
  );
  assert.equal(reachedDeviceMutation, false, "a stale password cannot mutate device state or mint a challenge");
});
