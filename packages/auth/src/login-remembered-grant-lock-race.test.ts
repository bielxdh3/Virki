import assert from "node:assert/strict";
import test from "node:test";
import { prisma } from "@virki/database";
import { generateDeviceToken, startLoginCeremony } from "./security";

test("USER remembered grant expired during User lock cannot mint a password-only session", async (context) => {
  const original = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(original);
  context.after(() => Object.defineProperty(prisma, "$transaction", original));

  const requestAt = new Date("2026-11-17T12:00:00.000Z");
  const expiresAt = new Date(requestAt.getTime() + 1_000);
  const verifiedAt = new Date(requestAt.getTime() - 60_000);
  let afterLock = requestAt;
  let mintedPasswordOnlySession = 0;
  const cookie = generateDeviceToken();
  const transaction = {
    user: { findUnique: async () => ({
      id: "user-grant-expired-at-lock", email: "user@example.invalid", emailNormalized: "user@example.invalid",
      displayName: "Test", emailVerifiedAt: verifiedAt, role: "USER", isActive: true,
      accountStatus: "ACTIVE", secondFactorMethod: "TOTP", totpFactor: { status: "ACTIVE" }
    }) },
    $queryRaw: async () => {
      // Simulates the real FOR UPDATE acquisition completing after the grant's deadline.
      afterLock = new Date(expiresAt.getTime() + 1_000);
      return [{ id: "user-grant-expired-at-lock" }];
    },
    trustedDevice: {
      updateMany: async () => ({ count: 0 }),
      findUnique: async () => ({ status: "TRUSTED", revokedAt: null, rememberedUntil: expiresAt, strongVerifiedAt: verifiedAt })
    },
    deviceChallenge: {
      findFirst: async () => ({ ceremonyId: "fresh-totp-required" }),
      updateMany: async () => ({ count: 0 })
    },
    session: { create: async () => {
      mintedPasswordOnlySession++;
      return { id: "unexpected-weak-session" };
    } }
  };
  Object.defineProperty(prisma, "$transaction", { ...original, value: async (run: (tx: never) => Promise<unknown>) => run(transaction as never) });

  const result = await startLoginCeremony(
    "user-grant-expired-at-lock", cookie, "pt-BR", requestAt,
    false, "USER", undefined, undefined, undefined, () => afterLock
  );
  assert.equal(result.kind, "CEREMONY", "the grant must be checked at the live post-lock clock, not the pre-lock request clock");
  assert.equal(mintedPasswordOnlySession, 0, "no password-only session may be minted after remembered-grant expiry");
});
