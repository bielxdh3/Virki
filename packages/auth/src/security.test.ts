import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { prisma } from "@bielos/database";
import {
  createTotpSecret,
  canApproveAccountRecovery,
  consumeApprovedAccountRecovery,
  decryptTotpSecret,
  encryptTotpSecret,
  getLoginCeremonyFailureStage,
  getApprovedAccountRecoveryExpiry,
  getPendingAccountRecoveryQueueWhere,
  hashDeviceToken,
  hashRecoveryCode,
  hashSecurityCode,
  isAccountRecoveryEligible,
  isPublicAccountRecoveryEligible,
  LoginCeremonyStartError,
  lockActiveLoginAccountInTransaction,
  lockActiveRecoveryAccountInTransaction,
  lockAndExpireSiblingAccountRecoveriesInTransaction,
  revokeUserAuthenticationProofsInTransaction,
  verifySecurityCode,
  verifyTotpCode
} from "./security";

test("login ceremony diagnostics expose only fixed failure stages", () => {
  assert.equal(getLoginCeremonyFailureStage(new LoginCeremonyStartError("outbox-enqueue")), "outbox-enqueue");
  assert.equal(getLoginCeremonyFailureStage(new Error("private database detail")), undefined);
});

test("TOTP secrets are encrypted and never returned from ciphertext", () => {
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret, { NODE_ENV: "test" });
  assert.notEqual(encrypted, secret);
  assert.equal(decryptTotpSecret(encrypted, { NODE_ENV: "test" }), secret);
  assert.match(hashDeviceToken("opaque-device-token"), /^[a-f0-9]{64}$/);
});

test("TOTP confirmation accepts the RFC vector and rejects same-window replay", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const now = new Date(0);
  assert.equal(verifyTotpCode(secret, "282760", now, null), 0);
  assert.equal(verifyTotpCode(secret, "282760", now, 0), null);
  assert.equal(verifyTotpCode(secret, "000000", now, null), null);
});

test("short security codes use a keyed versioned digest while existing recovery codes remain compatible", () => {
  const env = { NODE_ENV: "test" };
  const stored = hashSecurityCode("123456", env);
  assert.match(stored, /^h2:[a-f0-9]{64}$/u);
  assert.equal(verifySecurityCode("123456", stored, env), true);
  assert.equal(verifySecurityCode("654321", stored, env), false);
  assert.equal(verifySecurityCode("123456", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", env), true);
  assert.equal(hashRecoveryCode("ab-cd"), hashRecoveryCode("AB CD"));
});

test("administrator recovery queue excludes requests at or past expiry", () => {
  const now = new Date("2026-10-02T12:00:00.000Z");

  assert.deepEqual(getPendingAccountRecoveryQueueWhere(now), {
    status: "PENDING",
    emailVerifiedAt: { not: null },
    expiresAt: { gt: now },
    user: { role: { in: ["USER", "ADMIN"] }, isActive: true, accountStatus: "ACTIVE" }
  });
  assert.deepEqual(getPendingAccountRecoveryQueueWhere(now, "admin-1"), {
    status: "PENDING",
    emailVerifiedAt: { not: null },
    expiresAt: { gt: now },
    user: { role: { in: ["USER", "ADMIN"] }, isActive: true, accountStatus: "ACTIVE", id: { not: "admin-1" } }
  });
});

test("recovery role policy isolates portal requests and requires a different active Admin to approve", () => {
  const activeUser = { id: "user-1", role: "USER", isActive: true, accountStatus: "ACTIVE" };
  const activeAdmin = { id: "admin-1", role: "ADMIN", isActive: true, accountStatus: "ACTIVE" };
  const reviewer = { id: "admin-2", role: "ADMIN" };

  assert.equal(isPublicAccountRecoveryEligible(activeUser), true);
  assert.equal(isPublicAccountRecoveryEligible(activeAdmin), false);
  assert.equal(isAccountRecoveryEligible(activeAdmin, "ADMIN"), true);
  assert.equal(isAccountRecoveryEligible(activeUser, "ADMIN"), false);
  assert.equal(isPublicAccountRecoveryEligible({ ...activeUser, isActive: false }), false);
  assert.equal(isPublicAccountRecoveryEligible({ ...activeUser, accountStatus: "SUSPENDED" }), false);
  assert.equal(canApproveAccountRecovery(reviewer, activeUser), true);
  assert.equal(canApproveAccountRecovery(reviewer, activeAdmin), true);
  assert.equal(canApproveAccountRecovery({ id: activeUser.id, role: "ADMIN" }, activeUser), false);
  assert.equal(canApproveAccountRecovery({ id: activeAdmin.id, role: "ADMIN" }, activeAdmin), false);
  assert.equal(canApproveAccountRecovery(reviewer, { ...activeAdmin, isActive: false }), false);
});

test("approved account recovery gets a fresh completion window", () => {
  const approvedAt = new Date("2026-10-02T12:00:00.000Z");

  assert.equal(getApprovedAccountRecoveryExpiry(approvedAt).toISOString(), "2026-10-02T12:30:00.000Z");
});

test("recovery state transitions serialize on the active account row", async () => {
  let query = "";
  let values: unknown[] = [];
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray, ...parameters: unknown[]) => {
      query = strings.join("?");
      values = parameters;
      return [{ id: "user-a" }];
    }
  } as never;

  assert.equal(await lockActiveRecoveryAccountInTransaction(transaction, "user-a"), true);
  assert.match(query, /"role" = \?[\s\S]*"isActive" = TRUE[\s\S]*"accountStatus" = 'ACTIVE'[\s\S]*FOR UPDATE/u);
  assert.deepEqual(values, ["user-a", "USER"]);
  values = [];
  await lockActiveRecoveryAccountInTransaction(transaction, "admin-a", "ADMIN");
  assert.deepEqual(values, ["admin-a", "ADMIN"]);
});

test("approved password recovery changes the password and revokes access while preserving TOTP and recovery codes", async (context) => {
  type MutationArgs = { data?: Record<string, unknown> };
  const userId = "user-recovery-1";
  const requestId = "recovery-request-1";
  const requestKey = "R".repeat(32);
  const email = "recovery-user@example.test";
  const emailNormalized = email.toLowerCase();
  const now = new Date("2026-10-05T12:00:00.000Z");
  const totpFactor = { id: "totp-factor-1", userId, status: "ACTIVE", secretCiphertext: "encrypted-test-factor", keyVersion: 1, lastUsedStep: 123 };
  const recoveryCodes = [
    { id: "recovery-code-1", userId, codeHash: "recovery-hash-1", usedAt: null },
    { id: "recovery-code-2", userId, codeHash: "recovery-hash-2", usedAt: null }
  ];
  const user = {
    email,
    emailNormalized,
    displayName: "Recovery user",
    role: "USER",
    isActive: true,
    accountStatus: "ACTIVE",
    secondFactorMethod: "TOTP",
    totpFactor,
    recoveryCodes
  };
  const request = {
    id: requestId,
    requestKeyHash: createHash("sha256").update(requestKey, "utf8").digest("hex"),
    userId,
    emailAddressHash: createHash("sha256").update(emailNormalized, "utf8").digest("hex"),
    status: "APPROVED",
    expiresAt: new Date(now.getTime() + 60_000),
    user
  };
  const mfaOperations: string[] = [];
  const revocations = { sessions: 0, elevations: 0, devices: 0, challenges: 0 };
  let requestStatus = "APPROVED";
  let passwordHash = "old-password-hash";
  let userUpdateData: Record<string, unknown> | undefined;
  let auditEvent = "";

  const transaction = {
    $queryRaw: async (query: TemplateStringsArray) => query.join("").includes('FROM "User"') ? [{ id: userId }] : [],
    loginRateLimit: {
      findUnique: async () => null,
      create: async () => ({})
    },
    accountRecoveryRequest: {
      findUnique: async () => ({ ...request, status: requestStatus }),
      updateMany: async ({ data }: MutationArgs) => {
        if (data?.status === "CONSUMED") requestStatus = "CONSUMED";
        return { count: 1 };
      }
    },
    user: {
      update: async ({ data }: MutationArgs) => {
        userUpdateData = data;
        passwordHash = String(data?.passwordHash ?? "");
        return { id: userId };
      }
    },
    emailOutboxMessage: { upsert: async () => ({ id: "outbox-message-1" }) },
    session: {
      updateMany: async () => { revocations.sessions += 1; return { count: 1 }; }
    },
    securityElevation: {
      updateMany: async () => { revocations.elevations += 1; return { count: 1 }; }
    },
    trustedDevice: {
      updateMany: async () => { revocations.devices += 1; return { count: 1 }; }
    },
    deviceChallenge: {
      updateMany: async () => { revocations.challenges += 1; return { count: 1 }; }
    },
    totpFactor: {
      updateMany: async () => { mfaOperations.push("totp-update"); return { count: 1 }; },
      deleteMany: async () => { mfaOperations.push("totp-delete"); return { count: 1 }; }
    },
    recoveryCode: {
      updateMany: async () => { mfaOperations.push("recovery-code-update"); return { count: 1 }; },
      deleteMany: async () => { mfaOperations.push("recovery-code-delete"); return { count: 1 }; }
    },
    auditLog: {
      create: async ({ data }: MutationArgs) => {
        auditEvent = String(data?.eventType ?? "");
        return { id: "audit-entry-1" };
      }
    }
  };

  const recoveryRequestDelegate = prisma.accountRecoveryRequest;
  const originalFindUnique = Object.getOwnPropertyDescriptor(recoveryRequestDelegate, "findUnique");
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalFindUnique && originalTransaction);
  Object.defineProperty(recoveryRequestDelegate, "findUnique", { ...originalFindUnique, value: async () => request });
  Object.defineProperty(prisma, "$transaction", {
    ...originalTransaction,
    value: async (operation: (value: never) => Promise<unknown>) => operation(transaction as never)
  });
  context.after(() => {
    Object.defineProperty(recoveryRequestDelegate, "findUnique", originalFindUnique);
    Object.defineProperty(prisma, "$transaction", originalTransaction);
  });

  await consumeApprovedAccountRecovery(requestId, requestKey, "new password for recovery", now);

  assert.equal(requestStatus, "CONSUMED");
  assert.notEqual(passwordHash, "old-password-hash");
  assert.deepEqual(Object.keys(userUpdateData ?? {}).sort(), ["emailVerifiedAt", "passwordHash"]);
  assert.equal(userUpdateData?.emailVerifiedAt, now);
  assert.deepEqual(revocations, { sessions: 1, elevations: 1, devices: 1, challenges: 1 });
  assert.deepEqual(mfaOperations, []);
  assert.equal(totpFactor.status, "ACTIVE");
  assert.equal(user.secondFactorMethod, "TOTP");
  assert.deepEqual(recoveryCodes, [
    { id: "recovery-code-1", userId, codeHash: "recovery-hash-1", usedAt: null },
    { id: "recovery-code-2", userId, codeHash: "recovery-hash-2", usedAt: null }
  ]);
  assert.equal(auditEvent, "ACCOUNT_RECOVERY_CONSUMED");
});

test("login verification locks the account under the role allowed by its current surface", async () => {
  let query = "";
  let values: unknown[] = [];
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray, ...parameters: unknown[]) => {
      query = strings.join("?");
      values = parameters;
      return [{ id: "admin-a" }];
    }
  } as never;

  assert.equal(await lockActiveLoginAccountInTransaction(transaction, "admin-a", "ADMIN"), true);
  assert.match(query, /"role" = \?[\s\S]*"isActive" = TRUE[\s\S]*"accountStatus" = 'ACTIVE'[\s\S]*FOR UPDATE/u);
  assert.deepEqual(values, ["admin-a", "ADMIN"]);
  assert.equal(await lockActiveLoginAccountInTransaction(transaction, "user-a", "USER"), true);
  assert.deepEqual(values, ["user-a", "USER"]);
});

test("recovery completion locks per account and expires every pending or approved sibling", async () => {
  const operations: string[] = [];
  const requests = [
    { id: "current", userId: "user-a", status: "APPROVED" },
    { id: "pending", userId: "user-a", status: "PENDING" },
    { id: "approved", userId: "user-a", status: "APPROVED" },
    { id: "consumed", userId: "user-a", status: "CONSUMED" },
    { id: "other-user", userId: "user-b", status: "PENDING" }
  ];
  const transaction = {
    $queryRaw: async () => { operations.push("lock"); return []; },
    accountRecoveryRequest: {
      updateMany: async ({ where, data }: { where: { userId: string; id: { not: string }; status: { in: string[] } }; data: { status: string } }) => {
        operations.push("invalidate");
        let count = 0;
        for (const request of requests) {
          if (request.userId === where.userId && request.id !== where.id.not && where.status.in.includes(request.status)) {
            request.status = data.status;
            count += 1;
          }
        }
        return { count };
      }
    }
  } as never;

  await lockAndExpireSiblingAccountRecoveriesInTransaction(transaction, "user-a", "current");

  assert.deepEqual(operations, ["lock", "lock", "invalidate"]);
  assert.deepEqual(requests.map(({ id, status }) => [id, status]), [
    ["current", "APPROVED"],
    ["pending", "EXPIRED"],
    ["approved", "EXPIRED"],
    ["consumed", "CONSUMED"],
    ["other-user", "PENDING"]
  ]);
});

test("account deactivation revokes remembered devices and active login challenges", async () => {
  const now = new Date("2026-10-02T12:00:00.000Z");
  const devices = [
    { userId: "user-a", status: "TRUSTED", revokedAt: null as Date | null, rememberedUntil: new Date("2026-10-09T12:00:00.000Z") as Date | null, strongVerifiedAt: new Date("2026-10-02T11:00:00.000Z") as Date | null },
    { userId: "user-a", status: "REVOKED", revokedAt: now, rememberedUntil: null, strongVerifiedAt: null },
    { userId: "user-b", status: "TRUSTED", revokedAt: null, rememberedUntil: new Date("2026-10-09T12:00:00.000Z"), strongVerifiedAt: new Date("2026-10-02T11:00:00.000Z") }
  ];
  const challenges = [
    { userId: "user-a", status: "PENDING" },
    { userId: "user-a", status: "VERIFIED" },
    { userId: "user-a", status: "EXPIRED" },
    { userId: "user-b", status: "PENDING" }
  ];
  let expiredRecoveries: unknown;
  const transaction = {
    trustedDevice: {
      updateMany: async ({ where, data }: { where: { userId: string; status: string }; data: { status: string; revokedAt: Date; rememberedUntil: null; strongVerifiedAt: null } }) => {
        let count = 0;
        for (const device of devices) {
          if (device.userId === where.userId && device.status === where.status) {
            Object.assign(device, data);
            count += 1;
          }
        }
        return { count };
      }
    },
    deviceChallenge: {
      updateMany: async ({ where, data }: { where: { userId: string; status: { in: string[] } }; data: { status: string } }) => {
        for (const challenge of challenges) {
          if (challenge.userId === where.userId && where.status.in.includes(challenge.status)) challenge.status = data.status;
        }
        return { count: 0 };
      }
    },
    accountRecoveryRequest: {
      updateMany: async (args: unknown) => { expiredRecoveries = args; return { count: 2 }; }
    }
  } as never;

  await revokeUserAuthenticationProofsInTransaction(transaction, "user-a", now);

  assert.deepEqual(devices.map((device) => [device.status, device.revokedAt, device.rememberedUntil, device.strongVerifiedAt]), [
    ["REVOKED", now, null, null],
    ["REVOKED", now, null, null],
    ["TRUSTED", null, new Date("2026-10-09T12:00:00.000Z"), new Date("2026-10-02T11:00:00.000Z")]
  ]);
  assert.deepEqual(challenges.map(({ userId, status }) => [userId, status]), [
    ["user-a", "REVOKED"],
    ["user-a", "REVOKED"],
    ["user-a", "EXPIRED"],
    ["user-b", "PENDING"]
  ]);
  assert.deepEqual(expiredRecoveries, {
    where: { userId: "user-a", status: { in: ["PENDING", "APPROVED"] } },
    data: { status: "EXPIRED" }
  });
});
