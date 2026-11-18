import assert from "node:assert/strict";
import { test } from "node:test";
import { prisma, type Prisma } from "@virki/database";
import { recoveryPasskeyBinding, recoveryTotpBinding, startMultiMethodRecovery } from "./recovery-methods";
import { hashEmailAddress } from "./security";

type RivalKind = "pending-passkey" | "pending-totp" | "approved" | "invitation" | "none";
type Scenario = { label: string; rival: RivalKind; invalidation?: "revoke" | "rotate"; creates: boolean; changedMailbox?: boolean };

const cases: Scenario[] = [
  { label: "revoked proven PASSKEY permits alternate recovery", rival: "pending-passkey", invalidation: "revoke", creates: true },
  { label: "rotated proven PASSKEY permits alternate recovery", rival: "pending-passkey", invalidation: "rotate", creates: true },
  { label: "rotated proven TOTP permits alternate recovery", rival: "pending-totp", invalidation: "rotate", creates: true },
  { label: "live proven PASSKEY still vetoes alternate recovery", rival: "pending-passkey", creates: false },
  { label: "live proven TOTP still vetoes alternate recovery", rival: "pending-totp", creates: false },
  { label: "APPROVED recovery is protected", rival: "approved", creates: false },
  { label: "APPROVED invitation is protected", rival: "invitation", creates: false },
  { label: "changed owner mailbox cannot accept stale original address", rival: "none", creates: false, changedMailbox: true }
];

for (const scenario of cases) {
  test(scenario.label, async (context) => {
    const original = "recovery-veto-liveness@integration.invalid";
    const owner = { id: "liveness-user", email: original, emailNormalized: original, role: "USER", isActive: true, accountStatus: "ACTIVE", displayName: "Owner", secondFactorMethod: "TOTP" };
    const now = new Date();
    const originalFactor = { id: "totp-old", userId: owner.id, secretCiphertext: "encrypted-original", keyVersion: 1, confirmedAt: now, lastUsedStep: 42, status: "ACTIVE" };
    const factor = { ...originalFactor };
    const originalCredential = { id: "credential-old", userId: owner.id, credentialId: "passkey-id", rpID: "portal.biel.dev.br", publicKey: Buffer.from("original-key"), revokedAt: null as Date | null };
    const credential = { ...originalCredential };
    if (scenario.rival === "pending-passkey") {
      if (scenario.invalidation === "revoke") credential.revokedAt = now;
      if (scenario.invalidation === "rotate") credential.publicKey = Buffer.from("rotated-key");
    } else if (scenario.rival === "pending-totp" && scenario.invalidation === "rotate") {
      factor.secretCiphertext = "encrypted-rotated";
    }
    const isPending = scenario.rival === "pending-passkey" || scenario.rival === "pending-totp";
    const rival = {
      id: "rival-recovery", userId: owner.id, purpose: scenario.rival === "invitation" ? "INVITATION" : "RECOVERY",
      status: isPending ? "PENDING" : "APPROVED", recoveryRole: scenario.rival === "invitation" ? null : "USER",
      recoveryBrowserHash: scenario.rival === "invitation" ? null : "browser-proof",
      emailAddressHash: hashEmailAddress(original), recoveryAdminReview: false, reviewedByUserId: null,
      recoveryProofs: scenario.rival === "pending-passkey" ? ["EMAIL", "PASSKEY"] : scenario.rival === "pending-totp" ? ["EMAIL", "TOTP"] : [],
      emailVerifiedAt: null,
      recoveryPasskeyVerifiedAt: scenario.rival === "pending-passkey" ? now : null,
      recoveryTotpVerifiedAt: scenario.rival === "pending-totp" ? now : null,
      recoveryPasskeyCredentialId: scenario.rival === "pending-passkey" ? originalCredential.id : null,
      recoveryPasskeyBindingHash: scenario.rival === "pending-passkey" ? recoveryPasskeyBinding(originalCredential) : null,
      recoveryTotpUsedStep: scenario.rival === "pending-totp" ? 42 : null,
      recoveryTotpBindingHash: scenario.rival === "pending-totp" ? recoveryTotpBinding(originalFactor) : null
    };
    const created: string[] = [];
    const transaction = {
      $queryRaw: async (literals: TemplateStringsArray) => literals.join("").includes('FROM "User"') ? [{ id: owner.id }] : [],
      loginRateLimit: { findUnique: async () => null, create: async () => ({}) },
      user: {
        count: async () => 1,
        findUnique: async () => ({ ...owner, email: scenario.changedMailbox ? "changed@integration.invalid" : original,
          emailNormalized: scenario.changedMailbox ? "changed@integration.invalid" : original })
      },
      totpFactor: { findUnique: async () => factor },
      passkeyCredential: { findMany: async () => credential.revokedAt ? [] : [credential] },
      accountRecoveryRequest: {
        findFirst: async ({ where, orderBy }: { where?: { status?: string | { in: string[] } }; orderBy?: { createdAt: string } }) => {
          if (orderBy) return { createdAt: new Date(now.getTime() - 61_000) };
          if (where?.status === "APPROVED") return !isPending && scenario.rival !== "none" ? { id: rival.id } : null;
          return scenario.rival === "none" ? null : { id: rival.id };
        },
        findMany: async () => isPending ? [rival] : [],
        create: async ({ data }: { data: { id: string } }) => { created.push(data.id); return { id: data.id }; }
      },
      auditLog: { create: async () => ({}) }
    } as unknown as Prisma.TransactionClient;
    const findUser = Object.getOwnPropertyDescriptor(prisma.user, "findUnique");
    const runTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
    assert.ok(findUser && runTransaction);
    const oldEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "test";
    Object.defineProperty(prisma.user, "findUnique", { ...findUser, value: async () => owner });
    Object.defineProperty(prisma, "$transaction", { ...runTransaction, value: async (callback: (tx: Prisma.TransactionClient) => Promise<unknown>) => callback(transaction) });
    context.after(() => {
      Object.defineProperty(prisma, "$transaction", runTransaction);
      Object.defineProperty(prisma.user, "findUnique", findUser);
      if (oldEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = oldEnv;
    });
    const attempt = await startMultiMethodRecovery(original, "USER", { proofs: ["TOTP"], adminReview: true }, "pt-BR", now);
    assert.deepEqual(created, scenario.creates ? [attempt.requestId] : []);
  });
}
