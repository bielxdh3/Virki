import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import { recoveryPasskeyBinding, recoveryTotpBinding, startMultiMethodRecovery } from "./recovery-methods";
import { hashEmailAddress, hashRecoveryRequestKey, hashSecurityCode } from "./security";

after(() => prisma.$disconnect());

type Factor = "PASSKEY" | "TOTP";
type Mutation = "unchanged" | "revoked" | "rotated";
type Scenario = {
  label: string;
  factor: Factor;
  mutation: Mutation;
  approved?: boolean;
  invitation?: boolean;
  shouldCreate: boolean;
};

// These physical database cases test Prisma predicates and the serialized
// account lock. The prior cryptographic ceremonies are covered separately
// by the signed WebAuthn and real TOTP recovery integration tests.
const cases: Scenario[] = [
  { label: "live PENDING PASSKEY stays protected", factor: "PASSKEY", mutation: "unchanged", shouldCreate: false },
  { label: "revoked PENDING PASSKEY permits another recovery", factor: "PASSKEY", mutation: "revoked", shouldCreate: true },
  { label: "rotated PENDING PASSKEY permits another recovery", factor: "PASSKEY", mutation: "rotated", shouldCreate: true },
  { label: "live PENDING TOTP stays protected", factor: "TOTP", mutation: "unchanged", shouldCreate: false },
  { label: "revoked PENDING TOTP permits another recovery", factor: "TOTP", mutation: "revoked", shouldCreate: true },
  { label: "rotated PENDING TOTP permits another recovery", factor: "TOTP", mutation: "rotated", shouldCreate: true },
  { label: "APPROVED recovery remains protected after PASSKEY revocation", factor: "PASSKEY", mutation: "revoked", approved: true, shouldCreate: false },
  { label: "APPROVED invitation remains protected", factor: "TOTP", mutation: "unchanged", invitation: true, shouldCreate: false }
];

for (const scenario of cases) {
  test(`real PostgreSQL: ${scenario.label}`, integrationOptions, async (t) => {
    const priorPasskeyFlag = process.env.VIRKI_PASSKEYS_ENABLED;
    if (scenario.factor === "TOTP" && scenario.mutation === "revoked") {
      process.env.VIRKI_PASSKEYS_ENABLED = "true";
      t.after(() => {
        if (priorPasskeyFlag === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED;
        else process.env.VIRKI_PASSKEYS_ENABLED = priorPasskeyFlag;
      });
    }
    const owner = await createTestUser({ label: "live-recovery-veto" });
    await createTestUser({ role: "ADMIN", label: "live-recovery-reviewer" });
    const time = new Date();
    const originalTotp = await prisma.totpFactor.create({ data: {
      userId: owner.id, secretCiphertext: "physical-original-factor-ciphertext",
      keyVersion: 1, status: "ACTIVE", confirmedAt: time, lastUsedStep: 42
    } });
    await prisma.user.update({ where: { id: owner.id }, data: { secondFactorMethod: "TOTP" } });
    const credential = await prisma.passkeyCredential.create({ data: {
      userId: owner.id, credentialId: randomBytes(32).toString("base64url"),
      rpID: "portal.biel.dev.br", publicKey: Buffer.from("physical-original-public-key"),
      backupEligible: false, backupState: false, name: "Physical liveness fixture"
    } });
    const approved = scenario.approved || scenario.invitation;
    const originalRequest = await prisma.accountRecoveryRequest.create({ data: {
      userId: owner.id,
      requestKeyHash: hashRecoveryRequestKey(randomBytes(24).toString("base64url")),
      emailAddressHash: hashEmailAddress(owner.email),
      emailChallengeHash: hashSecurityCode("123456"),
      purpose: scenario.invitation ? "INVITATION" : "RECOVERY",
      recoveryRole: scenario.invitation ? null : "USER",
      recoveryProofs: scenario.invitation ? [] : ["EMAIL", scenario.factor],
      recoveryAdminReview: false,
      recoveryBrowserHash: scenario.invitation ? null : randomBytes(32).toString("hex"),
      status: approved ? "APPROVED" : "PENDING",
      createdAt: new Date(time.getTime() - 61_000),
      expiresAt: new Date(time.getTime() + 30 * 60_000),
      ...(scenario.factor === "PASSKEY" && !scenario.invitation ? {
        recoveryPasskeyVerifiedAt: time,
        recoveryPasskeyCredentialId: credential.id,
        recoveryPasskeyBindingHash: recoveryPasskeyBinding(credential)
      } : {}),
      ...(scenario.factor === "TOTP" && !scenario.invitation ? {
        recoveryTotpVerifiedAt: time,
        recoveryTotpBindingHash: recoveryTotpBinding(originalTotp),
        recoveryTotpUsedStep: 42
      } : {})
    } });
    if (scenario.factor === "PASSKEY") {
      if (scenario.mutation === "revoked") {
        await prisma.passkeyCredential.update({ where: { id: credential.id }, data: { revokedAt: new Date() } });
      } else if (scenario.mutation === "rotated") {
        await prisma.passkeyCredential.update({ where: { id: credential.id }, data: { publicKey: Buffer.from("physical-rotated-key") } });
      }
    } else if (scenario.mutation === "revoked") {
      await prisma.totpFactor.update({ where: { userId: owner.id }, data: { status: "REVOKED" } });
    } else if (scenario.mutation === "rotated") {
      await prisma.totpFactor.update({ where: { userId: owner.id }, data: {
        secretCiphertext: "physical-rotated-totp", keyVersion: 2, confirmedAt: new Date()
      } });
    }
    // A revoked TOTP switches to a still-active PASSKEY plus independent
    // reviewer. Other scenarios use current TOTP plus independent reviewer.
    const alternative = scenario.factor === "TOTP" && scenario.mutation === "revoked"
      ? { proofs: ["PASSKEY" as const], adminReview: true }
      : { proofs: ["TOTP" as const], adminReview: true };
    const fresh = await startMultiMethodRecovery(owner.email, "USER",
      alternative, "pt-BR", new Date(), `2001:db8::${randomUUID().replaceAll("-", "").slice(0, 4)}`);
    const persisted = await prisma.accountRecoveryRequest.findMany({
      where: { userId: owner.id }, select: { id: true, status: true }, orderBy: { createdAt: "asc" }
    });
    assert.equal(persisted.some(row => row.id === fresh.requestId), scenario.shouldCreate,
      "a newly returned browser request must map to a real row only when the previous proof is no longer live");
    assert.equal(persisted.length, scenario.shouldCreate ? 2 : 1);
    assert.equal(persisted.find(row => row.id === originalRequest.id)?.status, approved ? "APPROVED" : "PENDING",
      "a new request must not silently expire an existing approved or pending request");
  });
}
