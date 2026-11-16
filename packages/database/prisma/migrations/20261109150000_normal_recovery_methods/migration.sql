-- New USER/ADMIN normal-password recovery policy. Legacy and invitation rows remain
-- on the existing email plus independent administrative-review contract.
ALTER TABLE "AccountRecoveryRequest"
  ADD COLUMN "recoveryProofs" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN "recoveryRole" "UserRole",
  ADD COLUMN "recoveryAdminReview" BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN "recoveryBrowserHash" TEXT,
  ADD COLUMN "recoveryPasskeyVerifiedAt" TIMESTAMP(3),
  ADD COLUMN "recoveryPasskeyCredentialId" TEXT,
  ADD COLUMN "recoveryPasskeyBindingHash" TEXT,
  ADD COLUMN "recoveryTotpVerifiedAt" TIMESTAMP(3),
  ADD COLUMN "recoveryTotpBindingHash" TEXT,
  ADD COLUMN "recoveryTotpUsedStep" INTEGER,
  ADD COLUMN "recoveryComment" TEXT;
