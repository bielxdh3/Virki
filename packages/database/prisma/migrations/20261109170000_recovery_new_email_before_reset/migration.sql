-- Keep existing factors until a replacement mailbox is verified within the
-- same browser-bound, independently proven account-recovery request.
ALTER TABLE "AccountRecoveryRequest"
  ADD COLUMN "recoveryNewEmail" TEXT,
  ADD COLUMN "recoveryNewEmailChallengeHash" TEXT,
  ADD COLUMN "recoveryNewEmailExpiresAt" TIMESTAMP(3),
  ADD COLUMN "recoveryNewEmailVerifiedAt" TIMESTAMP(3);
