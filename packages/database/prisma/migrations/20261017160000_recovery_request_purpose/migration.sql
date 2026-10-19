CREATE TYPE "RecoveryRequestPurpose" AS ENUM ('RECOVERY', 'INVITATION');

ALTER TABLE "AccountRecoveryRequest"
ADD COLUMN "purpose" "RecoveryRequestPurpose" NOT NULL DEFAULT 'RECOVERY';
