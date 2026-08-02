-- BielOS account security verification: selectable second factor, device ceremony, and recovery state.
CREATE TYPE "SecondFactorMethod" AS ENUM ('EMAIL', 'TOTP');

ALTER TABLE "User" ADD COLUMN "secondFactorMethod" "SecondFactorMethod" NOT NULL DEFAULT 'EMAIL';
ALTER TABLE "TotpFactor" ADD COLUMN "lastUsedStep" INTEGER;
ALTER TABLE "DeviceChallenge" ADD COLUMN "requiresTotp" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "AccountRecoveryRequest" ADD COLUMN "requestKey" TEXT;
ALTER TABLE "AccountRecoveryRequest" ADD COLUMN "emailVerifiedAt" TIMESTAMP(3);
UPDATE "AccountRecoveryRequest" SET "requestKey" = md5("id") WHERE "requestKey" IS NULL;
ALTER TABLE "AccountRecoveryRequest" ALTER COLUMN "requestKey" SET NOT NULL;
CREATE UNIQUE INDEX "AccountRecoveryRequest_requestKey_key" ON "AccountRecoveryRequest"("requestKey");
