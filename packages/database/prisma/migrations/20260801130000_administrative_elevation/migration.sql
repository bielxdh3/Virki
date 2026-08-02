-- BielOS administrative credential and session-bound elevation ceremony.
ALTER TABLE "SecurityElevation" ADD COLUMN "requestKey" TEXT;
UPDATE "SecurityElevation" SET "requestKey" = md5("id") WHERE "requestKey" IS NULL;
ALTER TABLE "SecurityElevation" ALTER COLUMN "requestKey" SET NOT NULL;
CREATE UNIQUE INDEX "SecurityElevation_requestKey_key" ON "SecurityElevation"("requestKey");
