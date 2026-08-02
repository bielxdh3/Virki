-- Opaque UI references for personal session and trusted-device actions.
ALTER TABLE "Session" ADD COLUMN "sessionKey" TEXT;
UPDATE "Session" SET "sessionKey" = md5("id") WHERE "sessionKey" IS NULL;
ALTER TABLE "Session" ALTER COLUMN "sessionKey" SET NOT NULL;
CREATE UNIQUE INDEX "Session_sessionKey_key" ON "Session"("sessionKey");

ALTER TABLE "TrustedDevice" ADD COLUMN "deviceKey" TEXT;
UPDATE "TrustedDevice" SET "deviceKey" = md5("id") WHERE "deviceKey" IS NULL;
ALTER TABLE "TrustedDevice" ALTER COLUMN "deviceKey" SET NOT NULL;
CREATE UNIQUE INDEX "TrustedDevice_deviceKey_key" ON "TrustedDevice"("deviceKey");
