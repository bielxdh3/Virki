ALTER TABLE "AccountApplication" ADD COLUMN "abuseIdentifierHash" TEXT;
ALTER TABLE "ApplicationModuleDecision" ADD COLUMN "dedupeKey" TEXT NOT NULL DEFAULT '';
UPDATE "ApplicationModuleDecision" SET "dedupeKey" = md5("id") WHERE "dedupeKey" = '';
ALTER TABLE "ApplicationModuleDecision" ALTER COLUMN "dedupeKey" DROP DEFAULT;

CREATE UNIQUE INDEX "ApplicationModuleDecision_dedupeKey_key" ON "ApplicationModuleDecision"("dedupeKey");
CREATE INDEX "AccountApplication_abuseIdentifierHash_idx" ON "AccountApplication"("abuseIdentifierHash");
