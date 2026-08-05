-- Add a bounded, server-authoritative remembered-browser grant.
ALTER TABLE "TrustedDevice" ADD COLUMN "rememberedUntil" TIMESTAMP(3);
ALTER TABLE "TrustedDevice" ADD COLUMN "strongVerifiedAt" TIMESTAMP(3);

ALTER TABLE "TrustedDevice" ADD CONSTRAINT "TrustedDevice_remembered_grant_consistency_check"
  CHECK (("rememberedUntil" IS NULL AND "strongVerifiedAt" IS NULL)
    OR ("status" = 'TRUSTED' AND "rememberedUntil" IS NOT NULL AND "strongVerifiedAt" IS NOT NULL));

CREATE INDEX "TrustedDevice_rememberedUntil_idx" ON "TrustedDevice"("rememberedUntil");
