ALTER TABLE "EmailOutboxMessage"
  ADD COLUMN "processingLeaseExpiresAt" TIMESTAMP(3);

UPDATE "EmailOutboxMessage"
SET "processingLeaseExpiresAt" = "updatedAt"
WHERE "status" = 'PROCESSING';

CREATE INDEX "EmailOutboxMessage_status_processingLeaseExpiresAt_idx"
  ON "EmailOutboxMessage"("status", "processingLeaseExpiresAt");
