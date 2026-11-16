-- Reserve an SMTP Message-ID in the same transaction that claims an attempt.
-- A crashed worker can thereby preserve the original header on lease reclaim
-- even when the configured sending domain changes between attempts.
ALTER TABLE "EmailOutboxMessage"
  ADD COLUMN "pendingSmtpHeaderMessageId" VARCHAR(255);
