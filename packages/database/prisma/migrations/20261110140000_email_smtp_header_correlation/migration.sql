-- Identifier for correlating the internal outbox attempt with an inbox
-- Message-ID header. This is not proof of delivery to the recipient.
ALTER TABLE "EmailDeliveryAttempt"
  ADD COLUMN "smtpHeaderMessageId" VARCHAR(255);
