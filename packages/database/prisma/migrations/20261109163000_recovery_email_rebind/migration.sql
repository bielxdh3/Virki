-- Additive post-recovery email ownership proof. No existing identities change.
ALTER TYPE "EmailMessageKind" ADD VALUE IF NOT EXISTS 'RECOVERY_EMAIL_REBIND';
ALTER TYPE "EmailMessageKind" ADD VALUE IF NOT EXISTS 'RECOVERY_EMAIL_REBIND_NOTICE';

-- One-to-one provenance for the short-lived session minted by a verified
-- recovery. PostgreSQL clock timestamps need not equal Node's session time.
ALTER TABLE "AccountRecoveryRequest" ADD COLUMN "bootstrapSessionId" TEXT;
CREATE UNIQUE INDEX "AccountRecoveryRequest_bootstrapSessionId_key"
  ON "AccountRecoveryRequest"("bootstrapSessionId");
ALTER TABLE "AccountRecoveryRequest" ADD CONSTRAINT "AccountRecoveryRequest_bootstrapSessionId_fkey"
  FOREIGN KEY ("bootstrapSessionId") REFERENCES "Session"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE "RecoveryEmailRebind" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "sessionId" TEXT NOT NULL,
  "role" "UserRole" NOT NULL,
  "oldEmailHash" TEXT NOT NULL,
  "newEmail" TEXT NOT NULL,
  "codeHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "RecoveryEmailRebind_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "RecoveryEmailRebind_userId_consumedAt_revokedAt_idx"
  ON "RecoveryEmailRebind"("userId", "consumedAt", "revokedAt");
CREATE INDEX "RecoveryEmailRebind_sessionId_expiresAt_idx"
  ON "RecoveryEmailRebind"("sessionId", "expiresAt");

ALTER TABLE "RecoveryEmailRebind" ADD CONSTRAINT "RecoveryEmailRebind_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RecoveryEmailRebind" ADD CONSTRAINT "RecoveryEmailRebind_sessionId_fkey"
  FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;
