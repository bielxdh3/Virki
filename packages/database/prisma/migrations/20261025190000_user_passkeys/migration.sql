CREATE TABLE "PasskeyCredential" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "credentialId" TEXT NOT NULL,
  "publicKey" BYTEA NOT NULL,
  "counter" BIGINT NOT NULL DEFAULT 0,
  "revision" INTEGER NOT NULL DEFAULT 0,
  "transports" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "backupEligible" BOOLEAN NOT NULL,
  "backupState" BOOLEAN NOT NULL,
  "name" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastUsedAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  CONSTRAINT "PasskeyCredential_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "PasskeyCredential_credentialId_key" ON "PasskeyCredential"("credentialId");
CREATE INDEX "PasskeyCredential_userId_revokedAt_idx" ON "PasskeyCredential"("userId", "revokedAt");
ALTER TABLE "PasskeyCredential" ADD CONSTRAINT "PasskeyCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "PasskeyChallenge" (
  "id" TEXT NOT NULL,
  "challengeHash" TEXT NOT NULL,
  "ceremony" TEXT NOT NULL,
  "userId" TEXT,
  "sessionId" TEXT,
  "browserHash" TEXT NOT NULL,
  "proofHash" TEXT,
  "rpID" TEXT NOT NULL,
  "origin" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "PasskeyChallenge_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "PasskeyChallenge_ceremony_check" CHECK ("ceremony" IN ('REGISTRATION','AUTHENTICATION')),
  CONSTRAINT "PasskeyChallenge_registration_context_check" CHECK (
    ("ceremony" = 'REGISTRATION' AND "userId" IS NOT NULL AND "sessionId" IS NOT NULL)
    OR ("ceremony" = 'AUTHENTICATION' AND "sessionId" IS NULL)
  )
);
CREATE UNIQUE INDEX "PasskeyChallenge_challengeHash_key" ON "PasskeyChallenge"("challengeHash");
CREATE INDEX "PasskeyChallenge_expiresAt_idx" ON "PasskeyChallenge"("expiresAt");
CREATE INDEX "PasskeyChallenge_browserHash_ceremony_idx" ON "PasskeyChallenge"("browserHash", "ceremony");
ALTER TABLE "PasskeyChallenge" ADD CONSTRAINT "PasskeyChallenge_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PasskeyChallenge" ADD CONSTRAINT "PasskeyChallenge_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;
