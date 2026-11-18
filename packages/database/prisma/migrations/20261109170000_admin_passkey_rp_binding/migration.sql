-- Existing credentials were minted for the USER portal RP. They can never
-- authorize an ADMIN WebAuthn ceremony at the distinct hub RP.
ALTER TABLE "PasskeyCredential"
  ADD COLUMN "rpID" TEXT NOT NULL DEFAULT 'portal.biel.dev.br';

CREATE INDEX "PasskeyCredential_userId_rpID_revokedAt_idx"
  ON "PasskeyCredential"("userId", "rpID", "revokedAt");
