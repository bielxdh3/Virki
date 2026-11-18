-- The original WebAuthn constraints admitted only REGISTRATION and
-- AUTHENTICATION. The recovery backend creates a distinct owner-bound
-- ceremony, so that proof must also be admitted at the database boundary.
-- Keep the original restrictions for registration and login unchanged.
ALTER TABLE "PasskeyChallenge"
  DROP CONSTRAINT "PasskeyChallenge_ceremony_check";
ALTER TABLE "PasskeyChallenge"
  ADD CONSTRAINT "PasskeyChallenge_ceremony_check"
  CHECK ("ceremony" IN ('REGISTRATION', 'AUTHENTICATION', 'RECOVERY'));

ALTER TABLE "PasskeyChallenge"
  DROP CONSTRAINT "PasskeyChallenge_registration_context_check";
ALTER TABLE "PasskeyChallenge"
  ADD CONSTRAINT "PasskeyChallenge_registration_context_check"
  CHECK (
    ("ceremony" = 'REGISTRATION' AND "userId" IS NOT NULL AND "sessionId" IS NOT NULL)
    OR ("ceremony" = 'AUTHENTICATION' AND "sessionId" IS NULL)
    OR ("ceremony" = 'RECOVERY' AND "userId" IS NOT NULL AND "sessionId" IS NULL AND "proofHash" IS NOT NULL)
  );
