-- An authenticated password ceremony chooses a single server-bound verification factor.
-- NULL is reserved for legacy in-flight ceremonies and old API callers.
CREATE TYPE "LoginChallengeFactor" AS ENUM ('EMAIL', 'TOTP', 'BACKUP');

ALTER TABLE "DeviceChallenge"
  ADD COLUMN "factorChoice" "LoginChallengeFactor";
