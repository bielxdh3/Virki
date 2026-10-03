CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE "ProjectConnection" ADD COLUMN "launchUrl" TEXT;
ALTER TABLE "Session" ADD COLUMN "authenticationMethods" TEXT[] NOT NULL DEFAULT ARRAY['pwd']::TEXT[];

ALTER TABLE "DeviceChallenge"
  ADD COLUMN "emailAddressHash" TEXT NOT NULL DEFAULT '',
  ADD COLUMN "emailVerifiedAt" TIMESTAMP(3);

UPDATE "DeviceChallenge"
SET "status" = 'REVOKED'
WHERE "status" IN ('PENDING', 'VERIFIED') AND "consumedAt" IS NULL;

ALTER TABLE "DeviceChallenge" ALTER COLUMN "emailAddressHash" DROP DEFAULT;

ALTER TABLE "AccountRecoveryRequest" ADD COLUMN "emailAddressHash" TEXT;

UPDATE "AccountRecoveryRequest" AS recovery
SET "emailAddressHash" = encode(digest(lower(btrim(coalesce("User"."emailNormalized", "User"."email"))), 'sha256'), 'hex')
FROM "User"
WHERE "User"."id" = recovery."userId";

UPDATE "EmailOutboxMessage"
SET "idempotencyKey" = 'account-recovery-migrated:' || "id"
WHERE "kind" = 'ACCOUNT_RECOVERY'
  AND "idempotencyKey" ~ '^account-recovery:[A-Za-z0-9_-]{32}$';

UPDATE "AccountRecoveryRequest"
SET "requestKey" = encode(digest("requestKey", 'sha256'), 'hex');

ALTER TABLE "AccountRecoveryRequest" RENAME COLUMN "requestKey" TO "requestKeyHash";
ALTER TABLE "AccountRecoveryRequest" ALTER COLUMN "emailAddressHash" SET NOT NULL;
ALTER INDEX "AccountRecoveryRequest_requestKey_key" RENAME TO "AccountRecoveryRequest_requestKeyHash_key";
