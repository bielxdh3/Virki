-- Stop without changing data if the production privilege history is ambiguous.
DO $$
DECLARE
  owner_count BIGINT;
  admin_count BIGINT;
BEGIN
  SELECT COUNT(*) INTO owner_count FROM "User" WHERE "role"::text = 'OWNER';
  SELECT COUNT(*) INTO admin_count FROM "User" WHERE "role"::text = 'ADMIN';
  IF owner_count <> 1 OR admin_count <> 0 THEN
    RAISE EXCEPTION 'BIELOS_REBASELINE_BLOCKED_AMBIGUOUS_ADMIN_IDENTITY';
  END IF;
END $$;

-- Remove intake database capabilities before the legacy catalog and account tables.
DROP VIEW IF EXISTS "IntakePublicModuleCatalog";
DROP FUNCTION IF EXISTS "bielos_intake_activate_application"(TEXT, TEXT, TEXT, TIMESTAMP WITHOUT TIME ZONE);
DROP FUNCTION IF EXISTS "bielos_intake_enqueue_email_message"(TEXT, TEXT, TEXT, JSONB, TIMESTAMP WITHOUT TIME ZONE);

-- Keep only auth/security messages and audit events that remain meaningful.
DELETE FROM "EmailDeliveryAttempt"
WHERE "messageId" IN (
  SELECT "id" FROM "EmailOutboxMessage"
  WHERE "kind"::text NOT IN (
    'NEW_DEVICE_VERIFICATION', 'EMAIL_TWO_FACTOR', 'PASSWORD_CHANGED',
    'SESSION_TERMINATED', 'ACCOUNT_RECOVERY', 'SECOND_FACTOR_CHANGED',
    'ADMIN_EMAIL_VERIFICATION', 'ADMIN_CREDENTIAL_CHANGED', 'ELEVATION_CHANGED'
  )
);
DELETE FROM "EmailOutboxMessage"
WHERE "kind"::text NOT IN (
  'NEW_DEVICE_VERIFICATION', 'EMAIL_TWO_FACTOR', 'PASSWORD_CHANGED',
  'SESSION_TERMINATED', 'ACCOUNT_RECOVERY', 'SECOND_FACTOR_CHANGED',
  'ADMIN_EMAIL_VERIFICATION', 'ADMIN_CREDENTIAL_CHANGED', 'ELEVATION_CHANGED'
);
DELETE FROM "AuditLog"
WHERE "eventType" NOT IN (
  'AUTH_LOGIN_SUCCESS', 'AUTH_LOGIN_FAILURE', 'AUTH_LOGOUT',
  'AUTH_SESSION_REVOKED', 'AUTH_SESSION_CLEANUP', 'AUTH_AUDIT_LOG_CLEANUP',
  'AUDIT_LOG_EXPORTED', 'ACCOUNT_CREATED', 'ACCOUNT_STATE_CHANGED',
  'PROJECT_ACCESS_GRANTED', 'PROJECT_ACCESS_REVOKED',
  'PROJECT_CONNECTION_CREATED', 'PROJECT_CONNECTION_UPDATED',
  'PROJECT_CONNECTION_REVOKED', 'SSO_AUTHORIZATION_ISSUED',
  'SSO_AUTHORIZATION_DENIED', 'SSO_TOKEN_ISSUED', 'SSO_TOKEN_REJECTED',
  'SECOND_FACTOR_ENROLLMENT_STARTED', 'SECOND_FACTOR_ENROLLED',
  'SECOND_FACTOR_DISABLED', 'RECOVERY_CODES_REGENERATED', 'DEVICE_VERIFIED',
  'TRUSTED_DEVICE_REVOKED', 'ACCOUNT_RECOVERY_REQUESTED',
  'ACCOUNT_RECOVERY_EMAIL_VERIFIED', 'ACCOUNT_RECOVERY_APPROVED',
  'ACCOUNT_RECOVERY_CONSUMED', 'ADMIN_CREDENTIAL_SETUP',
  'ADMIN_CREDENTIAL_CHANGED', 'ADMIN_CREDENTIAL_RECOVERED',
  'ADMIN_ELEVATION_STARTED', 'ADMIN_ELEVATION_ACTIVATED',
  'ADMIN_ELEVATION_REVOKED', 'ACCESS_JWT_MISSING', 'ACCESS_JWT_INVALID',
  'ACCESS_JWT_VALID'
);

-- Invalidate sessions, in-flight login challenges, remembered devices, and elevations.
UPDATE "Session" SET "revokedAt" = CURRENT_TIMESTAMP WHERE "revokedAt" IS NULL;
DELETE FROM "DeviceChallenge";
UPDATE "TrustedDevice"
SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP,
    "rememberedUntil" = NULL, "strongVerifiedAt" = NULL
WHERE "status" <> 'REVOKED';
UPDATE "SecurityElevation"
SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP
WHERE "status" IN ('PENDING', 'ACTIVE');

-- AlterEnum
BEGIN;
CREATE TYPE "UserRole_new" AS ENUM ('ADMIN', 'USER');
ALTER TABLE "User" ALTER COLUMN "role" DROP DEFAULT;
ALTER TABLE "User" ALTER COLUMN "role" TYPE "UserRole_new"
  USING (CASE WHEN "role"::text IN ('OWNER', 'ADMIN') THEN 'ADMIN' ELSE 'USER' END)::"UserRole_new";
ALTER TYPE "UserRole" RENAME TO "UserRole_old";
ALTER TYPE "UserRole_new" RENAME TO "UserRole";
DROP TYPE "UserRole_old";
ALTER TABLE "User" ALTER COLUMN "role" SET DEFAULT 'USER';
COMMIT;

-- AlterEnum
BEGIN;
CREATE TYPE "EmailMessageKind_new" AS ENUM ('NEW_DEVICE_VERIFICATION', 'EMAIL_TWO_FACTOR', 'PASSWORD_CHANGED', 'SESSION_TERMINATED', 'ACCOUNT_RECOVERY', 'SECOND_FACTOR_CHANGED', 'ADMIN_EMAIL_VERIFICATION', 'ADMIN_CREDENTIAL_CHANGED', 'ELEVATION_CHANGED');
ALTER TABLE "EmailOutboxMessage" ALTER COLUMN "kind" TYPE "EmailMessageKind_new" USING ("kind"::text::"EmailMessageKind_new");
ALTER TYPE "EmailMessageKind" RENAME TO "EmailMessageKind_old";
ALTER TYPE "EmailMessageKind_new" RENAME TO "EmailMessageKind";
DROP TYPE "EmailMessageKind_old";
COMMIT;

-- DropForeignKey
ALTER TABLE "ProjectAccess" DROP CONSTRAINT "ProjectAccess_userId_fkey";

-- DropForeignKey
ALTER TABLE "ProjectAccess" DROP CONSTRAINT "ProjectAccess_projectId_fkey";

-- DropForeignKey
ALTER TABLE "SecurityUnlock" DROP CONSTRAINT "SecurityUnlock_userId_fkey";

-- DropForeignKey
ALTER TABLE "SecurityUnlock" DROP CONSTRAINT "SecurityUnlock_projectId_fkey";

-- DropForeignKey
ALTER TABLE "AccountApplication" DROP CONSTRAINT "AccountApplication_activatedUserId_fkey";

-- DropForeignKey
ALTER TABLE "AccountApplication" DROP CONSTRAINT "AccountApplication_reviewedByUserId_fkey";

-- DropForeignKey
ALTER TABLE "ApplicationEmailVerification" DROP CONSTRAINT "ApplicationEmailVerification_applicationId_fkey";

-- DropForeignKey
ALTER TABLE "AccountActivation" DROP CONSTRAINT "AccountActivation_applicationId_fkey";

-- DropForeignKey
ALTER TABLE "ApplicationModuleDecision" DROP CONSTRAINT "ApplicationModuleDecision_applicationId_fkey";

-- DropForeignKey
ALTER TABLE "ApplicationModuleDecision" DROP CONSTRAINT "ApplicationModuleDecision_moduleId_fkey";

-- DropForeignKey
ALTER TABLE "ApplicationModuleDecision" DROP CONSTRAINT "ApplicationModuleDecision_reviewedByUserId_fkey";

-- DropForeignKey
ALTER TABLE "ModuleAccessGrant" DROP CONSTRAINT "ModuleAccessGrant_userId_fkey";

-- DropForeignKey
ALTER TABLE "ModuleAccessGrant" DROP CONSTRAINT "ModuleAccessGrant_moduleId_fkey";

-- DropForeignKey
ALTER TABLE "ModuleAccessGrant" DROP CONSTRAINT "ModuleAccessGrant_grantedByUserId_fkey";

-- DropForeignKey
ALTER TABLE "ModuleAccessRequest" DROP CONSTRAINT "ModuleAccessRequest_userId_fkey";

-- DropForeignKey
ALTER TABLE "ModuleAccessRequest" DROP CONSTRAINT "ModuleAccessRequest_moduleId_fkey";

-- DropForeignKey
ALTER TABLE "ModuleAccessRequest" DROP CONSTRAINT "ModuleAccessRequest_reviewedByUserId_fkey";

-- DropForeignKey
ALTER TABLE "FeaturePermissionDeclaration" DROP CONSTRAINT "FeaturePermissionDeclaration_moduleId_fkey";

-- DropForeignKey
ALTER TABLE "FeaturePermissionGrant" DROP CONSTRAINT "FeaturePermissionGrant_userId_fkey";

-- DropForeignKey
ALTER TABLE "FeaturePermissionGrant" DROP CONSTRAINT "FeaturePermissionGrant_permissionId_fkey";

-- DropForeignKey
ALTER TABLE "FeaturePermissionGrant" DROP CONSTRAINT "FeaturePermissionGrant_grantedByUserId_fkey";

-- DropForeignKey
ALTER TABLE "FeaturePermissionRequest" DROP CONSTRAINT "FeaturePermissionRequest_userId_fkey";

-- DropForeignKey
ALTER TABLE "FeaturePermissionRequest" DROP CONSTRAINT "FeaturePermissionRequest_permissionId_fkey";

-- DropForeignKey
ALTER TABLE "FeaturePermissionRequest" DROP CONSTRAINT "FeaturePermissionRequest_reviewedByUserId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeParticipant" DROP CONSTRAINT "GymForgeParticipant_userId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeAttendance" DROP CONSTRAINT "GymForgeAttendance_participantId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeWorkout" DROP CONSTRAINT "GymForgeWorkout_participantId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeWorkoutSet" DROP CONSTRAINT "GymForgeWorkoutSet_workoutId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeWorkoutSet" DROP CONSTRAINT "GymForgeWorkoutSet_exerciseId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeCompetitionAssignment" DROP CONSTRAINT "GymForgeCompetitionAssignment_competitionId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeCompetitionAssignment" DROP CONSTRAINT "GymForgeCompetitionAssignment_participantId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeCompetitionScoreCorrection" DROP CONSTRAINT "GymForgeCompetitionScoreCorrection_competitionId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeCompetitionScoreCorrection" DROP CONSTRAINT "GymForgeCompetitionScoreCorrection_participantId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeCompetitionScoreCorrection" DROP CONSTRAINT "GymForgeCompetitionScoreCorrection_createdByUserId_fkey";

-- DropForeignKey
ALTER TABLE "GymForgeCompetitionScoreCorrection" DROP CONSTRAINT "GymForgeCompetitionScoreCorrection_revokedByUserId_fkey";

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "role" SET DEFAULT 'USER';

-- DropTable
DROP TABLE "Project";

-- DropTable
DROP TABLE "ProjectAccess";

-- DropTable
DROP TABLE "SecurityUnlock";

-- DropTable
DROP TABLE "AccountApplication";

-- DropTable
DROP TABLE "ApplicationEmailVerification";

-- DropTable
DROP TABLE "AccountActivation";

-- DropTable
DROP TABLE "ModuleCatalog";

-- DropTable
DROP TABLE "ApplicationModuleDecision";

-- DropTable
DROP TABLE "ModuleAccessGrant";

-- DropTable
DROP TABLE "ModuleAccessRequest";

-- DropTable
DROP TABLE "FeaturePermissionDeclaration";

-- DropTable
DROP TABLE "FeaturePermissionGrant";

-- DropTable
DROP TABLE "FeaturePermissionRequest";

-- DropTable
DROP TABLE "GymForgeParticipant";

-- DropTable
DROP TABLE "GymForgeExercise";

-- DropTable
DROP TABLE "GymForgeAttendance";

-- DropTable
DROP TABLE "GymForgeWorkout";

-- DropTable
DROP TABLE "GymForgeWorkoutSet";

-- DropTable
DROP TABLE "GymForgeCompetition";

-- DropTable
DROP TABLE "GymForgeCompetitionAssignment";

-- DropTable
DROP TABLE "GymForgeCompetitionScoreCorrection";

-- DropEnum
DROP TYPE "ProjectVisibility";

-- DropEnum
DROP TYPE "ProjectStatus";

-- DropEnum
DROP TYPE "AccessLevel";

-- DropEnum
DROP TYPE "UnlockPurpose";

-- DropEnum
DROP TYPE "UnlockStatus";

-- DropEnum
DROP TYPE "AccountApplicationStatus";

-- DropEnum
DROP TYPE "ApplicationModuleDecisionStatus";

-- DropEnum
DROP TYPE "ModuleCatalogVisibility";

-- DropEnum
DROP TYPE "ModuleRuntimeAvailability";

-- DropEnum
DROP TYPE "AccessDurationKind";

-- DropEnum
DROP TYPE "ModuleAccessStatus";

-- DropEnum
DROP TYPE "ModuleRequestStatus";

-- DropEnum
DROP TYPE "FeaturePermissionStatus";

-- DropEnum
DROP TYPE "GymForgeParticipantStatus";

-- DropEnum
DROP TYPE "GymForgeParticipantRole";

-- DropEnum
DROP TYPE "GymForgeWorkoutUnit";

-- DropEnum
DROP TYPE "GymForgeCompetitionStatus";

-- CreateTable
CREATE TABLE "ProjectConnection" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT,
    "origin" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "clientId" TEXT NOT NULL,
    "clientSecretCiphertext" TEXT NOT NULL,
    "redirectUris" JSONB NOT NULL,
    "createdByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProjectConnection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserProjectGrant" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "grantedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "UserProjectGrant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OidcArtifact" (
    "id" TEXT NOT NULL,
    "model" TEXT NOT NULL,
    "idHash" TEXT NOT NULL,
    "payloadCiphertext" TEXT NOT NULL,
    "grantHash" TEXT,
    "uidHash" TEXT,
    "userCodeHash" TEXT,
    "clientIdHash" TEXT,
    "accountIdHash" TEXT,
    "expiresAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OidcArtifact_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ProjectConnection_slug_key" ON "ProjectConnection"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "ProjectConnection_clientId_key" ON "ProjectConnection"("clientId");

-- CreateIndex
CREATE INDEX "ProjectConnection_enabled_idx" ON "ProjectConnection"("enabled");

-- CreateIndex
CREATE INDEX "UserProjectGrant_connectionId_revokedAt_idx" ON "UserProjectGrant"("connectionId", "revokedAt");

-- CreateIndex
CREATE INDEX "UserProjectGrant_userId_revokedAt_idx" ON "UserProjectGrant"("userId", "revokedAt");

-- CreateIndex
CREATE UNIQUE INDEX "UserProjectGrant_userId_connectionId_key" ON "UserProjectGrant"("userId", "connectionId");

-- CreateIndex
CREATE INDEX "OidcArtifact_model_uidHash_idx" ON "OidcArtifact"("model", "uidHash");

-- CreateIndex
CREATE INDEX "OidcArtifact_model_userCodeHash_idx" ON "OidcArtifact"("model", "userCodeHash");

-- CreateIndex
CREATE INDEX "OidcArtifact_model_grantHash_idx" ON "OidcArtifact"("model", "grantHash");

-- CreateIndex
CREATE INDEX "OidcArtifact_clientIdHash_accountIdHash_idx" ON "OidcArtifact"("clientIdHash", "accountIdHash");

-- CreateIndex
CREATE INDEX "OidcArtifact_expiresAt_idx" ON "OidcArtifact"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "OidcArtifact_model_idHash_key" ON "OidcArtifact"("model", "idHash");

-- AddForeignKey
ALTER TABLE "ProjectConnection" ADD CONSTRAINT "ProjectConnection_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserProjectGrant" ADD CONSTRAINT "UserProjectGrant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserProjectGrant" ADD CONSTRAINT "UserProjectGrant_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "ProjectConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
