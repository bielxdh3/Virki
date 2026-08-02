-- BielOS identity and module-access foundation.
-- Additive only: legacy SecurityUnlock rows remain non-authoritative.

CREATE TYPE "AccountStatus" AS ENUM ('PENDING_ACTIVATION', 'ACTIVE', 'BLOCKED', 'INACTIVE');
CREATE TYPE "AccountApplicationStatus" AS ENUM ('PENDING_EMAIL', 'EMAIL_VERIFIED', 'IN_REVIEW', 'APPROVED', 'REJECTED', 'EXPIRED', 'ACTIVATED');
CREATE TYPE "ApplicationModuleDecisionStatus" AS ENUM ('REQUESTED', 'APPROVED', 'REJECTED', 'BLOCKED', 'EXPIRED', 'REVOKED');
CREATE TYPE "ModuleCatalogVisibility" AS ENUM ('PUBLIC', 'UNLISTED', 'PRIVATE');
CREATE TYPE "ModuleRuntimeAvailability" AS ENUM ('AVAILABLE', 'UNAVAILABLE', 'INERT');
CREATE TYPE "AccessDurationKind" AS ENUM ('PERMANENT', 'TEMPORARY');
CREATE TYPE "ModuleAccessStatus" AS ENUM ('ACTIVE', 'EXPIRED', 'REVOKED');
CREATE TYPE "ModuleRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'BLOCKED', 'EXPIRED');
CREATE TYPE "FeaturePermissionStatus" AS ENUM ('ACTIVE', 'INACTIVE');
CREATE TYPE "OutboxMessageStatus" AS ENUM ('QUEUED', 'PROCESSING', 'SENT', 'RETRYABLE_FAILURE', 'TERMINAL_FAILURE');
CREATE TYPE "EmailMessageKind" AS ENUM ('APPLICATION_EMAIL_VERIFICATION', 'ACCOUNT_ACTIVATION', 'USER_VISIBLE_REJECTION', 'MODULE_ACCESS_CHANGED', 'FEATURE_PERMISSION_CHANGED', 'NEW_DEVICE_VERIFICATION', 'EMAIL_TWO_FACTOR', 'PASSWORD_CHANGED', 'SESSION_TERMINATED', 'ACCOUNT_RECOVERY', 'SECOND_FACTOR_CHANGED', 'ADMIN_EMAIL_VERIFICATION', 'ADMIN_CREDENTIAL_CHANGED', 'ELEVATION_CHANGED');
CREATE TYPE "DeliveryAttemptStatus" AS ENUM ('SENT', 'FAILED');
CREATE TYPE "SecurityFactorStatus" AS ENUM ('PENDING', 'ACTIVE', 'REVOKED');
CREATE TYPE "DeviceChallengeStatus" AS ENUM ('PENDING', 'VERIFIED', 'EXPIRED', 'REVOKED');
CREATE TYPE "TrustedDeviceStatus" AS ENUM ('TRUSTED', 'REVOKED');
CREATE TYPE "RecoveryRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED');
CREATE TYPE "AdministrativeCredentialStatus" AS ENUM ('NOT_CONFIGURED', 'ACTIVE', 'REVOKED');
CREATE TYPE "SecurityElevationStatus" AS ENUM ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'CONSUMED');

ALTER TABLE "User" ADD COLUMN "emailNormalized" TEXT;
ALTER TABLE "User" ADD COLUMN "accountStatus" "AccountStatus" NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE "User" ADD COLUMN "emailVerifiedAt" TIMESTAMP(3);
UPDATE "User" SET "emailNormalized" = LOWER(BTRIM("email")) WHERE "emailNormalized" IS NULL;
CREATE UNIQUE INDEX "User_emailNormalized_key" ON "User"("emailNormalized");

CREATE TABLE "AccountApplication" (
    "id" TEXT NOT NULL,
    "emailNormalized" TEXT NOT NULL,
    "displayName" TEXT,
    "status" "AccountApplicationStatus" NOT NULL DEFAULT 'PENDING_EMAIL',
    "reviewedByUserId" TEXT,
    "internalReviewReason" TEXT,
    "retryAfterAt" TIMESTAMP(3),
    "indefinitelyBlocked" BOOLEAN NOT NULL DEFAULT false,
    "activatedUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "AccountApplication_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ApplicationEmailVerification" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ApplicationEmailVerification_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AccountActivation" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "AccountActivation_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ModuleCatalog" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "visibility" "ModuleCatalogVisibility" NOT NULL DEFAULT 'PRIVATE',
    "runtimeAvailability" "ModuleRuntimeAvailability" NOT NULL DEFAULT 'INERT',
    "requestable" BOOLEAN NOT NULL DEFAULT false,
    "separateRepository" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ModuleCatalog_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ApplicationModuleDecision" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "moduleId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "status" "ApplicationModuleDecisionStatus" NOT NULL DEFAULT 'REQUESTED',
    "internalReason" TEXT,
    "userVisibleMessage" TEXT,
    "accessDurationKind" "AccessDurationKind" NOT NULL DEFAULT 'PERMANENT',
    "accessExpiresAt" TIMESTAMP(3),
    "retryAfterAt" TIMESTAMP(3),
    "indefinitelyBlocked" BOOLEAN NOT NULL DEFAULT false,
    "addedByOwner" BOOLEAN NOT NULL DEFAULT false,
    "reviewedByUserId" TEXT,
    "decidedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ApplicationModuleDecision_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ModuleAccessGrant" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "moduleId" TEXT NOT NULL,
    "status" "ModuleAccessStatus" NOT NULL DEFAULT 'ACTIVE',
    "accessDurationKind" "AccessDurationKind" NOT NULL DEFAULT 'PERMANENT',
    "expiresAt" TIMESTAMP(3),
    "grantedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    CONSTRAINT "ModuleAccessGrant_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ModuleAccessRequest" (
    "id" TEXT NOT NULL,
    "requestKey" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "moduleId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "status" "ModuleRequestStatus" NOT NULL DEFAULT 'PENDING',
    "userVisibleMessage" TEXT,
    "retryAfterAt" TIMESTAMP(3),
    "indefinitelyBlocked" BOOLEAN NOT NULL DEFAULT false,
    "reviewedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "decidedAt" TIMESTAMP(3),
    CONSTRAINT "ModuleAccessRequest_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "FeaturePermissionDeclaration" (
    "id" TEXT NOT NULL,
    "moduleId" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "status" "FeaturePermissionStatus" NOT NULL DEFAULT 'ACTIVE',
    "requestable" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "FeaturePermissionDeclaration_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "FeaturePermissionGrant" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "permissionId" TEXT NOT NULL,
    "grantedByUserId" TEXT,
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "FeaturePermissionGrant_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "FeaturePermissionRequest" (
    "id" TEXT NOT NULL,
    "requestKey" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "permissionId" TEXT NOT NULL,
    "reason" TEXT,
    "status" "ModuleRequestStatus" NOT NULL DEFAULT 'PENDING',
    "userVisibleMessage" TEXT,
    "retryAfterAt" TIMESTAMP(3),
    "indefinitelyBlocked" BOOLEAN NOT NULL DEFAULT false,
    "reviewedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "decidedAt" TIMESTAMP(3),
    CONSTRAINT "FeaturePermissionRequest_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "EmailOutboxMessage" (
    "id" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "kind" "EmailMessageKind" NOT NULL,
    "recipientEmail" TEXT NOT NULL,
    "locale" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "OutboxMessageStatus" NOT NULL DEFAULT 'QUEUED',
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "availableAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sentAt" TIMESTAMP(3),
    "terminalFailedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "EmailOutboxMessage_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "EmailDeliveryAttempt" (
    "id" TEXT NOT NULL,
    "messageId" TEXT NOT NULL,
    "attempt" INTEGER NOT NULL,
    "status" "DeliveryAttemptStatus" NOT NULL,
    "errorCode" TEXT,
    "attemptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "EmailDeliveryAttempt_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "TotpFactor" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "secretCiphertext" TEXT NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "status" "SecurityFactorStatus" NOT NULL DEFAULT 'PENDING',
    "confirmedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "TotpFactor_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "RecoveryCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "RecoveryCode_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DeviceChallenge" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "ceremonyId" TEXT NOT NULL,
    "deviceIdHash" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "status" "DeviceChallengeStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "DeviceChallenge_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "TrustedDevice" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "deviceIdHash" TEXT NOT NULL,
    "label" TEXT,
    "status" "TrustedDeviceStatus" NOT NULL DEFAULT 'TRUSTED',
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "TrustedDevice_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AccountRecoveryRequest" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "emailChallengeHash" TEXT NOT NULL,
    "status" "RecoveryRequestStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "reviewedByUserId" TEXT,
    "approvedAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "AccountRecoveryRequest_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AdministrativeCredential" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "status" "AdministrativeCredentialStatus" NOT NULL DEFAULT 'NOT_CONFIGURED',
    "keyVersion" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    CONSTRAINT "AdministrativeCredential_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AdministrativeRecoveryCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AdministrativeRecoveryCode_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SecurityElevation" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "protocolVersion" INTEGER NOT NULL,
    "scope" TEXT NOT NULL,
    "challengeHash" TEXT NOT NULL,
    "status" "SecurityElevationStatus" NOT NULL DEFAULT 'PENDING',
    "manualUntilRevoked" BOOLEAN NOT NULL DEFAULT false,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "activatedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SecurityElevation_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SanitizedAuditReference" (
    "id" TEXT NOT NULL,
    "referenceHash" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "SanitizedAuditReference_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "ApplicationModuleDecision" ADD CONSTRAINT "ApplicationModuleDecision_duration_check"
  CHECK (("accessDurationKind" = 'PERMANENT' AND "accessExpiresAt" IS NULL) OR ("accessDurationKind" = 'TEMPORARY' AND "accessExpiresAt" IS NOT NULL));
ALTER TABLE "ModuleAccessGrant" ADD CONSTRAINT "ModuleAccessGrant_duration_check"
  CHECK (("accessDurationKind" = 'PERMANENT' AND "expiresAt" IS NULL) OR ("accessDurationKind" = 'TEMPORARY' AND "expiresAt" IS NOT NULL));
ALTER TABLE "User" ADD CONSTRAINT "User_emailNormalized_nonempty_check"
  CHECK ("emailNormalized" IS NULL OR char_length("emailNormalized") > 0);

CREATE UNIQUE INDEX "ApplicationEmailVerification_applicationId_key" ON "ApplicationEmailVerification"("applicationId");
CREATE UNIQUE INDEX "AccountActivation_applicationId_key" ON "AccountActivation"("applicationId");
CREATE UNIQUE INDEX "ModuleCatalog_key_key" ON "ModuleCatalog"("key");
CREATE UNIQUE INDEX "ApplicationModuleDecision_applicationId_moduleId_key" ON "ApplicationModuleDecision"("applicationId", "moduleId");
CREATE UNIQUE INDEX "ModuleAccessGrant_userId_moduleId_key" ON "ModuleAccessGrant"("userId", "moduleId");
CREATE UNIQUE INDEX "ModuleAccessRequest_requestKey_key" ON "ModuleAccessRequest"("requestKey");
CREATE UNIQUE INDEX "FeaturePermissionDeclaration_moduleId_key_key" ON "FeaturePermissionDeclaration"("moduleId", "key");
CREATE UNIQUE INDEX "FeaturePermissionGrant_userId_permissionId_key" ON "FeaturePermissionGrant"("userId", "permissionId");
CREATE UNIQUE INDEX "FeaturePermissionRequest_requestKey_key" ON "FeaturePermissionRequest"("requestKey");
CREATE UNIQUE INDEX "EmailOutboxMessage_idempotencyKey_key" ON "EmailOutboxMessage"("idempotencyKey");
CREATE UNIQUE INDEX "EmailDeliveryAttempt_messageId_attempt_key" ON "EmailDeliveryAttempt"("messageId", "attempt");
CREATE UNIQUE INDEX "TotpFactor_userId_key" ON "TotpFactor"("userId");
CREATE UNIQUE INDEX "RecoveryCode_userId_codeHash_key" ON "RecoveryCode"("userId", "codeHash");
CREATE UNIQUE INDEX "DeviceChallenge_ceremonyId_key" ON "DeviceChallenge"("ceremonyId");
CREATE UNIQUE INDEX "TrustedDevice_userId_deviceIdHash_key" ON "TrustedDevice"("userId", "deviceIdHash");
CREATE UNIQUE INDEX "AdministrativeCredential_userId_key" ON "AdministrativeCredential"("userId");
CREATE UNIQUE INDEX "AdministrativeRecoveryCode_userId_codeHash_key" ON "AdministrativeRecoveryCode"("userId", "codeHash");
CREATE UNIQUE INDEX "SanitizedAuditReference_referenceHash_key" ON "SanitizedAuditReference"("referenceHash");

CREATE INDEX "AccountApplication_emailNormalized_idx" ON "AccountApplication"("emailNormalized");
CREATE INDEX "AccountApplication_status_createdAt_idx" ON "AccountApplication"("status", "createdAt");
CREATE INDEX "ApplicationEmailVerification_expiresAt_idx" ON "ApplicationEmailVerification"("expiresAt");
CREATE INDEX "AccountActivation_expiresAt_idx" ON "AccountActivation"("expiresAt");
CREATE INDEX "ApplicationModuleDecision_moduleId_status_idx" ON "ApplicationModuleDecision"("moduleId", "status");
CREATE INDEX "ModuleAccessGrant_moduleId_status_idx" ON "ModuleAccessGrant"("moduleId", "status");
CREATE INDEX "ModuleAccessGrant_expiresAt_idx" ON "ModuleAccessGrant"("expiresAt");
CREATE INDEX "ModuleAccessRequest_userId_moduleId_createdAt_idx" ON "ModuleAccessRequest"("userId", "moduleId", "createdAt");
CREATE INDEX "ModuleAccessRequest_moduleId_status_idx" ON "ModuleAccessRequest"("moduleId", "status");
CREATE INDEX "FeaturePermissionDeclaration_moduleId_status_requestable_idx" ON "FeaturePermissionDeclaration"("moduleId", "status", "requestable");
CREATE INDEX "FeaturePermissionGrant_permissionId_idx" ON "FeaturePermissionGrant"("permissionId");
CREATE INDEX "FeaturePermissionGrant_expiresAt_idx" ON "FeaturePermissionGrant"("expiresAt");
CREATE INDEX "FeaturePermissionRequest_userId_permissionId_createdAt_idx" ON "FeaturePermissionRequest"("userId", "permissionId", "createdAt");
CREATE INDEX "FeaturePermissionRequest_permissionId_status_idx" ON "FeaturePermissionRequest"("permissionId", "status");
CREATE INDEX "EmailOutboxMessage_status_availableAt_idx" ON "EmailOutboxMessage"("status", "availableAt");
CREATE INDEX "EmailDeliveryAttempt_attemptedAt_idx" ON "EmailDeliveryAttempt"("attemptedAt");
CREATE INDEX "RecoveryCode_userId_usedAt_idx" ON "RecoveryCode"("userId", "usedAt");
CREATE INDEX "DeviceChallenge_userId_deviceIdHash_idx" ON "DeviceChallenge"("userId", "deviceIdHash");
CREATE INDEX "DeviceChallenge_expiresAt_idx" ON "DeviceChallenge"("expiresAt");
CREATE INDEX "TrustedDevice_userId_status_idx" ON "TrustedDevice"("userId", "status");
CREATE INDEX "AccountRecoveryRequest_userId_status_idx" ON "AccountRecoveryRequest"("userId", "status");
CREATE INDEX "AccountRecoveryRequest_expiresAt_idx" ON "AccountRecoveryRequest"("expiresAt");
CREATE INDEX "AdministrativeRecoveryCode_userId_usedAt_idx" ON "AdministrativeRecoveryCode"("userId", "usedAt");
CREATE INDEX "SecurityElevation_userId_sessionId_scope_idx" ON "SecurityElevation"("userId", "sessionId", "scope");
CREATE INDEX "SecurityElevation_status_expiresAt_idx" ON "SecurityElevation"("status", "expiresAt");
CREATE INDEX "SecurityElevation_sessionId_idx" ON "SecurityElevation"("sessionId");
CREATE INDEX "SanitizedAuditReference_category_createdAt_idx" ON "SanitizedAuditReference"("category", "createdAt");

ALTER TABLE "AccountApplication" ADD CONSTRAINT "AccountApplication_reviewedByUserId_fkey" FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "AccountApplication" ADD CONSTRAINT "AccountApplication_activatedUserId_fkey" FOREIGN KEY ("activatedUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "ApplicationEmailVerification" ADD CONSTRAINT "ApplicationEmailVerification_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "AccountApplication"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AccountActivation" ADD CONSTRAINT "AccountActivation_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "AccountApplication"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ApplicationModuleDecision" ADD CONSTRAINT "ApplicationModuleDecision_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "AccountApplication"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ApplicationModuleDecision" ADD CONSTRAINT "ApplicationModuleDecision_moduleId_fkey" FOREIGN KEY ("moduleId") REFERENCES "ModuleCatalog"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ApplicationModuleDecision" ADD CONSTRAINT "ApplicationModuleDecision_reviewedByUserId_fkey" FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "ModuleAccessGrant" ADD CONSTRAINT "ModuleAccessGrant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ModuleAccessGrant" ADD CONSTRAINT "ModuleAccessGrant_moduleId_fkey" FOREIGN KEY ("moduleId") REFERENCES "ModuleCatalog"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ModuleAccessGrant" ADD CONSTRAINT "ModuleAccessGrant_grantedByUserId_fkey" FOREIGN KEY ("grantedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "ModuleAccessRequest" ADD CONSTRAINT "ModuleAccessRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ModuleAccessRequest" ADD CONSTRAINT "ModuleAccessRequest_moduleId_fkey" FOREIGN KEY ("moduleId") REFERENCES "ModuleCatalog"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ModuleAccessRequest" ADD CONSTRAINT "ModuleAccessRequest_reviewedByUserId_fkey" FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "FeaturePermissionDeclaration" ADD CONSTRAINT "FeaturePermissionDeclaration_moduleId_fkey" FOREIGN KEY ("moduleId") REFERENCES "ModuleCatalog"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "FeaturePermissionGrant" ADD CONSTRAINT "FeaturePermissionGrant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "FeaturePermissionGrant" ADD CONSTRAINT "FeaturePermissionGrant_permissionId_fkey" FOREIGN KEY ("permissionId") REFERENCES "FeaturePermissionDeclaration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "FeaturePermissionGrant" ADD CONSTRAINT "FeaturePermissionGrant_grantedByUserId_fkey" FOREIGN KEY ("grantedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "FeaturePermissionRequest" ADD CONSTRAINT "FeaturePermissionRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "FeaturePermissionRequest" ADD CONSTRAINT "FeaturePermissionRequest_permissionId_fkey" FOREIGN KEY ("permissionId") REFERENCES "FeaturePermissionDeclaration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "FeaturePermissionRequest" ADD CONSTRAINT "FeaturePermissionRequest_reviewedByUserId_fkey" FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "EmailDeliveryAttempt" ADD CONSTRAINT "EmailDeliveryAttempt_messageId_fkey" FOREIGN KEY ("messageId") REFERENCES "EmailOutboxMessage"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "TotpFactor" ADD CONSTRAINT "TotpFactor_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RecoveryCode" ADD CONSTRAINT "RecoveryCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DeviceChallenge" ADD CONSTRAINT "DeviceChallenge_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "TrustedDevice" ADD CONSTRAINT "TrustedDevice_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AccountRecoveryRequest" ADD CONSTRAINT "AccountRecoveryRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AccountRecoveryRequest" ADD CONSTRAINT "AccountRecoveryRequest_reviewedByUserId_fkey" FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "AdministrativeCredential" ADD CONSTRAINT "AdministrativeCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AdministrativeRecoveryCode" ADD CONSTRAINT "AdministrativeRecoveryCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SecurityElevation" ADD CONSTRAINT "SecurityElevation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
