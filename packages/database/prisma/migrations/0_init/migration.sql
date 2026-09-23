-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('ADMIN', 'USER');

-- CreateEnum
CREATE TYPE "AccountStatus" AS ENUM ('PENDING_ACTIVATION', 'ACTIVE', 'BLOCKED', 'INACTIVE');

-- CreateEnum
CREATE TYPE "SecondFactorMethod" AS ENUM ('EMAIL', 'TOTP');

-- CreateEnum
CREATE TYPE "OutboxMessageStatus" AS ENUM ('QUEUED', 'PROCESSING', 'SENT', 'RETRYABLE_FAILURE', 'TERMINAL_FAILURE');

-- CreateEnum
CREATE TYPE "EmailMessageKind" AS ENUM ('NEW_DEVICE_VERIFICATION', 'EMAIL_TWO_FACTOR', 'PASSWORD_CHANGED', 'SESSION_TERMINATED', 'ACCOUNT_RECOVERY', 'SECOND_FACTOR_CHANGED', 'ADMIN_EMAIL_VERIFICATION', 'ADMIN_CREDENTIAL_CHANGED', 'ELEVATION_CHANGED');

-- CreateEnum
CREATE TYPE "DeliveryAttemptStatus" AS ENUM ('SENT', 'FAILED');

-- CreateEnum
CREATE TYPE "SecurityFactorStatus" AS ENUM ('PENDING', 'ACTIVE', 'REVOKED');

-- CreateEnum
CREATE TYPE "DeviceChallengeStatus" AS ENUM ('PENDING', 'VERIFIED', 'EXPIRED', 'REVOKED');

-- CreateEnum
CREATE TYPE "TrustedDeviceStatus" AS ENUM ('TRUSTED', 'REVOKED');

-- CreateEnum
CREATE TYPE "RecoveryRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED');

-- CreateEnum
CREATE TYPE "AdministrativeCredentialStatus" AS ENUM ('NOT_CONFIGURED', 'ACTIVE', 'REVOKED');

-- CreateEnum
CREATE TYPE "SecurityElevationStatus" AS ENUM ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'CONSUMED');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "emailNormalized" TEXT,
    "displayName" TEXT,
    "passwordHash" TEXT,
    "role" "UserRole" NOT NULL DEFAULT 'USER',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "accountStatus" "AccountStatus" NOT NULL DEFAULT 'ACTIVE',
    "emailVerifiedAt" TIMESTAMP(3),
    "secondFactorMethod" "SecondFactorMethod" NOT NULL DEFAULT 'EMAIL',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "sessionKey" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LoginRateLimit" (
    "id" TEXT NOT NULL,
    "identifierHash" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "windowStartedAt" TIMESTAMP(3) NOT NULL,
    "blockedUntil" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "LoginRateLimit_pkey" PRIMARY KEY ("id")
);

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

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "actorUserId" TEXT,
    "actorEmailHash" TEXT,
    "result" TEXT NOT NULL,
    "resource" TEXT,
    "message" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
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

-- CreateTable
CREATE TABLE "EmailDeliveryAttempt" (
    "id" TEXT NOT NULL,
    "messageId" TEXT NOT NULL,
    "attempt" INTEGER NOT NULL,
    "status" "DeliveryAttemptStatus" NOT NULL,
    "errorCode" TEXT,
    "attemptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailDeliveryAttempt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TotpFactor" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "secretCiphertext" TEXT NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "lastUsedStep" INTEGER,
    "status" "SecurityFactorStatus" NOT NULL DEFAULT 'PENDING',
    "confirmedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TotpFactor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RecoveryCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RecoveryCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeviceChallenge" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "ceremonyId" TEXT NOT NULL,
    "deviceIdHash" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "requiresTotp" BOOLEAN NOT NULL DEFAULT false,
    "status" "DeviceChallengeStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DeviceChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TrustedDevice" (
    "id" TEXT NOT NULL,
    "deviceKey" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "deviceIdHash" TEXT NOT NULL,
    "label" TEXT,
    "status" "TrustedDeviceStatus" NOT NULL DEFAULT 'TRUSTED',
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rememberedUntil" TIMESTAMP(3),
    "strongVerifiedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TrustedDevice_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccountRecoveryRequest" (
    "id" TEXT NOT NULL,
    "requestKey" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "emailChallengeHash" TEXT NOT NULL,
    "emailVerifiedAt" TIMESTAMP(3),
    "status" "RecoveryRequestStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "reviewedByUserId" TEXT,
    "approvedAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AccountRecoveryRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
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

-- CreateTable
CREATE TABLE "AdministrativeRecoveryCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdministrativeRecoveryCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityElevation" (
    "id" TEXT NOT NULL,
    "requestKey" TEXT NOT NULL,
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

-- CreateTable
CREATE TABLE "SanitizedAuditReference" (
    "id" TEXT NOT NULL,
    "referenceHash" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SanitizedAuditReference_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_emailNormalized_key" ON "User"("emailNormalized");

-- CreateIndex
CREATE UNIQUE INDEX "Session_sessionKey_key" ON "Session"("sessionKey");

-- CreateIndex
CREATE UNIQUE INDEX "Session_tokenHash_key" ON "Session"("tokenHash");

-- CreateIndex
CREATE INDEX "Session_userId_idx" ON "Session"("userId");

-- CreateIndex
CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "LoginRateLimit_identifierHash_key" ON "LoginRateLimit"("identifierHash");

-- CreateIndex
CREATE INDEX "LoginRateLimit_blockedUntil_idx" ON "LoginRateLimit"("blockedUntil");

-- CreateIndex
CREATE INDEX "LoginRateLimit_expiresAt_idx" ON "LoginRateLimit"("expiresAt");

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

-- CreateIndex
CREATE INDEX "AuditLog_eventType_idx" ON "AuditLog"("eventType");

-- CreateIndex
CREATE INDEX "AuditLog_actorUserId_idx" ON "AuditLog"("actorUserId");

-- CreateIndex
CREATE INDEX "AuditLog_actorEmailHash_idx" ON "AuditLog"("actorEmailHash");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "EmailOutboxMessage_idempotencyKey_key" ON "EmailOutboxMessage"("idempotencyKey");

-- CreateIndex
CREATE INDEX "EmailOutboxMessage_status_availableAt_idx" ON "EmailOutboxMessage"("status", "availableAt");

-- CreateIndex
CREATE INDEX "EmailDeliveryAttempt_attemptedAt_idx" ON "EmailDeliveryAttempt"("attemptedAt");

-- CreateIndex
CREATE UNIQUE INDEX "EmailDeliveryAttempt_messageId_attempt_key" ON "EmailDeliveryAttempt"("messageId", "attempt");

-- CreateIndex
CREATE UNIQUE INDEX "TotpFactor_userId_key" ON "TotpFactor"("userId");

-- CreateIndex
CREATE INDEX "RecoveryCode_userId_usedAt_idx" ON "RecoveryCode"("userId", "usedAt");

-- CreateIndex
CREATE UNIQUE INDEX "RecoveryCode_userId_codeHash_key" ON "RecoveryCode"("userId", "codeHash");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceChallenge_ceremonyId_key" ON "DeviceChallenge"("ceremonyId");

-- CreateIndex
CREATE INDEX "DeviceChallenge_userId_deviceIdHash_idx" ON "DeviceChallenge"("userId", "deviceIdHash");

-- CreateIndex
CREATE INDEX "DeviceChallenge_expiresAt_idx" ON "DeviceChallenge"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "TrustedDevice_deviceKey_key" ON "TrustedDevice"("deviceKey");

-- CreateIndex
CREATE INDEX "TrustedDevice_userId_status_idx" ON "TrustedDevice"("userId", "status");

-- CreateIndex
CREATE INDEX "TrustedDevice_rememberedUntil_idx" ON "TrustedDevice"("rememberedUntil");

-- CreateIndex
CREATE UNIQUE INDEX "TrustedDevice_userId_deviceIdHash_key" ON "TrustedDevice"("userId", "deviceIdHash");

-- CreateIndex
CREATE UNIQUE INDEX "AccountRecoveryRequest_requestKey_key" ON "AccountRecoveryRequest"("requestKey");

-- CreateIndex
CREATE INDEX "AccountRecoveryRequest_userId_status_idx" ON "AccountRecoveryRequest"("userId", "status");

-- CreateIndex
CREATE INDEX "AccountRecoveryRequest_expiresAt_idx" ON "AccountRecoveryRequest"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "AdministrativeCredential_userId_key" ON "AdministrativeCredential"("userId");

-- CreateIndex
CREATE INDEX "AdministrativeRecoveryCode_userId_usedAt_idx" ON "AdministrativeRecoveryCode"("userId", "usedAt");

-- CreateIndex
CREATE UNIQUE INDEX "AdministrativeRecoveryCode_userId_codeHash_key" ON "AdministrativeRecoveryCode"("userId", "codeHash");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityElevation_requestKey_key" ON "SecurityElevation"("requestKey");

-- CreateIndex
CREATE INDEX "SecurityElevation_userId_sessionId_scope_idx" ON "SecurityElevation"("userId", "sessionId", "scope");

-- CreateIndex
CREATE INDEX "SecurityElevation_status_expiresAt_idx" ON "SecurityElevation"("status", "expiresAt");

-- CreateIndex
CREATE INDEX "SecurityElevation_sessionId_idx" ON "SecurityElevation"("sessionId");

-- CreateIndex
CREATE UNIQUE INDEX "SanitizedAuditReference_referenceHash_key" ON "SanitizedAuditReference"("referenceHash");

-- CreateIndex
CREATE INDEX "SanitizedAuditReference_category_createdAt_idx" ON "SanitizedAuditReference"("category", "createdAt");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProjectConnection" ADD CONSTRAINT "ProjectConnection_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserProjectGrant" ADD CONSTRAINT "UserProjectGrant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserProjectGrant" ADD CONSTRAINT "UserProjectGrant_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "ProjectConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailDeliveryAttempt" ADD CONSTRAINT "EmailDeliveryAttempt_messageId_fkey" FOREIGN KEY ("messageId") REFERENCES "EmailOutboxMessage"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TotpFactor" ADD CONSTRAINT "TotpFactor_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RecoveryCode" ADD CONSTRAINT "RecoveryCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceChallenge" ADD CONSTRAINT "DeviceChallenge_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TrustedDevice" ADD CONSTRAINT "TrustedDevice_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccountRecoveryRequest" ADD CONSTRAINT "AccountRecoveryRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccountRecoveryRequest" ADD CONSTRAINT "AccountRecoveryRequest_reviewedByUserId_fkey" FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdministrativeCredential" ADD CONSTRAINT "AdministrativeCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdministrativeRecoveryCode" ADD CONSTRAINT "AdministrativeRecoveryCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityElevation" ADD CONSTRAINT "SecurityElevation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
