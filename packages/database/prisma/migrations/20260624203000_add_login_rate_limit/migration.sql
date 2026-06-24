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

-- CreateIndex
CREATE UNIQUE INDEX "LoginRateLimit_identifierHash_key" ON "LoginRateLimit"("identifierHash");

-- CreateIndex
CREATE INDEX "LoginRateLimit_blockedUntil_idx" ON "LoginRateLimit"("blockedUntil");

-- CreateIndex
CREATE INDEX "LoginRateLimit_expiresAt_idx" ON "LoginRateLimit"("expiresAt");
