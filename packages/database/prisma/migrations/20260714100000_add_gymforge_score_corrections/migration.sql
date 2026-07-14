CREATE TABLE "GymForgeCompetitionScoreCorrection" (
    "id" TEXT NOT NULL,
    "competitionId" TEXT NOT NULL,
    "participantId" TEXT NOT NULL,
    "pointsDelta" INTEGER NOT NULL,
    "reason" TEXT,
    "requestKey" TEXT NOT NULL,
    "createdByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "revokedByUserId" TEXT,

    CONSTRAINT "GymForgeCompetitionScoreCorrection_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "GymForgeCompetitionScoreCorrection_pointsDelta_check"
      CHECK ("pointsDelta" <> 0 AND "pointsDelta" BETWEEN -1000 AND 1000),
    CONSTRAINT "GymForgeCompetitionScoreCorrection_reason_check"
      CHECK ("reason" IS NULL OR char_length("reason") <= 240),
    CONSTRAINT "GymForgeCompetitionScoreCorrection_requestKey_check"
      CHECK (char_length("requestKey") BETWEEN 20 AND 100),
    CONSTRAINT "GymForgeCompetitionScoreCorrection_revocation_check"
      CHECK (
        ("revokedAt" IS NULL AND "revokedByUserId" IS NULL)
        OR "revokedAt" IS NOT NULL
      ),
    CONSTRAINT "GymForgeCompetitionScoreCorrection_revokedAt_check"
      CHECK ("revokedAt" IS NULL OR "revokedAt" >= "createdAt")
);

CREATE UNIQUE INDEX "GymForgeCompetitionScoreCorrection_requestKey_key"
ON "GymForgeCompetitionScoreCorrection"("requestKey");

CREATE INDEX "GymForgeScoreCorrection_active_pair_idx"
ON "GymForgeCompetitionScoreCorrection"("competitionId", "participantId", "revokedAt");

CREATE INDEX "GymForgeCompetitionScoreCorrection_competitionId_createdAt_idx"
ON "GymForgeCompetitionScoreCorrection"("competitionId", "createdAt");

CREATE INDEX "GymForgeCompetitionScoreCorrection_participantId_createdAt_idx"
ON "GymForgeCompetitionScoreCorrection"("participantId", "createdAt");

CREATE INDEX "GymForgeCompetitionScoreCorrection_createdByUserId_idx"
ON "GymForgeCompetitionScoreCorrection"("createdByUserId");

CREATE INDEX "GymForgeCompetitionScoreCorrection_revokedByUserId_idx"
ON "GymForgeCompetitionScoreCorrection"("revokedByUserId");

ALTER TABLE "GymForgeCompetitionScoreCorrection"
ADD CONSTRAINT "GymForgeCompetitionScoreCorrection_competitionId_fkey"
FOREIGN KEY ("competitionId") REFERENCES "GymForgeCompetition"("id")
ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "GymForgeCompetitionScoreCorrection"
ADD CONSTRAINT "GymForgeCompetitionScoreCorrection_participantId_fkey"
FOREIGN KEY ("participantId") REFERENCES "GymForgeParticipant"("id")
ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "GymForgeCompetitionScoreCorrection"
ADD CONSTRAINT "GymForgeCompetitionScoreCorrection_createdByUserId_fkey"
FOREIGN KEY ("createdByUserId") REFERENCES "User"("id")
ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "GymForgeCompetitionScoreCorrection"
ADD CONSTRAINT "GymForgeCompetitionScoreCorrection_revokedByUserId_fkey"
FOREIGN KEY ("revokedByUserId") REFERENCES "User"("id")
ON DELETE SET NULL ON UPDATE CASCADE;
