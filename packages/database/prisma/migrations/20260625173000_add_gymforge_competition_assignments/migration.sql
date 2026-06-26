CREATE TABLE "GymForgeCompetitionAssignment" (
    "id" TEXT NOT NULL,
    "competitionId" TEXT NOT NULL,
    "participantId" TEXT NOT NULL,
    "assignedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GymForgeCompetitionAssignment_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "GymForgeCompetitionAssignment_competitionId_participantId_key" ON "GymForgeCompetitionAssignment"("competitionId", "participantId");
CREATE INDEX "GymForgeCompetitionAssignment_competitionId_idx" ON "GymForgeCompetitionAssignment"("competitionId");
CREATE INDEX "GymForgeCompetitionAssignment_participantId_idx" ON "GymForgeCompetitionAssignment"("participantId");

ALTER TABLE "GymForgeCompetitionAssignment" ADD CONSTRAINT "GymForgeCompetitionAssignment_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "GymForgeCompetition"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "GymForgeCompetitionAssignment" ADD CONSTRAINT "GymForgeCompetitionAssignment_participantId_fkey" FOREIGN KEY ("participantId") REFERENCES "GymForgeParticipant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
