-- GymForge MVP foundation schema only.
CREATE TYPE "GymForgeParticipantStatus" AS ENUM ('INVITED', 'ACTIVE', 'DISABLED', 'ARCHIVED');
CREATE TYPE "GymForgeParticipantRole" AS ENUM ('ADMIN', 'PARTICIPANT');
CREATE TYPE "GymForgeWorkoutUnit" AS ENUM ('KG', 'LB', 'BODYWEIGHT', 'OTHER');
CREATE TYPE "GymForgeCompetitionStatus" AS ENUM ('DRAFT', 'ACTIVE', 'ENDED', 'ARCHIVED');

CREATE TABLE "GymForgeParticipant" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "displayName" TEXT NOT NULL,
    "status" "GymForgeParticipantStatus" NOT NULL DEFAULT 'INVITED',
    "role" "GymForgeParticipantRole" NOT NULL DEFAULT 'PARTICIPANT',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "archivedAt" TIMESTAMP(3),

    CONSTRAINT "GymForgeParticipant_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "GymForgeExercise" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "category" TEXT,
    "description" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "archivedAt" TIMESTAMP(3),

    CONSTRAINT "GymForgeExercise_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "GymForgeAttendance" (
    "id" TEXT NOT NULL,
    "participantId" TEXT NOT NULL,
    "checkedInAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "effectiveDate" TIMESTAMP(3) NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'manual',
    "note" TEXT,
    "countsForStreak" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GymForgeAttendance_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "GymForgeWorkout" (
    "id" TEXT NOT NULL,
    "participantId" TEXT NOT NULL,
    "workoutAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "note" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GymForgeWorkout_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "GymForgeWorkoutSet" (
    "id" TEXT NOT NULL,
    "workoutId" TEXT NOT NULL,
    "exerciseId" TEXT NOT NULL,
    "setNumber" INTEGER NOT NULL,
    "reps" INTEGER NOT NULL,
    "load" DECIMAL(65,30),
    "unit" "GymForgeWorkoutUnit" NOT NULL DEFAULT 'KG',
    "note" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GymForgeWorkoutSet_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "GymForgeCompetition" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "status" "GymForgeCompetitionStatus" NOT NULL DEFAULT 'DRAFT',
    "startsAt" TIMESTAMP(3),
    "endsAt" TIMESTAMP(3),
    "scoringRule" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "archivedAt" TIMESTAMP(3),

    CONSTRAINT "GymForgeCompetition_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "GymForgeParticipant_userId_key" ON "GymForgeParticipant"("userId");
CREATE INDEX "GymForgeParticipant_status_idx" ON "GymForgeParticipant"("status");
CREATE INDEX "GymForgeParticipant_role_idx" ON "GymForgeParticipant"("role");
CREATE INDEX "GymForgeParticipant_createdAt_idx" ON "GymForgeParticipant"("createdAt");

CREATE UNIQUE INDEX "GymForgeExercise_name_key" ON "GymForgeExercise"("name");
CREATE INDEX "GymForgeExercise_isActive_idx" ON "GymForgeExercise"("isActive");
CREATE INDEX "GymForgeExercise_category_idx" ON "GymForgeExercise"("category");

CREATE UNIQUE INDEX "GymForgeAttendance_participantId_effectiveDate_key" ON "GymForgeAttendance"("participantId", "effectiveDate");
CREATE INDEX "GymForgeAttendance_effectiveDate_idx" ON "GymForgeAttendance"("effectiveDate");
CREATE INDEX "GymForgeAttendance_countsForStreak_idx" ON "GymForgeAttendance"("countsForStreak");

CREATE INDEX "GymForgeWorkout_participantId_workoutAt_idx" ON "GymForgeWorkout"("participantId", "workoutAt");
CREATE INDEX "GymForgeWorkout_workoutAt_idx" ON "GymForgeWorkout"("workoutAt");

CREATE UNIQUE INDEX "GymForgeWorkoutSet_workoutId_exerciseId_setNumber_key" ON "GymForgeWorkoutSet"("workoutId", "exerciseId", "setNumber");
CREATE INDEX "GymForgeWorkoutSet_exerciseId_idx" ON "GymForgeWorkoutSet"("exerciseId");

CREATE INDEX "GymForgeCompetition_status_idx" ON "GymForgeCompetition"("status");
CREATE INDEX "GymForgeCompetition_startsAt_idx" ON "GymForgeCompetition"("startsAt");
CREATE INDEX "GymForgeCompetition_endsAt_idx" ON "GymForgeCompetition"("endsAt");

ALTER TABLE "GymForgeParticipant" ADD CONSTRAINT "GymForgeParticipant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "GymForgeAttendance" ADD CONSTRAINT "GymForgeAttendance_participantId_fkey" FOREIGN KEY ("participantId") REFERENCES "GymForgeParticipant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "GymForgeWorkout" ADD CONSTRAINT "GymForgeWorkout_participantId_fkey" FOREIGN KEY ("participantId") REFERENCES "GymForgeParticipant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "GymForgeWorkoutSet" ADD CONSTRAINT "GymForgeWorkoutSet_workoutId_fkey" FOREIGN KEY ("workoutId") REFERENCES "GymForgeWorkout"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "GymForgeWorkoutSet" ADD CONSTRAINT "GymForgeWorkoutSet_exerciseId_fkey" FOREIGN KEY ("exerciseId") REFERENCES "GymForgeExercise"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
