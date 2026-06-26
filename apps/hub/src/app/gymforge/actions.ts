"use server";

import { validateCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { writeAuditLog } from "@bielos/auth";
import { prisma } from "@bielos/database";
import { revalidatePath } from "next/cache";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { formatGymForgeAttendanceDate, getGymForgeAttendanceEffectiveDate } from "./dates";

const PARTICIPANT_ROLES = ["ADMIN", "PARTICIPANT"] as const;
const PARTICIPANT_STATUSES = ["INVITED", "ACTIVE", "DISABLED", "ARCHIVED"] as const;
const COMPETITION_STATUSES = ["DRAFT", "ACTIVE", "ENDED", "ARCHIVED"] as const;
const EDITABLE_COMPETITION_STATUSES = ["DRAFT", "ACTIVE", "ENDED"] as const;
const COMPETITION_SCORING_RULES = [
  "ATTENDANCE_COUNT",
  "CURRENT_STREAK",
  "LONGEST_STREAK",
  "ATTENDANCE_PLUS_LONGEST_STREAK"
] as const;
const WORKOUT_UNITS = ["KG", "LB", "BODYWEIGHT", "OTHER"] as const;

type ParticipantRole = (typeof PARTICIPANT_ROLES)[number];
type ParticipantStatus = (typeof PARTICIPANT_STATUSES)[number];
type CompetitionStatus = (typeof COMPETITION_STATUSES)[number];
type EditableCompetitionStatus = (typeof EDITABLE_COMPETITION_STATUSES)[number];
type CompetitionScoringRule = (typeof COMPETITION_SCORING_RULES)[number];
type WorkoutUnit = (typeof WORKOUT_UNITS)[number];
type ParsedOptionalDate = Date | null | "invalid";

function isHubAdmin(role: string): boolean {
  return role === "OWNER" || role === "ADMIN";
}

function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function isParticipantRole(value: string): value is ParticipantRole {
  return PARTICIPANT_ROLES.includes(value as ParticipantRole);
}

function isParticipantStatus(value: string): value is ParticipantStatus {
  return PARTICIPANT_STATUSES.includes(value as ParticipantStatus);
}

function isCompetitionStatus(value: string): value is CompetitionStatus {
  return COMPETITION_STATUSES.includes(value as CompetitionStatus);
}

function isEditableCompetitionStatus(value: string): value is EditableCompetitionStatus {
  return EDITABLE_COMPETITION_STATUSES.includes(value as EditableCompetitionStatus);
}

function isCompetitionScoringRule(value: string): value is CompetitionScoringRule {
  return COMPETITION_SCORING_RULES.includes(value as CompetitionScoringRule);
}

function isWorkoutUnit(value: string): value is WorkoutUnit {
  return WORKOUT_UNITS.includes(value as WorkoutUnit);
}

function parsePositiveInteger(value: string, max: number): number | null {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= max ? parsed : null;
}

function parseLoad(value: string): string | null {
  if (!value) {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 1000 ? value : null;
}

function parseOptionalDate(value: string): ParsedOptionalDate {
  if (!value) {
    return null;
  }

  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);

  if (!match) {
    return "invalid";
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));

  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return "invalid";
  }

  return date;
}

async function requireGymForgeAdmin(formData: FormData) {
  const csrfResult = validateCsrfToken(readFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  if (!isHubAdmin(session.user.role)) {
    forbidden();
  }

  return session;
}

export async function createGymForgeParticipant(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const displayName = readFormString(formData, "displayName");
  const role = readFormString(formData, "role");
  const status = readFormString(formData, "status");

  if (displayName.length < 2 || displayName.length > 80) {
    redirect("/gymforge?error=participant-name");
  }

  if (!isParticipantRole(role) || !isParticipantStatus(status)) {
    redirect("/gymforge?error=participant-choice");
  }

  const participant = await prisma.gymForgeParticipant.create({
    data: {
      displayName,
      role,
      status
    },
    select: { id: true, role: true, status: true }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_PARTICIPANT_CREATED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.participant",
    message: "GymForge participant created.",
    metadata: {
      participantId: participant.id,
      role: participant.role,
      status: participant.status
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function changeGymForgeParticipantStatus(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const participantId = readFormString(formData, "participantId");
  const status = readFormString(formData, "status");

  if (!participantId || !isParticipantStatus(status)) {
    redirect("/gymforge?error=participant-status");
  }

  const participant = await prisma.gymForgeParticipant.update({
    where: { id: participantId },
    data: {
      status,
      archivedAt: status === "ARCHIVED" ? new Date() : null
    },
    select: { id: true, status: true }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_PARTICIPANT_STATUS_CHANGED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.participant",
    message: "GymForge participant status changed.",
    metadata: {
      participantId: participant.id,
      status: participant.status
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function createGymForgeExercise(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const name = readFormString(formData, "name");
  const category = readFormString(formData, "category");
  const description = readFormString(formData, "description");
  const isActive = readFormString(formData, "isActive") === "true";

  if (name.length < 2 || name.length > 100) {
    redirect("/gymforge?error=exercise-name");
  }

  if (category.length > 80 || description.length > 240) {
    redirect("/gymforge?error=exercise-details");
  }

  const exercise = await prisma.gymForgeExercise.create({
    data: {
      name,
      category: category || null,
      description: description || null,
      isActive
    },
    select: { id: true, isActive: true }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_EXERCISE_CREATED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.exercise",
    message: "GymForge exercise created.",
    metadata: {
      exerciseId: exercise.id,
      isActive: exercise.isActive
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function changeGymForgeExerciseStatus(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const exerciseId = readFormString(formData, "exerciseId");
  const action = readFormString(formData, "action");

  if (!exerciseId || (action !== "deactivate" && action !== "archive")) {
    redirect("/gymforge?error=exercise-status");
  }

  const exercise = await prisma.gymForgeExercise.update({
    where: { id: exerciseId },
    data: {
      isActive: false,
      archivedAt: action === "archive" ? new Date() : null
    },
    select: { id: true, isActive: true, archivedAt: true }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_EXERCISE_STATUS_CHANGED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.exercise",
    message: "GymForge exercise status changed.",
    metadata: {
      exerciseId: exercise.id,
      isActive: exercise.isActive,
      archived: Boolean(exercise.archivedAt)
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function createGymForgeCompetition(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const name = readFormString(formData, "name");
  const description = readFormString(formData, "description");
  const status = readFormString(formData, "status");
  const startsAtResult = parseOptionalDate(readFormString(formData, "startsAt"));
  const endsAtResult = parseOptionalDate(readFormString(formData, "endsAt"));
  const scoringRule = readFormString(formData, "scoringRule");

  if (name.length < 2 || name.length > 100) {
    redirect("/gymforge?error=competition-name");
  }

  if (description.length > 240 || scoringRule.length < 2 || scoringRule.length > 120) {
    redirect("/gymforge?error=competition-details");
  }

  if (!isCompetitionScoringRule(scoringRule)) {
    redirect("/gymforge?error=competition-scoring");
  }

  if (!isCompetitionStatus(status)) {
    redirect("/gymforge?error=competition-status");
  }

  if (startsAtResult === "invalid" || endsAtResult === "invalid") {
    redirect("/gymforge?error=competition-dates");
  }

  const startsAt = startsAtResult;
  const endsAt = endsAtResult;

  if (startsAt && endsAt && startsAt.getTime() > endsAt.getTime()) {
    redirect("/gymforge?error=competition-dates");
  }

  if (status === "ACTIVE" && (!startsAt || !endsAt)) {
    redirect("/gymforge?error=competition-dates");
  }

  const competition = await prisma.gymForgeCompetition.create({
    data: {
      name,
      description: description || null,
      status,
      startsAt,
      endsAt,
      scoringRule
    },
    select: {
      id: true,
      status: true,
      startsAt: true,
      endsAt: true
    }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_COMPETITION_CREATED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.competition",
    message: "GymForge competition created.",
    metadata: {
      competitionId: competition.id,
      status: competition.status,
      hasDateRange: Boolean(competition.startsAt || competition.endsAt)
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function updateGymForgeCompetitionAssignments(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const competitionId = readFormString(formData, "competitionId");
  const selectedParticipantIds = formData
    .getAll("participantId")
    .filter((value): value is string => typeof value === "string" && Boolean(value));

  if (!competitionId) {
    redirect("/gymforge?error=competition-assignment");
  }

  const uniqueSelectedParticipantIds = Array.from(new Set(selectedParticipantIds));

  const [competition, activeParticipants] = await Promise.all([
    prisma.gymForgeCompetition.findUnique({
      where: { id: competitionId },
      select: { id: true }
    }),
    prisma.gymForgeParticipant.findMany({
      where: {
        id: { in: uniqueSelectedParticipantIds },
        status: "ACTIVE"
      },
      select: { id: true }
    })
  ]);

  if (!competition) {
    redirect("/gymforge?error=competition-assignment");
  }

  const activeParticipantIds = new Set(activeParticipants.map((participant) => participant.id));

  if (activeParticipantIds.size !== uniqueSelectedParticipantIds.length) {
    redirect("/gymforge?error=competition-assignment");
  }

  await prisma.$transaction(async (transaction) => {
    await transaction.gymForgeCompetitionAssignment.deleteMany({
      where: {
        competitionId,
        participantId: {
          notIn: uniqueSelectedParticipantIds
        }
      }
    });

    await Promise.all(
      uniqueSelectedParticipantIds.map((participantId) =>
        transaction.gymForgeCompetitionAssignment.upsert({
          where: {
            competitionId_participantId: {
              competitionId,
              participantId
            }
          },
          update: {},
          create: {
            competitionId,
            participantId
          }
        })
      )
    );
  });

  await writeAuditLog({
    eventType: "GYMFORGE_COMPETITION_ASSIGNMENT_UPDATED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.competition",
    message: "GymForge competition assignments updated.",
    metadata: {
      competitionId,
      assignedCount: uniqueSelectedParticipantIds.length
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function updateGymForgeCompetition(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const competitionId = readFormString(formData, "competitionId");
  const name = readFormString(formData, "name");
  const description = readFormString(formData, "description");
  const status = readFormString(formData, "status");
  const startsAtResult = parseOptionalDate(readFormString(formData, "startsAt"));
  const endsAtResult = parseOptionalDate(readFormString(formData, "endsAt"));
  const scoringRule = readFormString(formData, "scoringRule");

  if (!competitionId) {
    redirect("/gymforge?error=competition-update");
  }

  if (name.length < 2 || name.length > 100) {
    redirect("/gymforge?error=competition-name");
  }

  if (description.length > 240 || scoringRule.length < 2 || scoringRule.length > 120) {
    redirect("/gymforge?error=competition-details");
  }

  if (!isEditableCompetitionStatus(status)) {
    redirect("/gymforge?error=competition-status");
  }

  if (!isCompetitionScoringRule(scoringRule)) {
    redirect("/gymforge?error=competition-scoring");
  }

  if (startsAtResult === "invalid" || endsAtResult === "invalid") {
    redirect("/gymforge?error=competition-dates");
  }

  const startsAt = startsAtResult;
  const endsAt = endsAtResult;

  if (startsAt && endsAt && startsAt.getTime() > endsAt.getTime()) {
    redirect("/gymforge?error=competition-dates");
  }

  if (status === "ACTIVE" && (!startsAt || !endsAt)) {
    redirect("/gymforge?error=competition-dates");
  }

  const competition = await prisma.gymForgeCompetition.update({
    where: { id: competitionId },
    data: {
      name,
      description: description || null,
      status,
      startsAt,
      endsAt,
      scoringRule,
      archivedAt: null
    },
    select: {
      id: true,
      status: true,
      startsAt: true,
      endsAt: true,
      scoringRule: true
    }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_COMPETITION_UPDATED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.competition",
    message: "GymForge competition updated.",
    metadata: {
      competitionId: competition.id,
      status: competition.status,
      hasDateRange: Boolean(competition.startsAt || competition.endsAt),
      scoringRule: competition.scoringRule
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function archiveGymForgeCompetition(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const competitionId = readFormString(formData, "competitionId");

  if (!competitionId) {
    redirect("/gymforge?error=competition-archive");
  }

  const competition = await prisma.gymForgeCompetition.update({
    where: { id: competitionId },
    data: {
      status: "ARCHIVED",
      archivedAt: new Date()
    },
    select: {
      id: true,
      status: true,
      archivedAt: true
    }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_COMPETITION_ARCHIVED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.competition",
    message: "GymForge competition archived.",
    metadata: {
      competitionId: competition.id,
      status: competition.status,
      archived: Boolean(competition.archivedAt)
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function deleteGymForgeCompetition(formData: FormData) {
  const session = await requireGymForgeAdmin(formData);
  const competitionId = readFormString(formData, "competitionId");
  const confirmed = readFormString(formData, "confirmDelete") === "true";

  if (!competitionId || !confirmed) {
    redirect("/gymforge?error=competition-delete");
  }

  const result = await prisma.gymForgeCompetition.deleteMany({
    where: {
      id: competitionId,
      status: { not: "ACTIVE" },
      assignments: {
        none: {}
      }
    }
  });

  if (result.count !== 1) {
    redirect("/gymforge?error=competition-delete");
  }

  await writeAuditLog({
    eventType: "GYMFORGE_COMPETITION_DELETED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.competition",
    message: "GymForge competition deleted.",
    metadata: {
      competitionId,
      deleted: true
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function createGymForgeAttendanceCheckIn(formData: FormData) {
  const csrfResult = validateCsrfToken(readFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const note = readFormString(formData, "note");

  if (note.length > 160) {
    redirect("/gymforge?error=checkin-note");
  }

  const participant = await prisma.gymForgeParticipant.findUnique({
    where: { userId: session.user.id },
    select: { id: true, status: true }
  });

  if (!participant || participant.status !== "ACTIVE") {
    forbidden();
  }

  const effectiveDate = getGymForgeAttendanceEffectiveDate();
  const existingAttendance = await prisma.gymForgeAttendance.findUnique({
    where: {
      participantId_effectiveDate: {
        participantId: participant.id,
        effectiveDate
      }
    },
    select: { id: true }
  });

  if (existingAttendance) {
    revalidatePath("/gymforge");
    redirect("/gymforge");
  }

  const attendance = await prisma.gymForgeAttendance.create({
    data: {
      participantId: participant.id,
      effectiveDate,
      note: note || null,
      countsForStreak: true
    },
    select: {
      participantId: true,
      effectiveDate: true,
      countsForStreak: true
    }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_ATTENDANCE_CHECKIN_CREATED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.attendance",
    message: "GymForge attendance check-in created.",
    metadata: {
      participantId: attendance.participantId,
      effectiveDate: formatGymForgeAttendanceDate(attendance.effectiveDate),
      countsForStreak: attendance.countsForStreak
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}

export async function createGymForgeWorkout(formData: FormData) {
  const csrfResult = validateCsrfToken(readFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const participant = await prisma.gymForgeParticipant.findUnique({
    where: { userId: session.user.id },
    select: { id: true, status: true }
  });

  if (!participant || participant.status !== "ACTIVE") {
    forbidden();
  }

  const note = readFormString(formData, "workoutNote");
  const setNote = readFormString(formData, "setNote");
  const exerciseId = readFormString(formData, "exerciseId");
  const setNumber = parsePositiveInteger(readFormString(formData, "setNumber"), 50);
  const reps = parsePositiveInteger(readFormString(formData, "reps"), 500);
  const load = parseLoad(readFormString(formData, "load"));
  const unit = readFormString(formData, "unit");

  if (note.length > 240 || setNote.length > 160) {
    redirect("/gymforge?error=workout-note");
  }

  if (!exerciseId || !setNumber || !reps || !isWorkoutUnit(unit)) {
    redirect("/gymforge?error=workout-set");
  }

  const exercise = await prisma.gymForgeExercise.findFirst({
    where: {
      id: exerciseId,
      isActive: true,
      archivedAt: null
    },
    select: { id: true }
  });

  if (!exercise) {
    redirect("/gymforge?error=workout-exercise");
  }

  const workout = await prisma.gymForgeWorkout.create({
    data: {
      participantId: participant.id,
      note: note || null,
      sets: {
        create: {
          exerciseId: exercise.id,
          setNumber,
          reps,
          load,
          unit,
          note: setNote || null
        }
      }
    },
    select: {
      id: true,
      participantId: true,
      _count: {
        select: { sets: true }
      }
    }
  });

  await writeAuditLog({
    eventType: "GYMFORGE_WORKOUT_CREATED",
    result: "SUCCESS",
    actorUserId: session.user.id,
    resource: "gymforge.workout",
    message: "GymForge workout created.",
    metadata: {
      participantId: workout.participantId,
      workoutId: workout.id,
      setCount: workout._count.sets
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}
