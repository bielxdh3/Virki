"use server";

import { validateCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { writeAuditLog } from "@bielos/auth";
import { prisma } from "@bielos/database";
import { revalidatePath } from "next/cache";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";

const PARTICIPANT_ROLES = ["ADMIN", "PARTICIPANT"] as const;
const PARTICIPANT_STATUSES = ["INVITED", "ACTIVE", "DISABLED", "ARCHIVED"] as const;

type ParticipantRole = (typeof PARTICIPANT_ROLES)[number];
type ParticipantStatus = (typeof PARTICIPANT_STATUSES)[number];

function isHubAdmin(role: string): boolean {
  return role === "OWNER" || role === "ADMIN";
}

function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function getLocalDayStart(now = new Date()): Date {
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

function isParticipantRole(value: string): value is ParticipantRole {
  return PARTICIPANT_ROLES.includes(value as ParticipantRole);
}

function isParticipantStatus(value: string): value is ParticipantStatus {
  return PARTICIPANT_STATUSES.includes(value as ParticipantStatus);
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

  const effectiveDate = getLocalDayStart();
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
      effectiveDate: attendance.effectiveDate.toISOString().slice(0, 10),
      countsForStreak: attendance.countsForStreak
    }
  });

  revalidatePath("/gymforge");
  redirect("/gymforge");
}
