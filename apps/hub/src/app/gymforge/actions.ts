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
