const SAFE_AUDIT_EVENT_TYPES = new Set([
  "AUTH_LOGIN_SUCCESS",
  "AUTH_LOGIN_FAILURE",
  "AUTH_LOGOUT",
  "AUTH_SESSION_REVOKED",
  "AUTH_SESSION_CLEANUP",
  "AUTH_AUDIT_LOG_CLEANUP",
  "ACCESS_JWT_MISSING",
  "ACCESS_JWT_INVALID",
  "ACCESS_JWT_VALID",
  "OWNER_SEED_CREATED",
  "OWNER_SEED_UPDATED",
  "CORE_PROJECT_CREATED",
  "CORE_PROJECT_UPDATED",
  "CORE_PROJECT_ARCHIVED",
  "CORE_PROJECT_ACCESS_GRANTED",
  "CORE_PROJECT_ACCESS_CHANGED",
  "CORE_PROJECT_ACCESS_REVOKED",
  "GYMFORGE_PARTICIPANT_CREATED",
  "GYMFORGE_PARTICIPANT_STATUS_CHANGED",
  "GYMFORGE_EXERCISE_CREATED",
  "GYMFORGE_EXERCISE_STATUS_CHANGED",
  "GYMFORGE_ATTENDANCE_CHECKIN_CREATED",
  "GYMFORGE_ATTENDANCE_CORRECTION_CREATED",
  "GYMFORGE_ATTENDANCE_CORRECTION_REMOVED",
  "GYMFORGE_WORKOUT_CREATED",
  "GYMFORGE_WORKOUT_UPDATED",
  "GYMFORGE_WORKOUT_DELETED",
  "GYMFORGE_COMPETITION_CREATED",
  "GYMFORGE_COMPETITION_UPDATED",
  "GYMFORGE_COMPETITION_ARCHIVED",
  "GYMFORGE_COMPETITION_DELETED",
  "GYMFORGE_COMPETITION_ASSIGNMENT_UPDATED",
  "GYMFORGE_SCORE_CORRECTION_CREATED",
  "GYMFORGE_SCORE_CORRECTION_REVOKED"
]);

export type SafeAuditResult = "SUCCESS" | "FAILURE" | "INFO" | "OTHER";
export type SafeAuditActorState = "user" | "system";
export type SafeAuditResource =
  | "hub"
  | "session"
  | "project"
  | "project-access"
  | "application"
  | "system"
  | "other";

export function getSafeAuditEventType(eventType: string): string {
  return SAFE_AUDIT_EVENT_TYPES.has(eventType) ? eventType : "OTHER_EVENT";
}

export function getSafeAuditResult(result: string): SafeAuditResult {
  return result === "SUCCESS" || result === "FAILURE" || result === "INFO"
    ? result
    : "OTHER";
}

export function getSafeAuditActorState(actorUserId: string | null): SafeAuditActorState {
  return actorUserId ? "user" : "system";
}

export function getSafeAuditResource(resource: string | null): SafeAuditResource {
  if (!resource) {
    return "system";
  }

  if (resource === "hub") {
    return "hub";
  }

  if (resource === "session") {
    return "session";
  }

  if (resource === "core.project") {
    return "project";
  }

  if (resource === "core.project-access") {
    return "project-access";
  }

  if (resource.startsWith("gymforge.")) {
    return "application";
  }

  return "other";
}
