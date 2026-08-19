import type { AuditEventType } from "@bielos/auth";

const SAFE_AUDIT_EVENT_TYPES = new Set<AuditEventType>([
  "AUTH_LOGIN_SUCCESS",
  "AUTH_LOGIN_FAILURE",
  "AUTH_LOGOUT",
  "AUTH_SESSION_REVOKED",
  "AUTH_SESSION_CLEANUP",
  "AUTH_AUDIT_LOG_CLEANUP",
  "ACCOUNT_APPLICATION_EMAIL_VERIFIED",
  "ACCOUNT_APPLICATION_REVIEWED",
  "ACCOUNT_ACTIVATED",
  "ACCOUNT_ACTIVATION_REISSUED",
  "MODULE_ACCESS_REQUESTED",
  "MODULE_ACCESS_REVIEWED",
  "FEATURE_PERMISSION_REQUESTED",
  "FEATURE_PERMISSION_REVIEWED",
  "MODULE_ACCESS_EXPIRED",
  "SECOND_FACTOR_ENROLLED",
  "SECOND_FACTOR_DISABLED",
  "RECOVERY_CODES_REGENERATED",
  "DEVICE_VERIFIED",
  "TRUSTED_DEVICE_REVOKED",
  "ACCOUNT_RECOVERY_REQUESTED",
  "ACCOUNT_RECOVERY_EMAIL_VERIFIED",
  "ACCOUNT_RECOVERY_APPROVED",
  "ACCOUNT_RECOVERY_CONSUMED",
  "ADMIN_CREDENTIAL_SETUP",
  "ADMIN_CREDENTIAL_CHANGED",
  "ADMIN_CREDENTIAL_RECOVERED",
  "ADMIN_ELEVATION_STARTED",
  "ADMIN_ELEVATION_ACTIVATED",
  "ADMIN_ELEVATION_REVOKED",
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

export const CORE_INFRASTRUCTURE_AUDIT_EVENT_TYPES = [
  "ACCESS_JWT_MISSING",
  "ACCESS_JWT_INVALID",
  "ACCESS_JWT_VALID"
] as const satisfies readonly AuditEventType[];

export type CoreAuditFilter = "activity" | "infrastructure";
export type SafeAuditEventType = AuditEventType | "OTHER_EVENT";

export type SafeAuditResult = "SUCCESS" | "FAILURE" | "INFO" | "OTHER";
export type SafeAuditActorState = "user" | "system";
export type SafeAuditResource =
  | "hub"
  | "access"
  | "session"
  | "project"
  | "project-access"
  | "application"
  | "security"
  | "system"
  | "other";

export function getSafeAuditEventType(eventType: string): SafeAuditEventType {
  return SAFE_AUDIT_EVENT_TYPES.has(eventType as AuditEventType)
    ? eventType as AuditEventType
    : "OTHER_EVENT";
}

export function normalizeCoreAuditFilter(value: string | undefined): CoreAuditFilter {
  return value === "infrastructure" ? "infrastructure" : "activity";
}

export function getSafeAuditResult(result: string): SafeAuditResult {
  return result === "SUCCESS" || result === "FAILURE" || result === "INFO"
    ? result
    : "OTHER";
}

export function getSafeAuditActorState(actorUserId: string | null): SafeAuditActorState {
  return actorUserId ? "user" : "system";
}

export function getSafeAuditResource(resource: string | null, eventType?: string): SafeAuditResource {
  if (eventType === "ACCESS_JWT_MISSING" || eventType === "ACCESS_JWT_INVALID" || eventType === "ACCESS_JWT_VALID") {
    return "access";
  }

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

  if (resource === "identity.application") {
    return "application";
  }

  if (resource.startsWith("identity.")) {
    return "security";
  }

  if (resource.startsWith("gymforge.")) {
    return "application";
  }

  return "other";
}
