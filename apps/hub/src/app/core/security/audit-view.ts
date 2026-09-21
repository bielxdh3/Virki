import type { AuditEventType } from "@bielos/auth";

const SAFE_AUDIT_EVENT_TYPES = new Set<AuditEventType>([
  "AUTH_LOGIN_SUCCESS",
  "AUTH_LOGIN_FAILURE",
  "AUTH_LOGOUT",
  "AUTH_SESSION_REVOKED",
  "AUTH_SESSION_CLEANUP",
  "AUTH_AUDIT_LOG_CLEANUP",
  "AUDIT_LOG_EXPORTED",
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
export type SafeAuditCategory = "auth" | "account" | "access" | "project" | "admin" | "session" | "system" | "ops" | "module" | "other";

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

export function getAuditRangeLabel(start: number, end: number, total: number, locale: "pt-BR" | "en"): string {
  if (start <= 0 || end <= 0 || total <= 0) return locale === "pt-BR" ? "0 eventos" : "0 events";
  return `${start}–${end} ${locale === "pt-BR" ? "de" : "of"} ${total}`;
}

export function getSafeAuditEventType(eventType: string): SafeAuditEventType {
  return SAFE_AUDIT_EVENT_TYPES.has(eventType as AuditEventType)
    ? eventType as AuditEventType
    : "OTHER_EVENT";
}

export function getSafeAuditCategory(eventType: string, resource: string | null = null): SafeAuditCategory {
  if (eventType.startsWith("AUTH_")) return "auth";
  if (eventType.startsWith("ACCESS_JWT_") || eventType.startsWith("CORE_PROJECT_ACCESS_")) return "access";
  if (eventType.startsWith("CORE_PROJECT_")) return "project";
  if (eventType.startsWith("ADMIN_")) return "admin";
  if (eventType.startsWith("GYMFORGE_") || eventType.startsWith("MODULE_") || eventType.startsWith("FEATURE_")) return "module";
  if (eventType.startsWith("ACCOUNT_") || eventType.startsWith("SECOND_FACTOR_") || eventType.startsWith("RECOVERY_")) return "account";
  if (eventType.includes("SESSION") || resource === "session") return "session";
  if (eventType.startsWith("OWNER_") || eventType.startsWith("AUDIT_")) return "ops";
  if (resource === "system") return "system";
  if (resource?.startsWith("identity.")) return "account";
  return "other";
}

const SAFE_AUDIT_EVENT_LABELS: Partial<Record<AuditEventType, string>> = {
  AUTH_LOGIN_SUCCESS: "Login concluído",
  AUTH_LOGIN_FAILURE: "Falha de login",
  AUTH_LOGOUT: "Logout",
  AUTH_SESSION_REVOKED: "Sessão revogada",
  AUTH_SESSION_CLEANUP: "Limpeza de sessões",
  AUDIT_LOG_EXPORTED: "Exportação de auditoria",
  ACCESS_JWT_MISSING: "Acesso externo ausente",
  ACCESS_JWT_INVALID: "Acesso externo recusado",
  ACCESS_JWT_VALID: "Acesso externo validado",
  CORE_PROJECT_CREATED: "Projeto criado",
  CORE_PROJECT_UPDATED: "Projeto atualizado",
  CORE_PROJECT_ARCHIVED: "Projeto arquivado",
  CORE_PROJECT_ACCESS_GRANTED: "Acesso concedido",
  CORE_PROJECT_ACCESS_CHANGED: "Acesso alterado",
  CORE_PROJECT_ACCESS_REVOKED: "Acesso revogado",
  ADMIN_ELEVATION_STARTED: "Confirmação administrativa iniciada",
  ADMIN_ELEVATION_ACTIVATED: "Confirmação administrativa ativa",
  ADMIN_ELEVATION_REVOKED: "Confirmação administrativa revogada",
  ACCOUNT_RECOVERY_REQUESTED: "Recuperação solicitada",
  ACCOUNT_RECOVERY_CONSUMED: "Recuperação concluída",
  MODULE_ACCESS_REQUESTED: "Acesso de módulo solicitado",
  MODULE_ACCESS_REVIEWED: "Acesso de módulo revisado"
};

const SAFE_AUDIT_EVENT_LABELS_EN: Partial<Record<AuditEventType, string>> = {
  AUTH_LOGIN_SUCCESS: "Login completed",
  AUTH_LOGIN_FAILURE: "Login failed",
  AUTH_LOGOUT: "Logout",
  AUTH_SESSION_REVOKED: "Session revoked",
  AUTH_SESSION_CLEANUP: "Session cleanup",
  AUDIT_LOG_EXPORTED: "Audit export",
  ACCESS_JWT_MISSING: "External access missing",
  ACCESS_JWT_INVALID: "External access denied",
  ACCESS_JWT_VALID: "External access validated",
  CORE_PROJECT_CREATED: "Project created",
  CORE_PROJECT_UPDATED: "Project updated",
  CORE_PROJECT_ARCHIVED: "Project archived",
  CORE_PROJECT_ACCESS_GRANTED: "Access granted",
  CORE_PROJECT_ACCESS_CHANGED: "Access changed",
  CORE_PROJECT_ACCESS_REVOKED: "Access revoked",
  ADMIN_ELEVATION_STARTED: "Administrative confirmation started",
  ADMIN_ELEVATION_ACTIVATED: "Administrative confirmation active",
  ADMIN_ELEVATION_REVOKED: "Administrative confirmation revoked",
  ACCOUNT_RECOVERY_REQUESTED: "Recovery requested",
  ACCOUNT_RECOVERY_CONSUMED: "Recovery completed",
  MODULE_ACCESS_REQUESTED: "Module access requested",
  MODULE_ACCESS_REVIEWED: "Module access reviewed"
};

export function getSafeAuditEventLabel(eventType: string, locale: "pt-BR" | "en" = "pt-BR"): string {
  const known = (locale === "en" ? SAFE_AUDIT_EVENT_LABELS_EN : SAFE_AUDIT_EVENT_LABELS)[eventType as AuditEventType];
  if (known) return known;
  if (getSafeAuditEventType(eventType) === "OTHER_EVENT" || eventType === "OTHER_EVENT") return locale === "en" ? "Other event" : "Outro evento";
  return eventType
    .toLocaleLowerCase("pt-BR")
    .split("_")
    .map((part) => part.charAt(0).toLocaleUpperCase("pt-BR") + part.slice(1))
    .join(" ");
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

  if (resource === "identity.module" || resource === "identity.permission") {
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
