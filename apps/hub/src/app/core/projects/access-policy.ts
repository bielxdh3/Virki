export const CORE_PROJECT_ACCESS_LEVELS = ["VIEWER", "EDITOR", "OWNER"] as const;

export type CoreProjectAccessLevel = (typeof CORE_PROJECT_ACCESS_LEVELS)[number];

export function isCoreProjectAccessLevel(value: string): value is CoreProjectAccessLevel {
  return CORE_PROJECT_ACCESS_LEVELS.includes(value as CoreProjectAccessLevel);
}

export function canSetCoreProjectAccess(
  actorRole: string,
  requestedLevel: CoreProjectAccessLevel,
  existingLevel: CoreProjectAccessLevel | null
): boolean {
  if (actorRole === "OWNER") {
    return true;
  }

  return (
    actorRole === "ADMIN" &&
    requestedLevel !== "OWNER" &&
    existingLevel !== "OWNER"
  );
}

export function canRevokeCoreProjectAccess(
  actorRole: string,
  existingLevel: CoreProjectAccessLevel
): boolean {
  return actorRole === "OWNER" || (actorRole === "ADMIN" && existingLevel !== "OWNER");
}

export function requiresActiveOwnerRetentionCheck(
  existingLevel: CoreProjectAccessLevel,
  targetUserIsActive: boolean
): boolean {
  return existingLevel === "OWNER" && targetUserIsActive;
}
