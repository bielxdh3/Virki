export const ELEVATION_SCOPES = [
  "ACCOUNT_APPLICATION_REVIEW",
  "ACCOUNT_ACTIVATION_REISSUE",
  "MODULE_ACCESS_CHANGE",
  "FEATURE_PERMISSION_CHANGE",
  "ACCOUNT_STATE_CHANGE",
  "GLOBAL_ROLE_CHANGE",
  "MODULE_CATALOG_CHANGE",
  "ADMIN_CREDENTIAL_CHANGE",
  "ADMIN_RECOVERY_REGENERATE",
  "PROJECT_OWNER_ACCESS_CHANGE",
  "CORE_PROJECT_ARCHIVE"
] as const;

export type ElevationScope = (typeof ELEVATION_SCOPES)[number];

export const ELEVATION_SCOPE_ACTIONS = {
  ACCOUNT_APPLICATION_REVIEW: { label: "Account application review", ui: true },
  ACCOUNT_ACTIVATION_REISSUE: { label: "Reissue account activation", ui: true },
  MODULE_ACCESS_CHANGE: { label: "Module access", ui: true },
  FEATURE_PERMISSION_CHANGE: { label: "Feature permission", ui: true },
  ACCOUNT_STATE_CHANGE: { label: "Account recovery approval", ui: true },
  GLOBAL_ROLE_CHANGE: { label: "Global role change", ui: false },
  MODULE_CATALOG_CHANGE: { label: "Module catalog change", ui: false },
  ADMIN_CREDENTIAL_CHANGE: { label: "Administrative credential change", ui: false },
  ADMIN_RECOVERY_REGENERATE: { label: "Administrative recovery regeneration", ui: false },
  PROJECT_OWNER_ACCESS_CHANGE: { label: "Core project access change", ui: true },
  CORE_PROJECT_ARCHIVE: { label: "Core project archive", ui: true }
} as const satisfies Record<ElevationScope, { label: string; ui: boolean }>;

export const UI_ELEVATION_SCOPES = ELEVATION_SCOPES.filter((scope) => ELEVATION_SCOPE_ACTIONS[scope].ui);
