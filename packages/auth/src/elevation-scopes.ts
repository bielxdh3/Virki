export const ELEVATION_SCOPES = [
  "ACCOUNT_STATE_CHANGE",
  "PROJECT_ACCESS_CHANGE",
  "PROJECT_CONNECTION_MANAGE",
  "ADMIN_CREDENTIAL_CHANGE",
  "ADMIN_RECOVERY_REGENERATE"
] as const;

export type ElevationScope = (typeof ELEVATION_SCOPES)[number];

export const ELEVATION_SCOPE_ACTIONS = {
  ACCOUNT_STATE_CHANGE: { label: "Account state change", ui: true },
  PROJECT_ACCESS_CHANGE: { label: "Project access change", ui: true },
  PROJECT_CONNECTION_MANAGE: { label: "Project connection change", ui: true },
  ADMIN_CREDENTIAL_CHANGE: { label: "Admin credential change", ui: true },
  ADMIN_RECOVERY_REGENERATE: { label: "Admin recovery codes", ui: true }
} as const satisfies Record<ElevationScope, { label: string; ui: boolean }>;

export const UI_ELEVATION_SCOPES = ELEVATION_SCOPES;
