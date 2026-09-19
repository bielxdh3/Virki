import { UI_ELEVATION_SCOPES, type ElevationScope } from "@bielos/auth/elevation-scopes";

export function getInitialElevationScope(value: string | undefined): ElevationScope {
  if (value === "project-access") return "PROJECT_OWNER_ACCESS_CHANGE";
  if (value === "project-archive") return "CORE_PROJECT_ARCHIVE";
  return UI_ELEVATION_SCOPES.find((scope) => scope === value) ?? UI_ELEVATION_SCOPES[0];
}
