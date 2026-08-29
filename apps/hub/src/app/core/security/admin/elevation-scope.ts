import { UI_ELEVATION_SCOPES, type ElevationScope } from "@bielos/auth/elevation-scopes";

export function getInitialElevationScope(value: string | undefined): ElevationScope {
  return UI_ELEVATION_SCOPES.find((scope) => scope === value) ?? UI_ELEVATION_SCOPES[0];
}
