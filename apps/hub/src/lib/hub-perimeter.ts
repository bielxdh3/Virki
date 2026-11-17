/**
 * Opt-in migration to Virki's native ADMIN authentication perimeter.
 * Only the canonical perimeter mode selects authentication. A stale Access
 * JWT switch must never add a second login in native mode; absent or
 * unrecognized modes retain the legacy Access gate. This never replaces Virki
 * session, role, MFA, CSRF, or elevation checks.
 */
export function isNativeHubPerimeterEnabled(env: Readonly<Record<string, string | undefined>> = process.env): boolean {
  if (env.VIRKI_HUB_PERIMETER_MODE !== "native") return false;
  return true;
}
