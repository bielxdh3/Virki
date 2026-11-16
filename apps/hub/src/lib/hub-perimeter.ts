/**
 * Opt-in migration to Virki's native ADMIN authentication perimeter.
 * In production, native mode requires explicit Access opt-out; absent or
 * misconfigured values retain Cloudflare Access. This never replaces Virki
 * session, role, MFA, CSRF, or elevation checks.
 */
export function isNativeHubPerimeterEnabled(env: Readonly<Record<string, string | undefined>> = process.env): boolean {
  if (env.VIRKI_HUB_PERIMETER_MODE !== "native") return false;
  if (env.NODE_ENV !== "production") return true;
  return env.CLOUDFLARE_ACCESS_JWT_REQUIRED === "false";
}
