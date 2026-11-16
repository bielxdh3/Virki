/**
 * Opt-in migration to Virki's native ADMIN authentication perimeter.
 * An absent, malformed or misspelled value always retains Cloudflare Access.
 * This does not authenticate a user: every protected page/action must still
 * validate the real Virki session, role, CSRF and elevation as appropriate.
 */
export function isNativeHubPerimeterEnabled(env: Readonly<Record<string, string | undefined>> = process.env): boolean {
  return env.VIRKI_HUB_PERIMETER_MODE === "native";
}
