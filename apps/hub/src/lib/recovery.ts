// Production uses the __Host- prefix (Secure, Path=/, no Domain) so a sibling subdomain cannot plant or
// overwrite the recovery key, matching the session and device cookies. Development keeps a plain name for http://localhost.
export function getRecoveryCookieName(env: { NODE_ENV?: string } = process.env): string {
  return env.NODE_ENV === "production" ? "__Host-virki_recovery" : "virki_recovery";
}

export const RECOVERY_COOKIE_NAME = getRecoveryCookieName();
// Pre-__Host- cookie scoped to /recover; expired whenever a recovery link is opened or completed.
export const LEGACY_RECOVERY_COOKIE = { name: "virki_recovery", path: "/recover" } as const;

export function getRecoveryCookieOptions(expires: Date, env: { NODE_ENV?: string } = process.env) {
  return { httpOnly: true, sameSite: "lax" as const, secure: env.NODE_ENV === "production", path: "/", expires };
}
