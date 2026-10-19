// Production uses the __Host- prefix (Secure, Path=/, no Domain) so a sibling subdomain cannot plant or
// overwrite the recovery key, matching the session and device cookies. Development uses a distinct plain name
// on http://localhost, so the original path-scoped virki_recovery can be expired in the same response.
export function getRecoveryCookieName(env: { NODE_ENV?: string } = process.env): string {
  return env.NODE_ENV === "production" ? "__Host-virki_recovery" : "virki_recovery_v2";
}

export const RECOVERY_COOKIE_NAME = getRecoveryCookieName();
// Pre-__Host- cookie scoped to /recover; expired whenever a recovery link is opened or completed.
export const LEGACY_RECOVERY_COOKIE = { name: "virki_recovery", path: "/recover" } as const;

export function requiresRecoveryRequestSwitch(activeRequestId: string | null | undefined, nextRequestId: string): boolean {
  return Boolean(activeRequestId && activeRequestId !== nextRequestId);
}

export function getRecoveryCookieOptions(expires: Date, env: { NODE_ENV?: string } = process.env) {
  return { httpOnly: true, sameSite: "lax" as const, secure: env.NODE_ENV === "production", path: "/", expires };
}
