import { getRecoveryCookieName, getRecoveryCookieOptions, LEGACY_RECOVERY_COOKIE } from "../../lib/recovery";

type RecoveryCookieStore = {
  set(name: string, value: string, options: ReturnType<typeof getRecoveryCookieOptions>): unknown;
  delete(options: { name: string; path: string }): unknown;
};

export const RECOVERY_CANDIDATE_COOKIE = process.env.NODE_ENV === "production" ? "__Host-virki_recovery_candidate" : "virki_recovery_candidate";

export function setRecoveryCookie(
  cookieStore: RecoveryCookieStore,
  requestKey: string,
  expiresAt: Date,
  env: { NODE_ENV?: string } = process.env
): void {
  const name = getRecoveryCookieName(env);
  if (name !== LEGACY_RECOVERY_COOKIE.name) cookieStore.delete(LEGACY_RECOVERY_COOKIE);
  cookieStore.set(name, requestKey, getRecoveryCookieOptions(expiresAt, env));
}

export function clearRecoveryCookie(
  cookieStore: RecoveryCookieStore,
  env: { NODE_ENV?: string } = process.env
): void {
  const name = getRecoveryCookieName(env);
  // An empty expiration without Secure is rejected for __Host- cookies by browsers.
  cookieStore.set(name, "", getRecoveryCookieOptions(new Date(0), env));
  if (name !== LEGACY_RECOVERY_COOKIE.name) cookieStore.delete(LEGACY_RECOVERY_COOKIE);
}

export function setRecoveryCandidateCookie(cookieStore: RecoveryCookieStore, requestKey: string, expiresAt: Date): void {
  const expires = new Date(Math.min(expiresAt.getTime(), Date.now() + 10 * 60 * 1000));
  cookieStore.set(RECOVERY_CANDIDATE_COOKIE, requestKey, getRecoveryCookieOptions(expires));
}

export function clearRecoveryCandidateCookie(cookieStore: RecoveryCookieStore): void {
  cookieStore.set(RECOVERY_CANDIDATE_COOKIE, "", getRecoveryCookieOptions(new Date(0)));
}
