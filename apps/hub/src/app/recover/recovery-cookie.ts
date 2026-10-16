import { getRecoveryCookieName, getRecoveryCookieOptions, LEGACY_RECOVERY_COOKIE } from "../../lib/recovery";

type RecoveryCookieStore = {
  set(name: string, value: string, options: ReturnType<typeof getRecoveryCookieOptions>): unknown;
  delete(options: { name: string; path: string }): unknown;
};

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
