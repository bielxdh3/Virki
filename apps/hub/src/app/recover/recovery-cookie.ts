import { getRecoveryCookieName, getRecoveryCookieOptions, LEGACY_RECOVERY_COOKIE } from "../../lib/recovery";
import { recoveryPolicyFromMethod, type RecoveryRequestMethod } from "./recovery-method-selection";

type RecoveryCookieStore = {
  set(name: string, value: string, options: ReturnType<typeof getRecoveryCookieOptions>): unknown;
  delete(options: { name: string; path: string }): unknown;
};

export const RECOVERY_CANDIDATE_COOKIE = process.env.NODE_ENV === "production" ? "__Host-virki_recovery_candidate" : "virki_recovery_candidate";
export const RECOVERY_BROWSER_COOKIE = process.env.NODE_ENV === "production" ? "__Host-virki_recovery_browser" : "virki_recovery_browser";
export const RECOVERY_INTENT_COOKIE = process.env.NODE_ENV === "production" ? "__Host-virki_recovery_intent" : "virki_recovery_intent";

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

// Intent is only a rendering hint for generic synthetic recovery sessions. It is never an authorization proof.
export function parseRecoveryIntent(value: string | undefined): { requestId: string; method: RecoveryRequestMethod } | null {
  if (!value) return null;
  const separator = value.indexOf(".");
  if (separator < 1) return null;
  const requestId = value.slice(0, separator);
  const method = value.slice(separator + 1);
  if (!/^[A-Za-z0-9_-]{8,80}$/u.test(requestId) || !recoveryPolicyFromMethod(method)) return null;
  return { requestId, method: method as RecoveryRequestMethod };
}

export function setMultiMethodRecoveryCookies(cookieStore: RecoveryCookieStore, requestKey: string, browserToken: string, requestId: string, method: RecoveryRequestMethod): void {
  // The backend's pending window is 30 minutes and its approved window may extend it by 30 more.
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
  setRecoveryCookie(cookieStore, requestKey, expiresAt);
  cookieStore.set(RECOVERY_BROWSER_COOKIE, browserToken, getRecoveryCookieOptions(expiresAt));
  cookieStore.set(RECOVERY_INTENT_COOKIE, `${requestId}.${method}`, getRecoveryCookieOptions(expiresAt));
}

export function clearMultiMethodRecoveryCookies(cookieStore: RecoveryCookieStore): void {
  const expired = getRecoveryCookieOptions(new Date(0));
  cookieStore.set(RECOVERY_BROWSER_COOKIE, "", expired);
  cookieStore.set(RECOVERY_INTENT_COOKIE, "", expired);
}
