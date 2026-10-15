import { hashSessionToken, SESSION_COOKIE_NAME } from "@virki/auth";
import { createCsrfToken, validateCsrfToken } from "@virki/auth/csrf";
import { cookies } from "next/headers";

// CSRF tokens for authenticated mutations are bound to the central session cookie (hashed),
// so a token minted for one session is useless in another. Anonymous pre-login scopes must
// keep using the unbound helpers from @virki/auth/csrf.

export function createSessionCsrfTokenFor(sessionCookie: string | undefined, scope: string): string {
  if (!sessionCookie) throw new Error("A session is required to mint a session-bound CSRF token.");
  return createCsrfToken({ scope, binding: hashSessionToken(sessionCookie) });
}

export function validateSessionCsrfTokenFor(sessionCookie: string | undefined, token: string | null | undefined, scope: string): boolean {
  if (!sessionCookie) return false;
  return validateCsrfToken(token, { scope, binding: hashSessionToken(sessionCookie) }).valid;
}

export async function createSessionCsrfToken(scope: string): Promise<string> {
  return createSessionCsrfTokenFor((await cookies()).get(SESSION_COOKIE_NAME)?.value, scope);
}

export async function validateSessionCsrfToken(token: string | null | undefined, scope: string): Promise<boolean> {
  return validateSessionCsrfTokenFor((await cookies()).get(SESSION_COOKIE_NAME)?.value, token, scope);
}
