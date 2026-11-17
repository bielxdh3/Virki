import { createAuditRequestMetadata, getSessionByToken, hashAuditSessionReference, writeAuditLog, type AuditLogInput, type AuthenticatedSession } from "@virki/auth";
import { writePreauthDenialAudit } from "./preauth-denial-audit";
import { isNativeHubPerimeterEnabled } from "./hub-perimeter";
import { getSurface } from "./surface";
import { createBoundedDenialSessionLookup } from "./denial-session-lookup";

const lookupDenialSession = createBoundedDenialSessionLookup(getSessionByToken);

// Fixed public login/recovery identifiers, logout Origin/CSRF and ADMIN passkey
// Origin/invalid-CSRF after a bounded live session lookup. Only a verified ADMIN session
// avoids the native Hub audit budget: a portal USER session cannot turn native
// Hub Origin probes into unlimited AuditLog writes. Other protected guards may
// reject Origin before session lookup and remain outside this source allowlist.
const PUBLIC_PREAUTH_DENIAL_SOURCES = new Set([
  "login-origin", "login-csrf", "login-factor-origin", "login-factor-csrf", "logout-origin", "logout-csrf", "admin-passkeys-origin", "admin-passkeys-csrf",
  "login-verification-origin", "login-verification-csrf",
  "account-recovery-request", "account-recovery-access", "account-recovery-switch",
  "account-recovery-verify", "account-recovery-new-mail-start", "account-recovery-new-mail-verify",
  "account-recovery-passkey-start", "account-recovery-passkey-verify", "account-recovery-complete"
]);

export async function recordSecurityDenial(requestHeaders: Pick<Headers, "get">, source: string, reason: "csrf" | "role" | "rejected" | "unavailable", session?: AuthenticatedSession | null): Promise<void> {
  const eventType: AuditLogInput["eventType"] = reason === "csrf" ? "CSRF_DENIED" : reason === "role" ? "AUTHORIZATION_DENIED" : "SECURITY_PROOF_REJECTED";
  const bestEffortAudit = session?.user.role !== "ADMIN" && PUBLIC_PREAUTH_DENIAL_SOURCES.has(source) &&
    getSurface(requestHeaders) === "hub" && isNativeHubPerimeterEnabled()
    ? writePreauthDenialAudit : writeAuditLog;
  await bestEffortAudit({
    eventType, result: "DENIED", reason,
    actorUserId: session?.user.id,
    actorRole: session?.user.role === "ADMIN" || session?.user.role === "USER" ? session.user.role : undefined,
    sessionRef: session ? hashAuditSessionReference(session.id) : undefined,
    resource: "identity.security", metadata: createAuditRequestMetadata(requestHeaders, source)
  });
}

export async function recordSessionCsrfDenial(requestHeaders: Pick<Headers, "get">, source: string, sessionToken?: string): Promise<void> {
  // Public native Hub logout Origin AND invalid-CSRF guards can run without
  // authenticating a session. Both need bounded attribution; otherwise a
  // plausible forged cookie would evade the PostgreSQL SELECT ceiling.
  // Portal, Access, and protected ADMIN mutation guards stay unchanged.
  const preauthOrigin =
    (source === "logout-origin" || source === "logout-csrf" || source === "admin-passkeys-origin" || source === "admin-passkeys-csrf") &&
    getSurface(requestHeaders) === "hub" && isNativeHubPerimeterEnabled();
  let session: AuthenticatedSession | null = null;
  if (preauthOrigin) {
    session = await lookupDenialSession(sessionToken);
  } else if (sessionToken && /^[A-Za-z0-9_-]{43}$/u.test(sessionToken)) {
    try {
      session = await getSessionByToken(sessionToken);
    } catch {
      // This is best-effort actor attribution, not an authorization decision.
    }
  }
  await recordSecurityDenial(requestHeaders, source, "csrf", session);
}
