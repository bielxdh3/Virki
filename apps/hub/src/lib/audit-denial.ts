import { createAuditRequestMetadata, getSessionByToken, hashAuditSessionReference, writeAuditLog, type AuditLogInput, type AuthenticatedSession } from "@virki/auth";
import { writePreauthDenialAudit } from "./preauth-denial-audit";
import { isNativeHubPerimeterEnabled } from "./hub-perimeter";
import { getSurface } from "./surface";

// These are fixed internal identifiers for public login/recovery entrypoints.
// Protected ADMIN and account mutation guards can reject Origin before the
// session is loaded; `!session` alone must never classify them as pre-auth.
const PUBLIC_PREAUTH_DENIAL_SOURCES = new Set([
  "login-origin", "login-csrf", "login-factor-origin", "login-factor-csrf",
  "login-verification-origin", "login-verification-csrf",
  "account-recovery-request", "account-recovery-access", "account-recovery-switch",
  "account-recovery-verify", "account-recovery-new-mail-start", "account-recovery-new-mail-verify",
  "account-recovery-passkey-start", "account-recovery-passkey-verify", "account-recovery-complete"
]);

export async function recordSecurityDenial(requestHeaders: Pick<Headers, "get">, source: string, reason: "csrf" | "role" | "rejected" | "unavailable", session?: AuthenticatedSession | null): Promise<void> {
  const eventType: AuditLogInput["eventType"] = reason === "csrf" ? "CSRF_DENIED" : reason === "role" ? "AUTHORIZATION_DENIED" : "SECURITY_PROOF_REJECTED";
  const bestEffortAudit = !session && PUBLIC_PREAUTH_DENIAL_SOURCES.has(source) &&
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
  let session: AuthenticatedSession | null = null;
  // Session tokens are 32-byte base64url values; reject malformed cookie data before a DB lookup.
  if (sessionToken && /^[A-Za-z0-9_-]{43}$/u.test(sessionToken)) {
    try {
      session = await getSessionByToken(sessionToken);
    } catch {
      // Actor attribution is best-effort; keep the denial event even if lookup fails.
    }
  }
  await recordSecurityDenial(requestHeaders, source, "csrf", session);
}
