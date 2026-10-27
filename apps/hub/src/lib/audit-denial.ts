import { createAuditRequestMetadata, getSessionByToken, hashAuditSessionReference, writeAuditLog, type AuditLogInput, type AuthenticatedSession } from "@virki/auth";

export async function recordSecurityDenial(requestHeaders: Pick<Headers, "get">, source: string, reason: "csrf" | "role" | "rejected" | "unavailable", session?: AuthenticatedSession | null): Promise<void> {
  const eventType: AuditLogInput["eventType"] = reason === "csrf" ? "CSRF_DENIED" : reason === "role" ? "AUTHORIZATION_DENIED" : "SECURITY_PROOF_REJECTED";
  await writeAuditLog({
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
