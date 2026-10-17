import { createAuditRequestMetadata, hashAuditIdentifier, writeAuditLog, type AuditLogInput, type AuthenticatedSession } from "@virki/auth";

export async function recordSecurityDenial(requestHeaders: Pick<Headers, "get">, source: string, reason: "csrf" | "role" | "rejected" | "unavailable", session?: AuthenticatedSession | null): Promise<void> {
  const eventType: AuditLogInput["eventType"] = reason === "csrf" ? "CSRF_DENIED" : reason === "role" ? "AUTHORIZATION_DENIED" : "SECURITY_PROOF_REJECTED";
  await writeAuditLog({
    eventType, result: "DENIED", reason,
    actorUserId: session?.user.id,
    actorRole: session?.user.role === "ADMIN" || session?.user.role === "USER" ? session.user.role : undefined,
    sessionRef: session ? hashAuditIdentifier(session.id) : undefined,
    resource: "identity.security", metadata: createAuditRequestMetadata(requestHeaders, source)
  });
}
