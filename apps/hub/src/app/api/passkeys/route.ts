import { NextResponse } from "next/server";
import { getCurrentSession } from "../../../lib/auth";
import { recordSecurityDenial, recordSessionCsrfDenial } from "../../../lib/audit-denial";
import { isNativeHubPerimeterEnabled } from "../../../lib/hub-perimeter";
import { writePreauthDenialAudit } from "../../../lib/preauth-denial-audit";
import { shouldBoundNativePasskeyDenial } from "../../../lib/native-passkey-denial";
import { requestHost, getSurface, sameOriginFailureReason } from "../../../lib/surface";
import { validateSessionCsrfToken, validateSessionCsrfTokenFor } from "../../../lib/session-csrf";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { SESSION_COOKIE_NAME, createAuditRequestMetadata, getSessionCookieOptions, hashAuditEmail, hashAuditSessionReference, normalizeEmail, writeAuditLog } from "@virki/auth";
import {
  PASSKEY_BROWSER_COOKIE,
  createPasskeyBrowserToken,
  finishPasskeyAuthentication,
  finishPasskeyRegistration,
  mutatePasskey,
  passkeysEnabledForRequest,
  startPasskeyAuthentication,
  startPasskeyRegistration
} from "@virki/auth/passkeys";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";

export const dynamic = "force-dynamic";
const noStore = { "cache-control": "no-store" };

async function boundedJson(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json") || !request.body) return null;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 48 * 1024) return null;
      chunks.push(value);
    }
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch { return null; }
  finally { await reader.cancel().catch(() => {}); }
}

function property(body: Record<string, unknown>, key: string, max = 256): string {
  const value = body[key];
  return typeof value === "string" && value.length <= max ? value : "";
}

function cookieValue(header: string | null, name: string): string {
  return header?.split(";").map(item => item.trim()).find(item => item.startsWith(`${name}=`))?.slice(name.length + 1) ?? "";
}

function guardedJson(payload: object, status = 200) {
  return NextResponse.json(payload, { status, headers: noStore });
}

function discardBrowserCookie(response: NextResponse) {
  response.cookies.set(PASSKEY_BROWSER_COOKIE, "", {
    httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict",
    path: "/api/passkeys", maxAge: 0
  });
}

export async function POST(request: Request) {
  const host = requestHost(request.headers);
  const body = await boundedJson(request);
  if (!body) return guardedJson({ error: "Invalid request" }, 400);
  const action = property(body, "action", 40);
  const adminAction = action.startsWith("admin-");
  const role = adminAction ? "ADMIN" : "USER";
  const surface = getSurface(request.headers);
  if (!passkeysEnabledForRequest(surface, host, process.env, role)) return guardedJson({ error: "Unavailable" }, 404);
  if (adminAction && surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "admin-passkeys"))) return guardedJson({ error: "Rejected" }, 403);
  if (sameOriginFailureReason(request.headers)) {
    if (adminAction && surface === "hub" && isNativeHubPerimeterEnabled()) {
      // Attribute a live ADMIN cookie before applying the anonymous Origin
      // audit budget; an actual ADMIN denial must retain forensic evidence.
      await recordSessionCsrfDenial(request.headers, "admin-passkeys-origin",
        cookieValue(request.headers.get("cookie"), SESSION_COOKIE_NAME));
    } else {
      await recordSecurityDenial(request.headers, adminAction ? "admin-passkeys-origin" : "portal-passkeys-origin", "csrf");
    }
    return guardedJson({ error: "Rejected" }, 403);
  }
  const auditState: { session: Awaited<ReturnType<typeof getCurrentSession>>; csrfDenied: boolean; preaudited: boolean } =
    { session: null, csrfDenied: false, preaudited: false };
  async function requireProtectedSessionForRequest() {
    if (adminAction && surface === "hub" && isNativeHubPerimeterEnabled()) {
      const sessionToken = cookieValue(request.headers.get("cookie"), SESSION_COOKIE_NAME);
      // A plausible cookie and a deliberately invalid CSRF token must not
      // force unlimited database lookups before authentication. Check the
      // session-bound HMAC locally first, then use bounded actor attribution
      // for a denial. Existing Access and USER Portal behavior is untouched.
      if (!validateSessionCsrfTokenFor(sessionToken, property(body!, "csrfToken", 1200), "admin-security")) {
        auditState.preaudited = true;
        await recordSessionCsrfDenial(request.headers, "admin-passkeys-csrf", sessionToken);
        throw new Error("Rejected");
      }
    }
    const session = await getCurrentSession();
    if (!session || session.user.role !== role) throw new Error("Rejected");
    // Identify the authenticated actor before checking CSRF so rejected requests
    // retain their verified audit actor without treating a bad proof as anonymous.
    auditState.session = session;
    if (!(await validateSessionCsrfToken(property(body!, "csrfToken", 1200), adminAction ? "admin-security" : "account-security"))) {
      auditState.csrfDenied = true;
      throw new Error("Rejected");
    }
    return session;
  }
  try {
    if (action === "login-options" || action === "register-options" || action === "admin-register-options") {
      const browserToken = createPasskeyBrowserToken();
      let options;
      if (action === "register-options" || action === "admin-register-options") {
        const session = await requireProtectedSessionForRequest();
        options = await startPasskeyRegistration(session.user.id, session.id, property(body, "password"), browserToken, host, property(body, "totpCode", 6), role);
      } else {
        options = await startPasskeyAuthentication(browserToken, request.headers.get("cf-connecting-ip")?.trim() ?? "", property(body, "email", 320) || undefined, host, property(body, "password"));
      }
      const response = guardedJson({ options });
      response.cookies.set(PASSKEY_BROWSER_COOKIE, browserToken, {
        httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict",
        path: "/api/passkeys", maxAge: 300
      });
      return response;
    }

    if (action === "login-verify") {
      const browserToken = cookieValue(request.headers.get("cookie"), PASSKEY_BROWSER_COOKIE);
      const assertion = body.response as AuthenticationResponseJSON;
      const session = await finishPasskeyAuthentication(browserToken, assertion, host);
      const response = guardedJson({ success: true });
      response.cookies.set(SESSION_COOKIE_NAME, session.token, getSessionCookieOptions(session.expiresAt));
      discardBrowserCookie(response);
      return response;
    }

    if (action === "register-verify" || action === "rename" || action === "revoke" || action === "admin-register-verify" || action === "admin-rename" || action === "admin-revoke") {
      const session = await requireProtectedSessionForRequest();
      if (action === "register-verify" || action === "admin-register-verify") {
        const browserToken = cookieValue(request.headers.get("cookie"), PASSKEY_BROWSER_COOKIE);
        await finishPasskeyRegistration(session.user.id, session.id, browserToken, body.response as RegistrationResponseJSON, property(body, "name", 80), host, role);
        const response = guardedJson({ success: true });
        discardBrowserCookie(response);
        return response;
      }
      await mutatePasskey(session.user.id, session.id, property(body, "id", 80), property(body, "password"), action.endsWith("rename") ? "rename" : "revoke", property(body, "name", 80), property(body, "totpCode", 6), role, host);
      return guardedJson({ success: true });
    }

    return guardedJson({ error: "Invalid request" }, 400);
  } catch {
    const { session: auditedSession, csrfDenied, preaudited } = auditState;
    if (preaudited) return guardedJson({ error: "Authentication rejected or service unavailable" }, 403);
    const loginAttempt = action === "login-options" || action === "login-verify";
    let actorEmailHash: string | undefined;
    if (action === "login-options") {
      const email = property(body, "email", 320);
      if (email) {
        try { actorEmailHash = hashAuditEmail(normalizeEmail(email)); } catch { /* An unavailable pseudonymization key must not expose the email. */ }
      }
    }
    // Audit outside the ceremony's transaction: rejected proofs roll back their transaction.
    // Never persist the WebAuthn response, password, credential ID, challenge or raw email.
    // ADMIN passkeys are public at ingress until a live session is loaded.
    // Budget unverified native Hub denial writes; keep verified ADMIN events
    // on the full writer and leave USER Portal and legacy Access unchanged.
    const auditWriter = shouldBoundNativePasskeyDenial(adminAction, surface, auditedSession?.user.role)
      ? writePreauthDenialAudit : writeAuditLog;
    await auditWriter({
      eventType: csrfDenied ? "CSRF_DENIED" : loginAttempt ? "AUTH_LOGIN_FAILURE" : "SECURITY_PROOF_REJECTED",
      result: loginAttempt && !csrfDenied ? "FAILURE" : "DENIED",
      actorUserId: auditedSession?.user.id,
      actorRole: auditedSession?.user.role === "USER" ? "USER" : auditedSession?.user.role === "ADMIN" ? "ADMIN" : undefined,
      sessionRef: auditedSession ? hashAuditSessionReference(auditedSession.id) : undefined,
      actorEmailHash,
      resource: "identity.passkey",
      metadata: createAuditRequestMetadata(request.headers, `${adminAction ? "admin" : "portal"}-passkeys-${action}`)
    });
    return guardedJson({ error: "Authentication rejected or service unavailable" }, 403);
  }
}
