import { NextResponse } from "next/server";
import { getCurrentSession } from "../../../lib/auth";
import { requestHost, getSurface, sameOriginFailureReason } from "../../../lib/surface";
import { validateSessionCsrfToken } from "../../../lib/session-csrf";
import { SESSION_COOKIE_NAME, getSessionCookieOptions } from "@virki/auth";
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
  if (!passkeysEnabledForRequest(getSurface(request.headers), host)) return guardedJson({ error: "Unavailable" }, 404);
  if (sameOriginFailureReason(request.headers)) return guardedJson({ error: "Rejected" }, 403);
  const body = await boundedJson(request);
  if (!body) return guardedJson({ error: "Invalid request" }, 400);
  const action = property(body, "action", 40);
  try {
    if (action === "login-options" || action === "register-options") {
      const browserToken = createPasskeyBrowserToken();
      let options;
      if (action === "register-options") {
        const session = await requireProtectedSession(body);
        options = await startPasskeyRegistration(session.user.id, session.id, property(body, "password"), browserToken, host, property(body, "totpCode", 6));
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

    if (action === "register-verify" || action === "rename" || action === "revoke") {
      const session = await requireProtectedSession(body);
      if (action === "register-verify") {
        const browserToken = cookieValue(request.headers.get("cookie"), PASSKEY_BROWSER_COOKIE);
        await finishPasskeyRegistration(session.user.id, session.id, browserToken, body.response as RegistrationResponseJSON, property(body, "name", 80), host);
        const response = guardedJson({ success: true });
        discardBrowserCookie(response);
        return response;
      }
      await mutatePasskey(session.user.id, session.id, property(body, "id", 80), property(body, "password"), action, property(body, "name", 80), property(body, "totpCode", 6));
      return guardedJson({ success: true });
    }

    return guardedJson({ error: "Invalid request" }, 400);
  } catch {
    return guardedJson({ error: "Authentication rejected or service unavailable" }, 403);
  }
}

async function requireProtectedSession(body: Record<string, unknown>) {
  const session = await getCurrentSession();
  if (!session || session.user.role !== "USER" || !(await validateSessionCsrfToken(property(body, "csrfToken", 1200), "account-security"))) {
    throw new Error("Rejected");
  }
  return session;
}
