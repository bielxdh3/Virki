import { NextResponse } from "next/server";
import {
  authenticateUserWithRateLimit,
  createAuditRequestMetadata,
  hashAuditEmail,
  normalizeEmail,
  getSessionCookieOptions,
  SESSION_COOKIE_NAME,
  writeAuditLog,
  writeAuditLogRequired
} from "@bielos/auth";
import { DEVICE_COOKIE_NAME, startLoginCeremony } from "@bielos/auth/security";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, getSurfaceBaseUrl, hasSameOrigin, safeReturnTo } from "../../../lib/surface";
import { readBoundedFormData } from "../../../lib/request-form";
import { createLoginResponseAfterRequiredAudit } from "../../../lib/login-audit";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const surface = getSurface(request.headers);
  if (surface === "unknown") return new NextResponse("Not found", { status: 404 });
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "admin-login-api"))) {
    return loginForbiddenResponse("cloudflare-access");
  }
  if (!hasSameOrigin(request.headers)) return loginForbiddenResponse("same-origin");

  const formData = await readBoundedFormData(request);
  if (!formData) return new NextResponse("Bad Request", { status: 400 });
  const csrfResult = validateCsrfToken(getFormString(formData, CSRF_FORM_FIELD_NAME), { scope: "login" });

  if (!csrfResult.valid) {
    return loginForbiddenResponse(`csrf-${csrfResult.reason}`);
  }

  const requestedReturnTo = getFormString(formData, "returnTo");
  const reauth = getFormString(formData, "reauth") === "1";
  const baseUrl = getSurfaceBaseUrl(request.headers, request.url);
  if (!baseUrl) return new NextResponse("Service Unavailable", { status: 503, headers: { "cache-control": "no-store" } });
  const failureRedirectUrl = new URL("/login", baseUrl);
  const defaultPath = surface === "hub" ? "/admin/accounts" : "/";

  const email = getFormString(formData, "email");
  const password = getFormRawString(formData, "password");
  if (email.length > 320 || password.length > 256) return redirectToLogin(failureRedirectUrl, true, safeReturnTo(requestedReturnTo, surface), reauth);
  const rateLimitIdentifier = normalizeEmail(email);
  const auditMetadata = createAuditRequestMetadata(request.headers, `${surface}-login`);
  const actorEmailHash = rateLimitIdentifier ? hashAuditEmail(rateLimitIdentifier) : undefined;

  const requiredRole = surface === "hub" ? "ADMIN" : surface === "portal" ? "USER" : undefined;
  const authentication = await authenticateUserWithRateLimit(email, password, new Date(), request.headers.get("cf-connecting-ip")?.trim(), requiredRole);
  const user = authentication.user;

  if (!user) {
    await writeAuditLog({
      eventType: "AUTH_LOGIN_FAILURE",
      result: "FAILURE",
      actorEmailHash,
      resource: surface,
      message:
        authentication.failureMode === "rate-limited"
          ? "Login rate limit reached."
          : authentication.failureMode === "limiter-unavailable"
            ? "Login rate limit unavailable."
            : "Login failed.",
      metadata: auditMetadata
    });
    return redirectToLogin(failureRedirectUrl, true, safeReturnTo(requestedReturnTo, surface), reauth);
  }

  if ((surface === "hub" && user.role !== "ADMIN") || (surface === "portal" && user.role !== "USER")) {
    await writeAuditLog({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", actorUserId: user.id, actorEmailHash: hashAuditEmail(user.email), resource: surface, message: "Login failed.", metadata: auditMetadata });
    return redirectToLogin(failureRedirectUrl, true, safeReturnTo(requestedReturnTo, surface, user.role), reauth);
  }

  const returnTo = safeReturnTo(requestedReturnTo, surface, user.role);
  const successUrl = new URL(returnTo ?? defaultPath, baseUrl);

  let ceremony;
  try {
    ceremony = await startLoginCeremony(
      user.id,
      readCookie(request.headers.get("cookie"), DEVICE_COOKIE_NAME),
      "pt-BR",
      new Date(),
      reauth,
      requiredRole
    );
  } catch {
    await writeAuditLog({
      eventType: "AUTH_LOGIN_FAILURE",
      result: "FAILURE",
      actorUserId: user.id,
      actorEmailHash: hashAuditEmail(user.email),
      resource: surface,
      message: "Security verification unavailable.",
      metadata: auditMetadata
    });
    return redirectToLogin(failureRedirectUrl, true, returnTo, reauth);
  }

  if (ceremony.kind === "SESSION") {
    try {
      return await createLoginResponseAfterRequiredAudit(
        () => writeAuditLogRequired({
          eventType: "AUTH_LOGIN_SUCCESS",
          result: "SUCCESS",
          actorUserId: user.id,
          actorEmailHash: hashAuditEmail(user.email),
          resource: surface,
          message: "Remembered-browser login succeeded.",
          metadata: { ...auditMetadata, rememberedBrowser: true }
        }),
        () => {
          const response = NextResponse.redirect(successUrl, { status: 303 });
          response.cookies.set(SESSION_COOKIE_NAME, ceremony.session.token, getSessionCookieOptions(ceremony.session.expiresAt));
          return response;
        }
      );
    } catch {
      return auditUnavailableResponse();
    }
  }

  try {
    return await createLoginResponseAfterRequiredAudit(
      () => writeAuditLogRequired({
        eventType: "AUTH_LOGIN_SUCCESS",
        result: "INFO",
        actorUserId: user.id,
        actorEmailHash: hashAuditEmail(user.email),
        resource: surface,
        message: "Password accepted; security verification pending.",
        metadata: auditMetadata
      }),
      () => {
        const verifyUrl = new URL("/login/verify", baseUrl);
        verifyUrl.searchParams.set("ceremony", ceremony.ceremonyId);
        verifyUrl.searchParams.set("factor", ceremony.factor.toLowerCase());
        if (returnTo) verifyUrl.searchParams.set("returnTo", returnTo);
        const response = NextResponse.redirect(verifyUrl, { status: 303 });
        if (readCookie(request.headers.get("cookie"), DEVICE_COOKIE_NAME) !== ceremony.deviceToken) {
          response.cookies.set(DEVICE_COOKIE_NAME, ceremony.deviceToken, {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            path: "/",
            maxAge: 180 * 24 * 60 * 60
          });
        }
        return response;
      }
    );
  } catch {
    return auditUnavailableResponse();
  }
}

function loginForbiddenResponse(reason: string): NextResponse {
  const response = new NextResponse("Forbidden", { status: 403 });
  if (process.env.NODE_ENV === "development" && process.env.BIELOS_E2E_ACCESS_DIAGNOSTICS === "true") {
    response.headers.set("x-bielos-e2e-login-reason", reason);
  }
  return response;
}

function auditUnavailableResponse() {
  return new NextResponse("Service Unavailable", {
    status: 503,
    headers: { "cache-control": "no-store" }
  });
}

function redirectToLogin(url: URL, failed: boolean, returnTo: string | null, reauth = false) {
  if (failed) {
    url.searchParams.set("error", "1");
  }
  if (returnTo) url.searchParams.set("returnTo", returnTo);
  if (reauth) url.searchParams.set("reauth", "1");

  return NextResponse.redirect(url, { status: 303 });
}

function getFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function getFormRawString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) {
    return undefined;
  }

  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0 || pair.slice(0, separator).trim() !== name) {
      continue;
    }
    return pair.slice(separator + 1).trim();
  }

  return undefined;
}
