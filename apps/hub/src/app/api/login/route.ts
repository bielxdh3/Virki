import { NextResponse } from "next/server";
import {
  authenticateUser,
  checkLoginRateLimit,
  clearLoginRateLimit,
  createAuditRequestMetadata,
  createSession,
  getSessionCookieOptions,
  hashAuditEmail,
  normalizeEmail,
  recordFailedLogin,
  SESSION_COOKIE_NAME,
  writeAuditLog
} from "@bielos/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const accessResult = await validateHubCloudflareAccess(request.headers, "hub-login-api");

  if (!isCloudflareAccessAllowed(accessResult)) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  const formData = await request.formData();
  const csrfResult = validateCsrfToken(getFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  const email = String(formData.get("email") ?? "");
  const password = String(formData.get("password") ?? "");
  const rateLimitIdentifier = normalizeEmail(email);
  const auditMetadata = createAuditRequestMetadata(request.headers, "hub-login");
  const actorEmailHash = rateLimitIdentifier ? hashAuditEmail(rateLimitIdentifier) : undefined;

  const rateLimit = await checkLoginRateLimit(rateLimitIdentifier);

  if (!rateLimit.allowed) {
    await writeAuditLog({
      eventType: "AUTH_LOGIN_FAILURE",
      result: "FAILURE",
      actorEmailHash,
      resource: "hub",
      message: rateLimit.failureMode ? "Login rate limit unavailable." : "Login rate limit reached.",
      metadata: auditMetadata
    });
    return redirectToLogin(request, true);
  }

  if (!email || !password) {
    await recordFailedLogin(rateLimitIdentifier);
    await writeAuditLog({
      eventType: "AUTH_LOGIN_FAILURE",
      result: "FAILURE",
      actorEmailHash,
      resource: "hub",
      message: "Login failed.",
      metadata: auditMetadata
    });
    return redirectToLogin(request, true);
  }

  const user = await authenticateUser(email, password);

  if (!user) {
    await recordFailedLogin(rateLimitIdentifier);
    await writeAuditLog({
      eventType: "AUTH_LOGIN_FAILURE",
      result: "FAILURE",
      actorEmailHash,
      resource: "hub",
      message: "Login failed.",
      metadata: auditMetadata
    });
    return redirectToLogin(request, true);
  }

  await clearLoginRateLimit(rateLimitIdentifier);
  const session = await createSession(user.id);
  await writeAuditLog({
    eventType: "AUTH_LOGIN_SUCCESS",
    result: "SUCCESS",
    actorUserId: user.id,
    actorEmailHash: hashAuditEmail(user.email),
    resource: "hub",
    message: "Login succeeded.",
    metadata: auditMetadata
  });
  const response = NextResponse.redirect(new URL("/", request.url), { status: 303 });
  response.cookies.set(
    SESSION_COOKIE_NAME,
    session.token,
    getSessionCookieOptions(session.expiresAt)
  );

  return response;
}

function redirectToLogin(request: Request, failed: boolean) {
  const url = new URL("/login", request.url);

  if (failed) {
    url.searchParams.set("error", "1");
  }

  return NextResponse.redirect(url, { status: 303 });
}

function getFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}
