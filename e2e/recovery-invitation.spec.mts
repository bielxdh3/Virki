import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { PrismaClient } from "@virki/database";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { createTotpSecret, encryptTotpSecret, hashEmailAddress, hashRecoveryRequestKey, requestAccountRecovery } from "@virki/auth/security";
// @ts-expect-error The disposable-database guard is a JavaScript safety helper without a declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";
// @ts-expect-error The LOW-05 diagnostics helper is a JavaScript test-only redaction boundary.
import { classifyLow05NavigationError, classifyLow05RequestBoundary, classifyLow05Url, describeLow05Response, isLow05ProtectedDocumentCacheControl } from "../scripts/e2e/low05-diagnostics.mjs";

const portalUrl = process.env.VIRKI_E2E_HUB_MODE === "production" ? "https://portal.localhost" : "https://portal.localhost:3001";
const hubMode = process.env.VIRKI_E2E_HUB_MODE === "production" ? "production" : "development";
const sessionCookieName = getSessionCookieName({ NODE_ENV: process.env.VIRKI_E2E_HUB_MODE === "production" ? "production" : "development" });
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();

async function explicitlyAdoptLegacyRecoveryLink(page: Page, requestKey: string, expectedRequestId: string): Promise<void> {
  // A legacy GET is discovery only. Neither opening an invitation nor opening
  // a legacy recovery URL may replace an authorizing browser bearer until the
  // visitor explicitly adopts the candidate through the CSRF-bound action.
  await expect(page).toHaveURL(`${portalUrl}/recover?requestId=${expectedRequestId}&switch=1`);
  await expect(page.getByRole("status")).toContainText("Nenhuma recuperação foi substituída ao visualizar o link.");
  const primaryName = hubMode === "production" ? "__Host-virki_recovery" : "virki_recovery_v2";
  const candidateName = hubMode === "production" ? "__Host-virki_recovery_candidate" : "virki_recovery_candidate";
  const before = await page.context().cookies(portalUrl);
  expect(before.find(cookie => cookie.name === primaryName)?.value ?? "",
    "opening a legacy GET must not install the authorizing bearer").toBe("");
  expect(before.find(cookie => cookie.name === candidateName)?.value,
    "the discovery cookie must identify exactly the delivered link").toBe(requestKey);

  await page.getByRole("button", { name: "Continuar com este link", exact: true }).click();
  try {
    await expect(page).toHaveURL(`${portalUrl}/recover?requestId=${expectedRequestId}`, { timeout: 10_000 });
  } catch {
    const current = new URL(page.url());
    const afterClick = await page.context().cookies(portalUrl);
    throw new Error(`Explicit legacy adoption did not reach its expected document: ${JSON.stringify({
      route: current.pathname === "/recover" ? "recover" : current.pathname === "/login" ? "login" : "other",
      requestIdMatches: current.searchParams.get("requestId") === expectedRequestId,
      switchPending: current.searchParams.get("switch") === "1",
      hasErrorParam: current.searchParams.has("error"),
      primaryIsApprovedKey: afterClick.find(cookie => cookie.name === primaryName)?.value === requestKey,
      candidateStillPresent: afterClick.find(cookie => cookie.name === candidateName)?.value === requestKey,
      switchButtonVisible: await page.getByRole("button", { name: "Continuar com este link", exact: true }).isVisible().catch(() => false),
      genericErrorVisible: await page.locator('p.form-error[role="alert"]').isVisible().catch(() => false)
    })}`);
  }
  const adopted = await page.context().cookies(portalUrl);
  expect(adopted.find(cookie => cookie.name === primaryName)?.value,
    "the explicit switch must adopt the same live legacy link, not another capability").toBe(requestKey);
  expect(adopted.find(cookie => cookie.name === candidateName)?.value ?? "",
    "the consumed candidate must not remain available for a later switch").toBe("");
}

function hasLow05NoStoreDirectives(value: string): boolean {
  const directives = new Set(value.toLowerCase().split(",").map((directive) => directive.trim()));
  return ["no-store", "max-age=0", "must-revalidate"].every((directive) => directives.has(directive)) && !directives.has("public");
}

async function goBackToProtectedPage(page: import("@playwright/test").Page, priorSecurityOrigin: number): Promise<{ status: number; cacheControl: string }> {
  const responses: import("@playwright/test").Response[] = [];
  const observeProtectedDocument = (response: import("@playwright/test").Response) => {
    const request = response.request();
    const url = new URL(response.url());
    if (request.frame() === page.mainFrame() && request.isNavigationRequest() &&
        request.resourceType() === "document" && request.method() === "GET" &&
        url.origin === new URL(portalUrl).origin && url.pathname === "/account/security") {
      responses.push(response);
    }
  };
  page.on("response", observeProtectedDocument);
  try {
    try {
      await page.goBack({ waitUntil: "domcontentloaded" });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // The protected history entry intentionally scrubs and reloads itself;
      // an aborted first navigation is tolerated only if the expected secured
      // document response, exact URL, and completed reload still follow.
      if (!/page\.goBack: net::ERR_ABORTED/u.test(message)) throw error;
    }
    await expect(page).toHaveURL(`${portalUrl}/account/security`);
    await waitForHistoryRevalidation(page, priorSecurityOrigin);
    await expect(page).toHaveURL(`${portalUrl}/account/security`);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    // Assert the last security GET observed through the guard reload, not an
    // earlier, possibly weaker response to the history traversal itself.
    const finalResponse = responses.at(-1);
    expect(finalResponse, "fresh history reload must have a main-frame security GET").toBeDefined();
    return { status: finalResponse!.status(), cacheControl: await finalResponse!.headerValue("cache-control") ?? "" };
  } finally {
    page.off("response", observeProtectedDocument);
  }
}

async function waitForHistoryRevalidation(page: import("@playwright/test").Page, priorOrigin: number): Promise<void> {
  // Both protected routes deliberately scrub and reload a history-restored
  // document. A preexisting navigation entry with type "reload" is not
  // evidence of a NEW document. Require a later performance time origin.
  await expect.poll(async () => {
    try {
      return await page.evaluate((previous) => {
        const navigation = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
        return navigation?.type === "reload" && performance.timeOrigin > previous;
      }, priorOrigin);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!/(?:execution context was destroyed|page is navigating|frame was detached)/iu.test(message)) throw error;
      return false;
    }
  }, { timeout: 15_000, message: "History restoration must finish a newly loaded protected document" }).toBe(true);
}

async function goForwardToPortalPage(page: import("@playwright/test").Page, priorPortalOrigin: number): Promise<void> {
  try {
    await page.goForward({ waitUntil: "domcontentloaded" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // The protected page deliberately forces a second full navigation on
    // history restoration. Chromium can abort the first document navigation
    // while the browser still completes the forward traversal. Do not treat
    // other errors as transient, and require the intended URL and UI below.
    if (!/page\.goForward: net::ERR_ABORTED/u.test(message)) throw error;
  }
  await expect(page).toHaveURL(`${portalUrl}/?history-probe=low05`);
  await waitForHistoryRevalidation(page, priorPortalOrigin);
  await expect(page).toHaveURL(`${portalUrl}/?history-probe=low05`);
  await expect(page.getByRole("heading", { level: 1, name: "Projetos", exact: true })).toBeVisible();
}

test.skip(!e2eDatabaseUrl, "Recovery/invitation E2E requires an explicit disposable PostgreSQL fixture.");

type AuthFixture = { admin: { id: string }; user: { id: string; email: string; password: string } };

test("public recovery form gives known and unknown addresses the same browser response", async ({ browser }) => {
  test.setTimeout(90_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery/invitation E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  if (process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable" || new URL(e2eDatabaseUrl).pathname !== "/virki_e2e_test") {
    throw new Error("This recovery browser test requires the owned disposable E2E database.");
  }
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  // The shared authentication fixture may have prior requests. A fresh owner-labelled
  // TOTP account avoids cooldowns silently converting the real case to synthetic.
  const knownEmail = `${randomUUID()}.invitation-recovery@e2e.invalid`;
  const unknownEmail = `${randomUUID()}@unknown.e2e.invalid`;
  const contexts: import("@playwright/test").BrowserContext[] = [];
  const responses: Array<{ requestId: string; publicView: { path: string; httpStatus: number; body: string; proof: string; heading: string } }> = [];
  let ownedUserId: string | undefined;
  try {
    const user = await database.user.create({ data: {
      email: knownEmail, emailNormalized: knownEmail, displayName: "Owned recovery invitation E2E fixture",
      passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
      secondFactorMethod: "TOTP",
      totpFactor: { create: {
        secretCiphertext: encryptTotpSecret(createTotpSecret()), keyVersion: 1,
        status: "ACTIVE", confirmedAt: new Date()
      } }
    }, select: { id: true } });
    ownedUserId = user.id;
    const knownRequestCountBefore = await database.accountRecoveryRequest.count({ where: { userId: ownedUserId } });
    const knownMessageCountBefore = await database.emailOutboxMessage.count({ where: { recipientEmail: knownEmail, kind: "ACCOUNT_RECOVERY" } });
    for (const email of [knownEmail, unknownEmail]) {
      const context = await browser.newContext();
      contexts.push(context);
      const page = await context.newPage();
      await page.goto(`${portalUrl}/recover`);
      await page.getByLabel("E-mail da conta", { exact: true }).fill(email);
      await page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
      const actionResponsePromise = page.waitForResponse((response) => {
        const responseUrl = new URL(response.url());
        return response.request().method() === "POST" && responseUrl.origin === portalUrl && responseUrl.pathname === "/recover";
      });
      await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
      const actionResponse = await actionResponsePromise;
      expect(actionResponse.status()).toBeGreaterThanOrEqual(200);
      expect(actionResponse.status()).toBeLessThan(400);
      await expect(page).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]{43}$/u);
      await expect(page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toBeVisible();
      const url = new URL(page.url());
      const requestId = url.searchParams.get("requestId") ?? "";
      expect(requestId).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      const cookieNames = hubMode === "production"
        ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
        : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
      const cookies = await context.cookies(portalUrl);
      for (const name of cookieNames) {
        const cookie = cookies.find((candidate) => candidate.name === name);
        expect(cookie, `each browser must have its own ${name}`).toBeDefined();
        expect(cookie).toMatchObject({ domain: "portal.localhost", path: "/", httpOnly: true, sameSite: "Lax", secure: hubMode === "production" });
        expect(cookie!.value).not.toBe("");
      }
      expect(cookies.find((cookie) => cookie.name === cookieNames[2])?.value).toBe(`${requestId}.TOTP_EMAIL`);
      responses.push({
        requestId,
        publicView: {
          path: url.pathname,
          httpStatus: actionResponse.status(),
          body: (await page.locator("main").innerText()).trim(),
          proof: (await page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim(),
          heading: (await page.getByRole("heading", { level: 1 }).innerText()).trim()
        }
      });
    }
    expect(responses).toHaveLength(2);
    const [known, unknown] = responses;
    expect(known.requestId).not.toBe(unknown.requestId);
    expect(known.publicView).toEqual(unknown.publicView);
    expect(await database.accountRecoveryRequest.findUnique({ where: { id: known.requestId }, select: { userId: true, recoveryProofs: true, recoveryRole: true } }))
      .toMatchObject({ userId: ownedUserId, recoveryProofs: ["EMAIL", "TOTP"], recoveryRole: "USER" });
    expect(await database.accountRecoveryRequest.findUnique({ where: { id: unknown.requestId } })).toBeNull();
    const unboundContext = await browser.newContext();
    contexts.push(unboundContext);
    const unboundPage = await unboundContext.newPage();
    const unboundUrl = `${portalUrl}/recover?requestId=${encodeURIComponent(known.requestId)}`;
    const unboundResponse = await unboundPage.goto(unboundUrl);
    expect(unboundResponse?.status()).toBe(200);
    await expect(unboundPage).toHaveURL(unboundUrl);
    await expect(unboundPage.getByRole("heading", { level: 1, name: "Recuperar conta" })).toBeVisible();
    await expect(unboundPage.locator('p.form-error[role="alert"]')).toContainText("Este link de recuperação não é mais válido");
    await expect(unboundPage.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toHaveCount(0);

    const knownRequestCountAfter = await database.accountRecoveryRequest.count({ where: { userId: ownedUserId } });
    const knownMessageCountAfter = await database.emailOutboxMessage.count({ where: { recipientEmail: knownEmail, kind: "ACCOUNT_RECOVERY" } });
    expect(knownRequestCountAfter).toBe(knownRequestCountBefore + 1);
    expect(knownMessageCountAfter).toBe(knownMessageCountBefore + 1);
    expect(await database.accountRecoveryRequest.count({ where: { emailAddressHash: hashEmailAddress(unknownEmail) } })).toBe(0);
    expect(await database.emailOutboxMessage.count({ where: { recipientEmail: unknownEmail, kind: "ACCOUNT_RECOVERY" } })).toBe(0);
  } finally {
    try {
      await Promise.all(contexts.map((context) => context.close()));
    } finally {
      try {
        if (ownedUserId) {
          await database.accountRecoveryRequest.deleteMany({ where: { userId: ownedUserId } });
          await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: knownEmail } });
          await database.totpFactor.deleteMany({ where: { userId: ownedUserId } });
          await database.user.deleteMany({ where: { id: ownedUserId, email: knownEmail } });
        }
      } finally {
        await database.$disconnect();
      }
    }
  }
});

test("invitation purpose survives URL spoofing and activates a USER once with onboarding copy", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery/invitation E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  process.env.DATABASE_URL = e2eDatabaseUrl;
  process.env.VIRKI_PORTAL_URL = portalUrl;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.localhost";
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const context = await browser.newContext();
  let sessionId: string | undefined;
  try {
    const { provisionInvitedUserAccount } = await import("@virki/auth/account-invitation");
    const email = `${randomUUID()}.invited@e2e.invalid`;
    const expiresAt = new Date(Date.now() + 10 * 60_000);
    const session = await database.session.create({
      data: { userId: fixture.admin.id, tokenHash: hashSessionToken(randomBytes(32).toString("base64url")), expiresAt },
      select: { id: true }
    });
    sessionId = session.id;
    const credential = await database.administrativeCredential.upsert({
      where: { userId: fixture.admin.id },
      create: { userId: fixture.admin.id, passwordHash: await hashPassword(randomBytes(24).toString("base64url")), status: "ACTIVE" },
      update: {},
      select: { keyVersion: true }
    });
    await database.securityElevation.create({
      data: {
        userId: fixture.admin.id,
        sessionId,
        requestKey: randomBytes(24).toString("base64url"),
        protocolVersion: 1,
        credentialKeyVersion: credential.keyVersion,
        scope: "ACCOUNT_STATE_CHANGE",
        challengeHash: "e2e-fixture",
        status: "ACTIVE",
        expiresAt
      }
    });
    await provisionInvitedUserAccount({ id: fixture.admin.id }, sessionId, { email, displayName: "E2E Invitee" });
    const account = await database.user.findUnique({ where: { emailNormalized: email }, select: { id: true, passwordHash: true } });
    expect(account).not.toBeNull();
    const message = await database.emailOutboxMessage.findFirst({ where: { recipientEmail: email, kind: "ACCOUNT_INVITATION" }, select: { payload: true } });
    expect(message).not.toBeNull();
    if (!account || !message) throw new Error("Invitation E2E fixture was not created.");
    const actionUrl = decryptEmailPayload(message.payload).actionUrl;
    if (!actionUrl || new URL(actionUrl).origin !== portalUrl) throw new Error("Invitation E2E link is invalid.");
    const invitationKey = new URL(actionUrl).searchParams.get("request");
    if (!invitationKey) throw new Error("Invitation E2E key is unavailable.");
    const invitationRequest = await database.accountRecoveryRequest.findUnique({
      where: { requestKeyHash: hashRecoveryRequestKey(invitationKey) },
      select: { id: true, purpose: true }
    });
    expect(invitationRequest?.purpose).toBe("INVITATION");
    if (!invitationRequest) throw new Error("Invitation E2E record is unavailable.");
    const spoofedUrl = new URL(actionUrl);
    spoofedUrl.searchParams.set("purpose", "RECOVERY");
    const page = await context.newPage();
    await page.goto(spoofedUrl.toString());
    await explicitlyAdoptLegacyRecoveryLink(page, invitationKey, invitationRequest.id);
    await expect(page.getByRole("heading", { level: 1, name: "Ativar sua conta", exact: true })).toBeVisible();
    await expect(page.getByText("Bem-vindo ao Virki! Defina uma senha para ativar sua conta. O convite é válido por 72 horas e pode ser usado uma vez.", { exact: true })).toBeVisible();
    const passwordInput = page.getByLabel("Criar senha", { exact: true });
    await expect(passwordInput).toHaveAttribute("minlength", "12");
    const password = `Invite-${randomBytes(24).toString("base64url")}`;
    await passwordInput.fill(password);
    await page.getByRole("button", { name: "Ativar conta", exact: true }).click();
    await expect(page).toHaveURL(`${portalUrl}/login?invited=1`);
    await expect(page.getByRole("status")).toContainText("Conta ativada");
    const activated = await database.user.findUnique({ where: { id: account.id }, select: { passwordHash: true, emailVerifiedAt: true, accountStatus: true } });
    expect(activated?.passwordHash).toBeTruthy();
    expect(activated?.emailVerifiedAt).not.toBeNull();
    expect(activated?.accountStatus).toBe("ACTIVE");
    expect(await verifyPassword(activated!.passwordHash!, password)).toBe(true);
    expect(await database.accountRecoveryRequest.count({ where: { userId: account.id, purpose: "INVITATION", status: "CONSUMED" } })).toBe(1);

    await page.goto(actionUrl);
    await expect(page.locator('p.form-error[role="alert"]')).toContainText("Não foi possível abrir este link.");
    await expect(page.getByLabel("Criar senha", { exact: true })).toHaveCount(0);
    expect(await database.user.findUnique({ where: { id: account.id }, select: { passwordHash: true } })).toEqual({ passwordHash: activated?.passwordHash });
  } finally {
    if (sessionId) await database.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
    await context.close();
    await database.$disconnect();
  }
});

test("approved USER recovery keeps recovery copy and rejects a short password on the server", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery/invitation E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  process.env.DATABASE_URL = e2eDatabaseUrl;
  process.env.VIRKI_PORTAL_URL = portalUrl;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.localhost";
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const context = await browser.newContext();
  try {
    const email = `${randomUUID()}.recovery@e2e.invalid`;
    const originalPassword = `Original-${randomBytes(24).toString("base64url")}`;
    const user = await database.user.create({ data: {
      email, emailNormalized: email, displayName: "E2E Recovery User", passwordHash: await hashPassword(originalPassword),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date()
    }, select: { id: true, passwordHash: true } });
    await requestAccountRecovery(email, "pt-BR");
    const message = await database.emailOutboxMessage.findFirst({ where: { recipientEmail: email, kind: "ACCOUNT_RECOVERY" }, orderBy: { createdAt: "desc" }, select: { payload: true } });
    if (!message) throw new Error("USER recovery E2E email is unavailable.");
    const actionUrl = decryptEmailPayload(message.payload).actionUrl;
    if (!actionUrl || new URL(actionUrl).origin !== portalUrl) throw new Error("USER recovery E2E link is invalid.");
    const requestKey = new URL(actionUrl).searchParams.get("request");
    if (!requestKey) throw new Error("USER recovery E2E key is unavailable.");
    const recovery = await database.accountRecoveryRequest.findUnique({ where: { requestKeyHash: hashRecoveryRequestKey(requestKey) }, select: { id: true } });
    if (!recovery) throw new Error("USER recovery E2E record is unavailable.");
    const approvedAt = new Date();
    await database.accountRecoveryRequest.update({ where: { id: recovery.id }, data: {
      status: "APPROVED", emailVerifiedAt: approvedAt, reviewedByUserId: fixture.admin.id, approvedAt
    } });

    const page = await context.newPage();
    await page.goto(actionUrl);
    await explicitlyAdoptLegacyRecoveryLink(page, requestKey, recovery.id);
    await expect(page.getByRole("heading", { level: 1, name: "Recuperar conta", exact: true })).toBeVisible();
    await expect(page.getByRole("status")).toContainText("Defina uma nova senha para concluir o acesso à sua conta.");
    const passwordInput = page.getByLabel("Nova senha", { exact: true });
    await expect(passwordInput).toHaveAttribute("minlength", "12");
    await expect(passwordInput).toHaveAttribute("pattern", "[^\\u0000-\\u001f\\u007f-\\u009f]{12,256}");
    await passwordInput.evaluate((input) => { (input as HTMLInputElement).form!.noValidate = true; });
    await passwordInput.fill("short");
    await page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(page).toHaveURL(`${portalUrl}/recover?requestId=${recovery.id}`);
    await expect(page.locator('p.form-error[role="alert"]')).toContainText("pelo menos 12 caracteres");
    expect(await database.user.findUnique({ where: { id: user.id }, select: { passwordHash: true } })).toEqual({ passwordHash: user.passwordHash });

    const newPassword = `Recovered-${randomBytes(24).toString("base64url")}`;
    await page.getByLabel("Nova senha", { exact: true }).fill(newPassword);
    await page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(page).toHaveURL(`${portalUrl}/login?recovered=1`);
    const recovered = await database.user.findUnique({ where: { id: user.id }, select: { passwordHash: true } });
    expect(recovered?.passwordHash).not.toBeNull();
    expect(await verifyPassword(recovered!.passwordHash!, newPassword)).toBe(true);
    expect(await verifyPassword(recovered!.passwordHash!, originalPassword)).toBe(false);
    expect(await database.accountRecoveryRequest.findUnique({ where: { id: recovery.id }, select: { status: true, purpose: true, emailVerifiedAt: true } })).toMatchObject({ status: "CONSUMED", purpose: "RECOVERY", emailVerifiedAt: approvedAt });
  } finally {
    await context.close();
    await database.$disconnect();
  }
});

test("USER TOTP setup can restart after reload without restoring the pending secret", async ({ browser }) => {
  test.setTimeout(90_000);
  if (!e2eDatabaseUrl) throw new Error("TOTP E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const context = await browser.newContext();
  await context.addInitScript(() => {
    const recordLifecycleEvent = (keyPrefix: string | null, type: "pagehide" | "pageshow", persisted: boolean) => {
      if (!keyPrefix) return;
      const storageKey = `${keyPrefix}-lifecycle-events`;
      const current = JSON.parse(window.sessionStorage.getItem(storageKey) ?? "[]") as Array<{ type: string; persisted: boolean }>;
      current.push({ type, persisted });
      window.sessionStorage.setItem(storageKey, JSON.stringify(current));
    };
    window.addEventListener("pagehide", (event) => {
      const keyPrefix = window.location.pathname === "/account/security"
        ? "virki-low05-security"
        : window.location.pathname === "/"
          ? "virki-low05-portal"
          : null;
      if (!keyPrefix) return;
      window.sessionStorage.setItem(`${keyPrefix}-pagehide-persisted`, String(event.persisted));
      recordLifecycleEvent(keyPrefix, "pagehide", event.persisted);
    });
    window.addEventListener("pageshow", (event) => {
      const keyPrefix = window.location.pathname === "/account/security"
        ? "virki-low05-security"
        : window.location.pathname === "/"
          ? "virki-low05-portal"
          : null;
      if (!keyPrefix) return;
      window.sessionStorage.setItem(`${keyPrefix}-pageshow-persisted`, String(event.persisted));
      recordLifecycleEvent(keyPrefix, "pageshow", event.persisted);
    });
  });
  const page = await context.newPage();
  const low05NavigationResponses: Array<Record<string, unknown>> = [];
  const low05NavigationFailures: Array<Record<string, string>> = [];
  page.on("response", (response) => {
    const request = response.request();
    if (!request.isNavigationRequest()) return;
    const summary = describeLow05Response(response, response.url(), portalUrl) as Record<string, unknown> & { route: { origin: string; route: string } };
    if (summary.route.origin !== "portal" || !["account-security", "login", "root"].includes(summary.route.route)) return;
    const method = request.method().toUpperCase();
    low05NavigationResponses.push({ method: ["GET", "HEAD", "POST"].includes(method) ? method : "other", ...summary });
  });
  page.on("requestfailed", (request) => {
    if (!request.isNavigationRequest()) return;
    const route = classifyLow05Url(request.url(), portalUrl);
    if (route.origin !== "portal" || !["account-security", "login"].includes(route.route)) return;
    low05NavigationFailures.push({ route: route.route, error: classifyLow05NavigationError(request.failure()?.errorText) });
  });
  let sessionId: string | undefined;
  try {
    await context.clearCookies();
    expect((await context.cookies(portalUrl)).some(({ name }) => name === sessionCookieName)).toBe(false);
    const initialUrl = classifyLow05Url(portalUrl + "/account/security", portalUrl);
    let unauthenticatedResponse: import("@playwright/test").Response | null = null;
    let navigationError = "none";
    try {
      unauthenticatedResponse = await page.goto(portalUrl + "/account/security", { waitUntil: "domcontentloaded" });
    } catch (error) {
      navigationError = classifyLow05NavigationError(error);
    }
    const loginFormPresent = await page.getByLabel("E-mail", { exact: true }).count().then((count) => count > 0).catch(() => false);
    const securityHeadingPresent = await page.getByRole("heading", { level: 1, name: "Segurança", exact: true }).count().then((count) => count > 0).catch(() => false);
    const genericErrorPagePresent = await page.getByRole("heading", { name: /^(404|500|internal server error|application error)/iu }).count().then((count) => count > 0).catch(() => false);
    const navigationEvidence = {
      initialUrl,
      finalUrl: classifyLow05Url(page.url(), portalUrl),
      requestBoundary: {
        ...classifyLow05RequestBoundary(portalUrl, hubMode),
        productionHubMode: process.env.VIRKI_E2E_HUB_MODE === "production"
      },
      gotoResponse: unauthenticatedResponse ? { method: "GET", ...describeLow05Response(unauthenticatedResponse, unauthenticatedResponse.url(), portalUrl) } : null,
      nextProxyMatcherExecuted: low05NavigationResponses.some((response) =>
        (response.route as { route?: string }).route === "account-security" && response.requestIdPresent === true
      ),
      redirectChain: low05NavigationResponses,
      failedNavigationRequests: low05NavigationFailures,
      navigationError,
      page: { loginFormPresent, securityHeadingPresent, genericErrorPagePresent }
    };
    if (process.env.VIRKI_E2E_LOW05_DIAGNOSTICS === "true") {
      console.log(`LOW-05 unauthenticated navigation: ${JSON.stringify(navigationEvidence)}`);
    }
    expect(navigationError).toBe("none");
    expect(low05NavigationResponses[0]?.status).toBe(307);
    expect(low05NavigationResponses[0]?.requestIdPresent).toBe(true);
    expect(navigationEvidence.finalUrl).toEqual({ origin: "portal", route: "login", returnTo: "account-security" });
    await page.getByLabel("E-mail", { exact: true }).fill(fixture.user.email);
    await page.getByLabel("Senha", { exact: true }).fill(fixture.user.password);
    const loginResponsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/login" && response.request().method() === "POST");
    await page.getByRole("button", { name: "Entrar", exact: true }).click();
    const loginResponse = await loginResponsePromise;
    if (loginResponse.status() !== 303) throw new Error("E2E USER login did not create an email verification challenge.");
    const loginLocation = loginResponse.headers().location;
    if (!loginLocation) throw new Error("E2E USER login did not return a verification destination.");
    const verificationUrl = new URL(loginLocation, portalUrl);
    const ceremonyId = verificationUrl.searchParams.get("ceremony");
    if (verificationUrl.pathname !== "/login/verify" || verificationUrl.searchParams.get("factor") !== "email" || !ceremonyId) {
      const fixtureUserState = await database.user.findUnique({
        where: { id: fixture.user.id },
        select: { passwordHash: true, role: true, isActive: true, accountStatus: true, secondFactorMethod: true }
      });
      const factor = verificationUrl.searchParams.get("factor");
      const loginEvidence = {
        status: loginResponse.status(),
        destination: verificationUrl.pathname === "/login/verify" ? "login-verify" : verificationUrl.pathname === "/login" ? "login" : "other",
        factor: factor === "email" || factor === "totp" ? factor : "other",
        ceremonyPresent: Boolean(ceremonyId),
        errorPresent: verificationUrl.searchParams.has("error"),
        role: fixtureUserState?.role ?? "missing",
        active: fixtureUserState?.isActive ?? false,
        accountStatus: fixtureUserState?.accountStatus ?? "missing",
        secondFactorMethod: fixtureUserState?.secondFactorMethod ?? "none",
        passwordMatchesStoredHash: fixtureUserState?.passwordHash ? await verifyPassword(fixtureUserState.passwordHash, fixture.user.password) : false
      };
      if (process.env.VIRKI_E2E_LOW05_DIAGNOSTICS === "true") console.log(`LOW-05 login classification: ${JSON.stringify(loginEvidence)}`);
      throw new Error("E2E USER login did not request the expected email factor.");
    }
    await page.waitForURL((url) => url.pathname === "/login/verify" && url.searchParams.get("ceremony") === ceremonyId);
    const verificationMessage = await database.emailOutboxMessage.findFirst({
      where: {
        idempotencyKey: "security-ceremony:" + ceremonyId,
        recipientEmail: fixture.user.email,
        kind: { in: ["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"] }
      },
      select: { payload: true }
    });
    if (!verificationMessage) throw new Error("E2E USER email verification message is unavailable.");
    const emailCode = decryptEmailPayload(verificationMessage.payload).code;
    if (!/^\d{6}$/u.test(emailCode ?? "")) throw new Error("E2E USER email verification message is invalid.");
    await page.getByLabel("Código", { exact: true }).fill(emailCode!);
    await page.getByRole("button", { name: "Continuar", exact: true }).click();
    await page.waitForURL((url) => url.pathname === "/account/security");
    const sessionCookie = (await context.cookies(portalUrl)).find(({ name }) => name === sessionCookieName);
    if (!sessionCookie) throw new Error("E2E USER session cookie was not created after email verification.");
    const activeSession = await database.session.findFirst({
      where: { userId: fixture.user.id, tokenHash: hashSessionToken(sessionCookie.value) },
      select: { id: true }
    });
    if (!activeSession) throw new Error("E2E USER session was not persisted after email verification.");
    sessionId = activeSession.id;

    const securityResponse = await page.reload();
    const securityCacheControl = await securityResponse?.headerValue("cache-control") ?? "";
    const securityResponseIsNoStore = /(?:^|,)\s*no-store(?:,|$)/iu.test(securityCacheControl);
    if (process.env.VIRKI_E2E_HUB_MODE === "production") {
      expect(securityCacheControl).toBe("private, no-store, max-age=0, must-revalidate");
    } else if (!securityResponseIsNoStore) {
      // Next's development server replaces Proxy response headers with this value; the production policy is
      // checked at the Proxy boundary, while browser BFCache proof requires a production-mode server.
      expect(securityCacheControl).toBe("no-cache, must-revalidate");
      console.log("LOW-05 production BFCache proof unavailable: isolated E2E uses Next development mode.");
    }
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const actionResponses: Array<Promise<{ status: number; cacheControl: string }>> = [];
    page.on("response", (response) => {
      if (response.request().method() === "POST" && new URL(response.url()).origin === new URL(portalUrl).origin) {
        actionResponses.push(response.headerValue("cache-control").then((cacheControl) => ({ status: response.status(), cacheControl: cacheControl ?? "" })));
      }
    });
    const factorSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Autenticação multifator", exact: true }) });
    await factorSection.getByLabel("Senha atual", { exact: true }).fill(fixture.user.password);
    const beginActionIndex = actionResponses.length;
    await factorSection.getByRole("button", { name: "Configurar aplicativo autenticador", exact: true }).click();
    const secretElement = factorSection.locator("code");
    await expect(secretElement).toHaveCount(1);
    const pendingSecret = (await secretElement.textContent())?.trim() ?? "";
    if (!/^[A-Z2-7]+=*$/u.test(pendingSecret)) throw new Error("E2E TOTP enrollment secret was invalid.");
    const beginAction = (await Promise.all(actionResponses))[beginActionIndex];
    if (!beginAction) throw new Error("E2E TOTP enrollment action response was not observed.");
    if (process.env.VIRKI_E2E_HUB_MODE === "production") {
      expect(hasLow05NoStoreDirectives(beginAction.cacheControl)).toBe(true);
    }
    const pendingCode = currentTotpCode(pendingSecret);
    await page.reload();
    await expect(factorSection.getByText("Existe uma configuração TOTP pendente.", { exact: true })).toBeVisible();
    const restartButton = factorSection.getByRole("button", { name: "Reiniciar configuração do autenticador", exact: true });
    const restartPassword = factorSection.getByLabel("Senha atual", { exact: true });
    await expect(restartButton).toBeVisible();
    await expect(restartPassword).toBeVisible();
    const reloadedPendingState = await inspectSensitiveBrowserState(page, [pendingSecret, pendingCode]);
    expect(reloadedPendingState.dom, "reload must not restore the pending secret in the document").toBe(false);
    expect(reloadedPendingState.accessibility, "reload must not expose the pending secret to assistive technology").toBe(false);
    expect(reloadedPendingState.history).toBe(false);
    expect(reloadedPendingState.storage).toBe(false);
    expect(reloadedPendingState.forms).toBe(false);
    await restartPassword.focus();
    await page.keyboard.press("Tab");
    await expect(restartButton).toBeFocused();
    await restartPassword.evaluate((input) => input.removeAttribute("maxlength"));
    await restartPassword.fill("x".repeat(257));
    await restartButton.click();
    await expect(factorSection.getByRole("alert")).toContainText("Não foi possível iniciar.");
    await expect(secretElement).toHaveCount(0);
    await restartPassword.fill(fixture.user.password);
    const restartActionIndex = actionResponses.length;
    await restartButton.click();
    await expect(secretElement).toHaveCount(1);
    const secret = (await secretElement.textContent())?.trim() ?? "";
    if (!/^[A-Z2-7]+=*$/u.test(secret)) throw new Error("E2E restarted TOTP enrollment secret was invalid.");
    expect(secret).not.toBe(pendingSecret);
    const restartAction = (await Promise.all(actionResponses))[restartActionIndex];
    if (!restartAction) throw new Error("E2E TOTP restart action response was not observed.");
    if (process.env.VIRKI_E2E_HUB_MODE === "production") {
      expect(hasLow05NoStoreDirectives(restartAction.cacheControl)).toBe(true);
    }
    const code = currentTotpCode(secret);
    const staleCode = [
      currentTotpCode(pendingSecret, Date.now() - 30_000),
      currentTotpCode(pendingSecret),
      currentTotpCode(pendingSecret, Date.now() + 30_000)
    ].find((candidate) => candidate !== code);
    if (!staleCode) throw new Error("E2E could not choose a distinct TOTP code from the replaced seed.");
    const codeInput = factorSection.getByLabel("Código atual do aplicativo", { exact: true });
    await codeInput.fill(staleCode);
    await factorSection.getByRole("button", { name: "Ativar TOTP", exact: true }).click();
    await expect(factorSection.getByRole("alert")).toContainText("Código inválido ou configuração expirada.");
    await codeInput.fill(code);
    const activateActionIndex = actionResponses.length;
    await factorSection.getByRole("button", { name: "Ativar TOTP", exact: true }).click();
    await expect(factorSection.getByRole("heading", { name: "Códigos de recuperação — exibidos uma vez", exact: true })).toBeVisible();
    const codes = await factorSection.locator("section[aria-live='polite'] li code").allTextContents();
    if (codes.length !== 10 || codes.some((recoveryCode) => !/^[A-Z0-9-]{8,32}$/u.test(recoveryCode))) {
      throw new Error("E2E TOTP recovery codes were invalid.");
    }
    const activateAction = (await Promise.all(actionResponses))[activateActionIndex];
    if (!activateAction) throw new Error("E2E TOTP activation action response was not observed.");
    if (process.env.VIRKI_E2E_HUB_MODE === "production") {
      expect(hasLow05NoStoreDirectives(activateAction.cacheControl)).toBe(true);
    }
    const sensitiveValues = [fixture.user.password, emailCode!, pendingSecret, pendingCode, secret, code, ...codes];
    const visibleState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(visibleState.dom).toBe(true);
    expect(visibleState.accessibility).toBe(true);
    expect(visibleState.history).toBe(false);
    expect(visibleState.storage).toBe(false);
    expect(await database.recoveryCode.count({ where: { userId: fixture.user.id, usedAt: null } })).toBe(10);

    const firstSecurityOrigin = await page.evaluate(() => performance.timeOrigin);
    await page.goto(`${portalUrl}/?history-probe=low05`);
    await expect(page).toHaveURL(`${portalUrl}/?history-probe=low05`);
    const firstPortalOrigin = await page.evaluate(() => performance.timeOrigin);
    const historyBackResponse = await goBackToProtectedPage(page, firstSecurityOrigin);
    expect(historyBackResponse.status).toBe(200);
    // Next dev overwrites the protected Proxy header when rendering documents.
    // Production browser history always requires the full no-store policy.
    expect(isLow05ProtectedDocumentCacheControl(historyBackResponse.cacheControl, hubMode),
      `LOW-05 secure history reload header in ${hubMode}: ${historyBackResponse.cacheControl || "absent"}`).toBe(true);
    // Protected history traversal deliberately reloads the document during hydration.
    // Retry only reads interrupted by a real navigation, never failed security assertions.
    const browserCacheEvidence = await readDuringStableNavigation(page, async () => {
      await expect(page).toHaveURL(`${portalUrl}/account/security`);
      return page.evaluate(() => {
        type NotRestoredReasonTree = { reasons?: Array<{ reason: string }>; children?: NotRestoredReasonTree[] };
        type NavigationWithNotRestoredReasons = PerformanceNavigationTiming & { notRestoredReasons?: NotRestoredReasonTree | null };
        const navigation = performance.getEntriesByType("navigation")[0] as NavigationWithNotRestoredReasons | undefined;
        const collectReasons = (tree: NotRestoredReasonTree | null | undefined): string[] => tree
          ? [...(tree.reasons ?? []).map(({ reason }) => reason), ...(tree.children ?? []).flatMap(collectReasons)]
          : [];
        return {
          pagehidePersisted: window.sessionStorage.getItem("virki-low05-security-pagehide-persisted"),
          pageshowPersisted: window.sessionStorage.getItem("virki-low05-security-pageshow-persisted"),
          lifecycleEvents: JSON.parse(window.sessionStorage.getItem("virki-low05-security-lifecycle-events") ?? "[]") as Array<{ type: string; persisted: boolean }>,
          notRestoredReasons: collectReasons(navigation?.notRestoredReasons)
        };
      });
    });
    console.log(`LOW-05 browser history probe: cache-control=${securityCacheControl || "unobserved"}; pagehide.persisted=${browserCacheEvidence.pagehidePersisted ?? "unobserved"}; pageshow.persisted=${browserCacheEvidence.pageshowPersisted ?? "unobserved"}; lifecycle=${JSON.stringify(browserCacheEvidence.lifecycleEvents)}; notRestoredReasons=${browserCacheEvidence.notRestoredReasons.join(",") || "none"}`);
    console.log(`LOW-05 production browser: chromium=${browser.version()}; document-cache-control=${securityCacheControl}; begin-action-cache-control=${beginAction.cacheControl}; recovery-action-cache-control=${activateAction.cacheControl}`);
    expect(browserCacheEvidence.pagehidePersisted).not.toBeNull();
    expect(browserCacheEvidence.pageshowPersisted).not.toBeNull();
    expect(browserCacheEvidence.lifecycleEvents.some(({ type }) => type === "pagehide")).toBe(true);
    expect(browserCacheEvidence.lifecycleEvents.some(({ type }) => type === "pageshow")).toBe(true);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const backState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(backState.dom).toBe(false);
    expect(backState.accessibility).toBe(false);
    expect(backState.history).toBe(false);
    expect(backState.storage).toBe(false);
    expect(backState.forms).toBe(false);
    const firstSecurityReloadOrigin = await page.evaluate(() => performance.timeOrigin);
    await goForwardToPortalPage(page, firstPortalOrigin);
    const repeatHistoryBackResponse = await goBackToProtectedPage(page, firstSecurityReloadOrigin);
    expect(repeatHistoryBackResponse.status).toBe(200);
    expect(isLow05ProtectedDocumentCacheControl(repeatHistoryBackResponse.cacheControl, hubMode),
      `LOW-05 repeat secure history reload header in ${hubMode}: ${repeatHistoryBackResponse.cacheControl || "absent"}`).toBe(true);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const repeatBackState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(repeatBackState.dom).toBe(false);
    expect(repeatBackState.accessibility).toBe(false);
    expect(repeatBackState.history).toBe(false);
    expect(repeatBackState.storage).toBe(false);
    expect(repeatBackState.forms).toBe(false);

    await page.reload();
    await expect(factorSection.getByText("Aplicativo autenticador (TOTP) ativo.", { exact: true })).toBeVisible();
    const reloadState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(reloadState.dom).toBe(false);
    expect(reloadState.accessibility).toBe(false);
    expect(reloadState.history).toBe(false);
    expect(reloadState.storage).toBe(false);
    expect(reloadState.forms).toBe(false);

    await page.goto(`${portalUrl}/`);
    await expect(page.getByRole("heading", { level: 1, name: "Projetos", exact: true })).toBeVisible();
    const logoutResponsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/logout" && response.request().method() === "POST");
    await page.getByRole("button", { name: "Sair", exact: true }).click();
    const logoutResponse = await logoutResponsePromise;
    await page.waitForURL((url) => url.pathname === "/login");
    const logoutEvidence = describeLow05Response(logoutResponse, logoutResponse.url(), portalUrl);
    console.log(`LOW-05 logout response: ${JSON.stringify({ method: "POST", ...logoutEvidence })}`);
    expect(logoutResponse.status()).toBe(303);
    expect(logoutEvidence.cacheControl).toBe("private-no-store");
    expect((await context.cookies(portalUrl)).some(({ name }) => name === sessionCookieName)).toBe(false);
    expect((await database.session.findUnique({ where: { id: sessionId }, select: { revokedAt: true } }))?.revokedAt).not.toBeNull();

    await page.goBack({ waitUntil: "networkidle" });
    const logoutBackEvidence = await page.evaluate(() => ({
      path: window.location.pathname,
      navigationType: (window.performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type ?? "unknown",
      bodyChildCount: document.body.childElementCount,
      protectedContentCount: document.querySelectorAll("[data-protected-page-content]").length,
      protectedContentHasChildren: Array.from(document.querySelectorAll("[data-protected-page-content]"), (element) => element.childElementCount > 0),
      portalPagehidePersisted: window.sessionStorage.getItem("virki-low05-portal-pagehide-persisted"),
      portalPageshowPersisted: window.sessionStorage.getItem("virki-low05-portal-pageshow-persisted"),
      lifecycleEvents: JSON.parse(window.sessionStorage.getItem("virki-low05-portal-lifecycle-events") ?? "[]") as Array<{ type: string; persisted: boolean }>
    }));
    const postLogoutLoginFormPresent = await page.getByLabel("E-mail", { exact: true }).count().then((count) => count > 0).catch(() => false);
    const authenticatedPortalHeadingPresent = await page.getByRole("heading", { level: 1, name: "Projetos", exact: true }).count().then((count) => count > 0).catch(() => false);
    const logoutButtonPresent = await page.getByRole("button", { name: "Sair", exact: true }).count().then((count) => count > 0).catch(() => false);
    console.log(`LOW-05 post-logout history: ${JSON.stringify({ ...logoutBackEvidence, route: classifyLow05Url(page.url(), portalUrl), loginFormPresent: postLogoutLoginFormPresent, authenticatedPortalHeadingPresent, logoutButtonPresent, recentNavigationResponses: low05NavigationResponses.slice(-6) })}`);
    await expect(page.getByLabel("E-mail", { exact: true })).toBeVisible();
    expect(logoutBackEvidence.path).toBe("/login");
    expect(logoutBackEvidence.lifecycleEvents.some(({ type }) => type === "pagehide")).toBe(true);
    expect(authenticatedPortalHeadingPresent).toBe(false);
    expect(logoutButtonPresent).toBe(false);
    const loggedOutState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(loggedOutState.dom).toBe(false);
    expect(loggedOutState.accessibility).toBe(false);
    expect(loggedOutState.history).toBe(false);
    expect(loggedOutState.storage).toBe(false);
    expect(loggedOutState.forms).toBe(false);

  } finally {
    if (sessionId) await database.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
    await context.close();
    await database.$disconnect();
  }
});

async function readDuringStableNavigation<T>(page: import("@playwright/test").Page, read: () => Promise<T>): Promise<T> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      await page.waitForLoadState("load", { timeout: 10_000 });
      return await read();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (attempt === 3 || !/(?:execution context was destroyed|page is navigating|frame was detached)/iu.test(message)) {
        throw error;
      }
    }
  }
  throw new Error("The browser document did not stabilize after navigation.");
}

async function inspectSensitiveBrowserState(page: import("@playwright/test").Page, sensitiveValues: string[]) {
  return readDuringStableNavigation(page, async () => {
    const html = await page.content();
    const accessibleSnapshot = await page.locator("body").ariaSnapshot();
    const pageState = await page.evaluate(() => ({
      history: JSON.stringify(window.history.state ?? null),
      storage: [window.localStorage, window.sessionStorage].flatMap((storage) => Object.keys(storage).map((key) => storage.getItem(key) ?? "")).join("\n"),
      forms: Array.from(document.forms).flatMap((form) => Array.from(form.elements).map((element) => "value" in element ? String(element.value ?? "") : "")).join("\n"),
      dom: document.documentElement.outerHTML
    }));
    const containsValue = (text: string) => sensitiveValues.some((value) => value.length > 0 && text.includes(value));
    return {
      dom: containsValue(html) || containsValue(pageState.dom),
      accessibility: containsValue(accessibleSnapshot),
      history: containsValue(pageState.history),
      storage: containsValue(pageState.storage),
      forms: containsValue(pageState.forms)
    };
  });
}

function currentTotpCode(secret: string, now = Date.now()): string {
  const key = decodeBase32(secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function decodeBase32(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const character of value.replace(/=+$/u, "")) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error("TOTP E2E secret is invalid.");
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return Buffer.from(bytes);
}
