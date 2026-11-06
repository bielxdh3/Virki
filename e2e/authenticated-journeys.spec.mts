import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test, type BrowserContext } from "@playwright/test";
import { getDeviceCookieName, getSessionCookieName } from "@virki/auth/constants";
import { hashSessionToken, verifyPassword } from "@virki/auth";
import { decryptEmailPayload } from "@virki/auth/email";
import { getPendingAccountRecoveryQueueWhere } from "@virki/auth/security";
import { PrismaClient } from "@virki/database";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

// @ts-expect-error This JavaScript safety helper has no declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const productionHubMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const portalUrl = productionHubMode ? "https://portal.localhost" : "https://portal.localhost:3001";
const hubUrl = productionHubMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const sessionCookieName = getSessionCookieName({ NODE_ENV: productionHubMode ? "production" : process.env.NODE_ENV });
const deviceCookieName = getDeviceCookieName({ NODE_ENV: productionHubMode ? "production" : process.env.NODE_ENV });
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE;
const hasFixture = Boolean(fixturePath && existsSync(fixturePath));

test.skip(!e2eDatabaseUrl || !hasFixture, "Authenticated E2E requires an explicit disposable E2E database and its global-setup fixture.");

type AccountFixture = {
  id: string;
  email: string;
  password: string;
  deviceToken: string;
};

type RecoveryReviewerFixture = AccountFixture & { administrativePassword: string };

type AuthFixture = {
  user: AccountFixture;
  recoveryTargetUser: AccountFixture;
  admin: AccountFixture;
  recoveryReviewer: RecoveryReviewerFixture;
  projectName: string;
  projectLaunchUrl: string;
  ungrantedProjectName: string;
  disabledProjectName: string;
};

let fixture: AuthFixture;

test.beforeAll(async () => {
  if (!fixturePath) throw new Error("Authenticated E2E fixture path is unavailable.");
  const value: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!isAuthFixture(value)) throw new Error("Authenticated E2E fixture is invalid.");
  fixture = value;
});

test("USER can sign in and sees only the granted enabled project", async ({ browser }) => {
  const context = await browser.newContext();
  try {
    await rememberDevice(context, portalUrl, fixture.user.deviceToken);
    const page = await context.newPage();
    await page.goto(`${portalUrl}/`);
    await expect(page).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
    await signIn(page, fixture.user);

    await expect(page).toHaveURL(`${portalUrl}/`);
    await expect(page.getByRole("heading", { level: 1, name: "Projetos", exact: true })).toBeVisible();
    const projectLink = page.getByRole("link", { name: fixture.projectName });
    await expect(projectLink).toBeVisible();
    await expect(projectLink).toHaveAttribute("href", fixture.projectLaunchUrl);
    await expect(page.getByText(fixture.ungrantedProjectName, { exact: true })).toHaveCount(0);
    await expect(page.getByText(fixture.disabledProjectName, { exact: true })).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test("ADMIN restarts a failed credential setup challenge with a fresh same-origin CSRF token", async ({ browser }) => {
  test.setTimeout(60_000);
  const context = await browser.newContext();
  const prisma = createE2ePrismaClient();
  let sessionId: string | undefined;
  try {
    const token = randomBytes(32).toString("base64url");
    const session = await prisma.session.create({ data: {
      userId: fixture.admin.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 600_000), authenticationMethods: ["pwd", "otp", "mfa"]
    }, select: { id: true } });
    sessionId = session.id;
    await context.addCookies([{ name: sessionCookieName, value: token, url: hubUrl, httpOnly: true, secure: true, sameSite: "Lax" }]);
    const page = await context.newPage();
    await addCloudflareAccessHeader(page);
    await page.goto(`${hubUrl}/admin/security`);
    const credentialSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Credencial administrativa", exact: true }) });
    const setupForm = credentialSection.locator("form").first();
    await setupForm.getByLabel("Senha normal atual", { exact: true }).fill(fixture.admin.password);
    await setupForm.getByRole("button", { name: "Enviar código de confirmação", exact: true }).click();
    const firstChallengeForm = credentialSection.locator("form").first();
    const firstRequestKey = await firstChallengeForm.locator('input[name="requestKey"]').inputValue();
    const firstCsrf = await firstChallengeForm.locator('input[name="csrfToken"]').inputValue();
    const firstCode = await readLatestAdminVerificationCode(prisma, fixture.admin.email, firstRequestKey);
    const invalidCode = firstCode === "000000" ? "000001" : "000000";
    await firstChallengeForm.getByLabel("Código enviado por e-mail", { exact: true }).fill(invalidCode);
    const candidatePassword = randomBytes(32).toString("base64url");
    await firstChallengeForm.locator('input[name="newPassword"]').fill(candidatePassword);
    await firstChallengeForm.locator('input[name="confirmPassword"]').fill(candidatePassword + "x");
    await firstChallengeForm.getByRole("button", { name: "Configurar credencial", exact: true }).click();
    await expect(firstChallengeForm.getByRole("alert")).toContainText("duas senhas administrativas precisam ser iguais");
    expect((await prisma.securityElevation.findUnique({ where: { requestKey: firstRequestKey }, select: { status: true } }))?.status).toBe("PENDING");
    await firstChallengeForm.locator('input[name="confirmPassword"]').fill(candidatePassword);
    await firstChallengeForm.getByRole("button", { name: "Configurar credencial", exact: true }).click();
    await expect(firstChallengeForm.getByRole("alert")).toContainText("Código inválido ou expirado");
    const restartLink = credentialSection.getByRole("link", { name: "Iniciar configuração novamente", exact: true });
    await expect(restartLink).toBeVisible();
    expect((await prisma.securityElevation.findUnique({ where: { requestKey: firstRequestKey }, select: { status: true } }))?.status).toBe("PENDING");

    await restartLink.click();
    await expect(page).toHaveURL(`${hubUrl}/admin/security?restart=credential#admin-content`);
    const restartedForm = credentialSection.locator("form").first();
    expect(await restartedForm.locator('input[name="requestKey"]').count()).toBe(0);
    const freshCsrf = await restartedForm.locator('input[name="csrfToken"]').inputValue();
    expect(freshCsrf).not.toBe(firstCsrf);
    await restartedForm.getByLabel("Senha normal atual", { exact: true }).fill(fixture.admin.password);
    await restartedForm.getByRole("button", { name: "Enviar código de confirmação", exact: true }).click();
    const newRequestKey = await credentialSection.locator("form").first().locator('input[name="requestKey"]').inputValue();
    expect(newRequestKey).not.toBe(firstRequestKey);
    expect((await prisma.securityElevation.findUnique({ where: { requestKey: firstRequestKey }, select: { status: true } }))?.status).toBe("REVOKED");
    expect((await prisma.securityElevation.findUnique({ where: { requestKey: newRequestKey }, select: { status: true } }))?.status).toBe("PENDING");
  } finally {
    if (sessionId) {
      await prisma.securityElevation.updateMany({ where: { userId: fixture.admin.id, sessionId, status: "PENDING" }, data: { status: "REVOKED", revokedAt: new Date() } });
      await prisma.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
    }
    await context.close();
    await prisma.$disconnect();
  }
});

test("ADMIN can sign in to a protected page, navigate, and have the session revoked on logout", async ({ browser }) => {
  // Multi-step ADMIN journey: every ADMIN sign-in now includes the emailed second-factor step.
  test.setTimeout(90_000);
  const context = await browser.newContext();
  const prisma = createE2ePrismaClient();
  let firstHydrationMismatchPhase: string | undefined;
  let adminJourneyPhase = "initialization";
  let lifecycleConnectionSlug: string | undefined;
  const oneTimeSecrets = new Map<"created" | "rotated", string>();
  try {
    await rememberDevice(context, hubUrl, fixture.admin.deviceToken);
    await context.addInitScript(() => {
      const key = "virki-e2e-oidc-secret-lifecycle";
      window.addEventListener("pageshow", (event) => {
        localStorage.setItem(`${key}:pageshow`, event.persisted ? "persisted" : "not-persisted");
        const navigation = performance.getEntriesByType("navigation")[0] as (PerformanceNavigationTiming & { notRestoredReasons?: { reasons?: Array<{ reason?: unknown }> } }) | undefined;
        localStorage.setItem(`${key}:navigation`, navigation?.type ?? "unknown");
        const reasons = (navigation?.notRestoredReasons?.reasons ?? [])
          .slice(0, 8)
          .map(({ reason }) => typeof reason === "string" ? reason.replace(/[^a-z0-9_-]/giu, "").slice(0, 40) : "unknown")
          .filter(Boolean);
        localStorage.setItem(`${key}:notRestoredReasons`, reasons.join(",") || "none");
      });
    });
    const page = await context.newPage();
    const hubPageResponses = observeHubPageResponses(page, "/admin/connections");
    const hubPagePolicies = observeHubResponsePolicies(page, "/admin/connections");
    const initialAdminRouteResponses: Promise<{ status: number; origin: string; pathname: string; locationPath: string; accessReasonHeaderPresent: boolean }>[] = [];
    const loginFlowResponses: Promise<{ method: string; pathname: string; status: number; locationPath: string }>[] = [];
    page.on("response", (response) => {
      const responseUrl = new URL(response.url());
      if (responseUrl.origin === hubUrl && ["/api/login", "/login", "/login/verify", "/admin/accounts"].includes(responseUrl.pathname)) {
        loginFlowResponses.push((async () => {
          const locationHeader = await response.headerValue("location");
          let locationPath = "none";
          if (locationHeader) {
            try {
              const location = new URL(locationHeader, hubUrl);
              locationPath = location.origin === hubUrl ? location.pathname : "external";
            } catch {
              locationPath = "invalid";
            }
          }
          return { method: response.request().method(), pathname: responseUrl.pathname, status: response.status(), locationPath };
        })());
      }
      if (responseUrl.origin !== hubUrl || responseUrl.pathname !== "/admin/accounts" || response.request().resourceType() !== "document") return;
      initialAdminRouteResponses.push((async () => {
        const locationHeader = await response.headerValue("location");
        const accessReasonHeader = await response.headerValue("x-virki-e2e-access-reason");
        let locationPath = "none";
        if (locationHeader) {
          try {
            const location = new URL(locationHeader, hubUrl);
            locationPath = location.origin === hubUrl ? location.pathname : "external";
          } catch {
            locationPath = "invalid";
          }
        }
        return {
          status: response.status(),
          origin: responseUrl.origin,
          pathname: responseUrl.pathname,
          locationPath,
          accessReasonHeaderPresent: Boolean(accessReasonHeader)
        };
      })());
    });
    page.on("console", (message) => {
      if (/hydration|server-rendered html/iu.test(message.text())) {
        firstHydrationMismatchPhase ??= adminJourneyPhase;
      }
    });
    await addCloudflareAccessHeader(page);
    adminJourneyPhase = "initial-admin-page-and-login";
    const adminUserState = await prisma.user.findUnique({
      where: { id: fixture.admin.id },
      select: { role: true, isActive: true, accountStatus: true }
    });
    const administrativeCredentialState = await prisma.administrativeCredential.findUnique({
      where: { userId: fixture.admin.id },
      select: { status: true }
    });
    const activeElevationCount = await prisma.securityElevation.count({
      where: { userId: fixture.admin.id, status: "ACTIVE", OR: [{ manualUntilRevoked: true }, { expiresAt: { gt: new Date() } }] }
    });
    const initialAdminResponse = await page.goto(`${hubUrl}/admin/accounts`);
    const initialAdminRouteObservations = await Promise.all(initialAdminRouteResponses);
    const initialHubCookies = (await context.cookies(hubUrl)).map(({ name, domain, path, httpOnly, secure, sameSite }) => ({ name, domain, path, httpOnly, secure, sameSite }));
    console.info(`Production Hub initial ADMIN route: ${JSON.stringify({
      hubOrigin: new URL(hubUrl).origin,
      accessIssuerOrigin: process.env.VIRKI_E2E_ACCESS_ISSUER ? new URL(process.env.VIRKI_E2E_ACCESS_ISSUER).origin : "missing",
      directResponseStatus: initialAdminResponse?.status() ?? null,
      responseChain: initialAdminRouteObservations,
      cookies: initialHubCookies,
      adminRole: adminUserState?.role ?? "missing",
      adminActive: Boolean(adminUserState?.isActive && adminUserState.accountStatus === "ACTIVE"),
      administrativeCredentialStatus: administrativeCredentialState?.status ?? "missing",
      activeElevationCount,
      sessionCookiePresent: initialHubCookies.some(({ name }) => name === sessionCookieName),
      rememberedDeviceCookiePresent: initialHubCookies.some(({ name }) => name === deviceCookieName)
    })}`);
    await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
    await signIn(page, fixture.admin);
    const sessionCookie = (await context.cookies(hubUrl)).find((cookie) => cookie.name === sessionCookieName);
    const postLoginCookies = (await context.cookies(hubUrl)).map(({ name, domain, path, httpOnly, secure, sameSite }) => ({ name, domain, path, httpOnly, secure, sameSite }));
    const activeSessionCount = await prisma.session.count({ where: { userId: fixture.admin.id, revokedAt: null, expiresAt: { gt: new Date() } } });
    console.info(`Production Hub login result: ${JSON.stringify({
      currentPath: new URL(page.url()).pathname,
      responses: await Promise.all(loginFlowResponses),
      cookies: postLoginCookies,
      sessionCookiePresent: Boolean(sessionCookie),
      activeSessionCount
    })}`);
    expect(sessionCookie?.value).toBeTruthy();
    if (!sessionCookie) throw new Error("Authenticated E2E session cookie was not created.");

    await expect(page).toHaveURL(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    await assertAdminSkipLink(page);

    adminJourneyPhase = "authenticated-return-target-allowlist";
    for (const target of [
      { returnTo: "/account/security", expectedPath: "/account/security", heading: "Segurança" },
      { returnTo: "https://attacker.invalid/", expectedPath: "/admin/accounts", heading: "Contas" }
    ]) {
      const returnContext = await browser.newContext();
      try {
        const returnPage = await returnContext.newPage();
        await addCloudflareAccessHeader(returnPage);
        await returnPage.goto(`${hubUrl}/login?returnTo=${encodeURIComponent(target.returnTo)}`);
        await signIn(returnPage, fixture.admin);
        await expect(returnPage).toHaveURL(`${hubUrl}${target.expectedPath}`);
        await expect(returnPage.getByRole("heading", { level: 1, name: target.heading, exact: true })).toBeVisible();
      } finally {
        await returnContext.close();
      }
    }

    await page.getByRole("link", { name: "Acessos", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/access`);
    await expect(page.getByRole("heading", { level: 1, name: "Acessos", exact: true })).toBeVisible();
    await expect(page.getByText(`E2E User → ${fixture.projectName}`, { exact: true })).toBeVisible();
    await assertAdminSkipLink(page);

    adminJourneyPhase = "connection-edit-without-elevation";
    await page.getByRole("link", { name: "Conexões", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/connections`);
    await assertAdminSkipLink(page);
    console.info("ADMIN connections main-document policy: " + await hubPagePolicies());
    const projectRow = page.locator("article").filter({ hasText: fixture.projectName });
    const editDetails = projectRow.locator("details").filter({ hasText: "Editar configuração" });
    // Native <details> clicks during React hydration mutate the SSR open
    // attribute, causing a real console hydration mismatch. Wait for the
    // component's post-hydration effect; do not suppress the warning.
    await expect(editDetails).toHaveAttribute("data-hydrated", "true");
    await editDetails.getByText("Editar configuração", { exact: true }).click();
    const projectNameInput = editDetails.locator('input[name="name"]');
    const redirectUrisInput = editDetails.locator('textarea[name="redirectUris"]');
    await projectNameInput.fill("Draft preserved without elevation");
    await redirectUrisInput.fill("https://project.e2e.invalid/callback");
    await editDetails.getByRole("button", { name: "Salvar configuração", exact: true }).click();
    await expect(editDetails).toHaveAttribute("open", "");
    const editAlert = editDetails.getByRole("alert");
    await expect(editAlert).toContainText("elevação de segurança");
    await expect(editAlert).toContainText("valores enviados foram mantidos");
    await expect(projectNameInput).toHaveValue("Draft preserved without elevation");
    await expect(redirectUrisInput).toHaveValue("https://project.e2e.invalid/callback");

    await page.getByRole("link", { name: "Segurança", exact: true }).click();
    await expect(page).toHaveURL(hubUrl + "/admin/security");
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    await assertAdminSkipLink(page);

    adminJourneyPhase = "administrative-credential-verification";
    const credentialSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Credencial administrativa", exact: true }) });
    const credentialForm = credentialSection.locator("form").first();
    let administrativePassword = randomBytes(32).toString("base64url");
    await credentialForm.getByLabel("Senha normal atual", { exact: true }).fill(fixture.admin.password);
    await credentialForm.getByRole("button", { name: "Enviar código de confirmação", exact: true }).click();
    const confirmationCodeInput = credentialForm.getByLabel("Código enviado por e-mail", { exact: true });
    const startError = credentialForm.getByRole("alert");
    let confirmationStarted = false;
    try {
      await expect(confirmationCodeInput.or(startError)).toBeVisible({ timeout: 15_000 });
      confirmationStarted = await confirmationCodeInput.isVisible();
    } catch {
      // The scoped state below distinguishes a delayed or rejected flow without exposing its code.
    }
    if (!confirmationStarted) {
      const ceremony = await prisma.securityElevation.findFirst({
        where: { userId: fixture.admin.id, scope: "ADMIN_CREDENTIAL_SETUP", status: "PENDING" },
        select: { requestKey: true }
      });
      const outboxCount = ceremony
        ? await prisma.emailOutboxMessage.count({
          where: { idempotencyKey: `admin-elevation:${ceremony.requestKey}`, kind: "ADMIN_EMAIL_VERIFICATION", recipientEmail: fixture.admin.email }
        })
        : 0;
      const feedback = (await startError.textContent().catch(() => null))?.trim() || "none";
      throw new Error(`E2E ADMIN verification did not reach the code form (feedback=${feedback}; pendingCeremony=${Boolean(ceremony)}; matchingOutboxMessage=${outboxCount === 1}).`);
    }
    const credentialRequestKey = await credentialForm.locator('input[name="requestKey"]').inputValue();
    const credentialCode = await readLatestAdminVerificationCode(prisma, fixture.admin.email, credentialRequestKey);
    await credentialForm.getByLabel("Código enviado por e-mail", { exact: true }).fill(credentialCode);
    await credentialForm.locator('input[name="newPassword"]').fill(administrativePassword);
    await credentialForm.locator('input[name="confirmPassword"]').fill(administrativePassword);
    await credentialForm.getByRole("button", { name: "Configurar credencial", exact: true }).click();
    try {
      await expect(credentialSection.getByRole("heading", { name: /Códigos de recuperação/u })).toBeVisible();
      await expect(credentialSection.locator("ul li")).toHaveCount(10);
    } catch {
      const credentialState = await prisma.administrativeCredential.findUnique({
        where: { userId: fixture.admin.id },
        select: { status: true }
      });
      const ceremonyState = await prisma.securityElevation.findUnique({
        where: { requestKey: credentialRequestKey },
        select: { status: true }
      });
      const recoveryCodeCount = await prisma.administrativeRecoveryCode.count({ where: { userId: fixture.admin.id } });
      throw new Error(`E2E ADMIN recovery-code view is unavailable (credential=${credentialState?.status ?? "missing"}; ceremony=${ceremonyState?.status ?? "missing"}; storedCodeCount=${recoveryCodeCount}).`);
    }
    const initialAdministrativeRecoveryCode = (await credentialSection.locator("ul li").first().textContent())?.trim();
    if (!initialAdministrativeRecoveryCode) throw new Error("E2E ADMIN recovery code is unavailable for the recovery journey.");
    adminJourneyPhase = "credential-acknowledgment";
    const credentialBeforeAcknowledgment = await prisma.administrativeCredential.findUnique({
      where: { userId: fixture.admin.id }, select: { status: true, keyVersion: true }
    });
    expect(credentialBeforeAcknowledgment?.status).toBe("ACTIVE");
    expect(await prisma.administrativeRecoveryCode.count({ where: { userId: fixture.admin.id, usedAt: null } })).toBe(10);
    const predecessorUrl = `${hubUrl}/admin/security#recovery-code-predecessor`;
    const acknowledgementUrl = `${hubUrl}/admin/security?status=credential#admin-content`;
    // Two native fragment entries deliberately keep the document that displayed the codes reachable with Back.
    await page.evaluate(() => { window.location.hash = "recovery-code-predecessor"; });
    await expect(page).toHaveURL(predecessorUrl);
    await expect(credentialSection.locator("ul li code")).toHaveCount(10);
    await page.evaluate(() => { window.location.hash = "recovery-code-acknowledgment"; });
    await expect(page).toHaveURL(`${hubUrl}/admin/security#recovery-code-acknowledgment`);
    await expect(credentialSection.locator("ul li code")).toHaveCount(10);
    // There must be no native href navigation when a sensitive one-time
    // control is visible before React hydrates. Otherwise the default anchor
    // follows its href with a PUSH (rather than our scrub-and-REPLACE click),
    // leaving an extra fragment entry behind and possibly a secret-bearing
    // document in browser history.
    const acknowledgeRecoveryCodes = credentialSection.getByRole("button", { name: "Continuar para elevação", exact: true });
    await expect(acknowledgeRecoveryCodes).toHaveAttribute("type", "button");
    await expect(acknowledgeRecoveryCodes).toBeDisabled();
    await credentialSection.getByRole("checkbox", { name: /Guardei os dez códigos de recuperação fora do Virki/u }).check();
    await expect(acknowledgeRecoveryCodes).toBeEnabled();
    await expect(credentialSection.getByRole("link", { name: "Continuar para elevação", exact: true })).toHaveCount(0);
    const recoveryCodeInput = credentialSection.getByLabel("Código de recuperação administrativa", { exact: true });
    const recoveryForm = recoveryCodeInput.locator("xpath=ancestor::form");
    const historyEntriesBeforeDismissal = await page.evaluate(() => window.history.length);
    await acknowledgeRecoveryCodes.click();
    await expect(page).toHaveURL(acknowledgementUrl);
    // Native window.location.replace must not add a history entry. If the
    // pre-hydration fallback follows an anchor href instead, Chrome PUSHes
    // and one Back stops at the old one-time-code acknowledgment fragment.
    expect(await page.evaluate(() => window.history.length)).toBe(historyEntriesBeforeDismissal);
    await expect(page.getByRole("status")).toContainText("Credencial administrativa configurada");
    await expect(credentialSection.locator("ul li code")).toHaveCount(0);
    await expect(acknowledgeRecoveryCodes).toHaveCount(0);
    await expect(recoveryCodeInput).toBeVisible();
    await page.goBack();
    try {
      await expect(page).toHaveURL(predecessorUrl);
    } catch {
      // The general E2E log scrubber masks both query and hash, making
      // distinct protected URLs look identical. Report ONLY a fixed
      // allowlisted route/query/fragment classification (never raw URLs).
      const observed = new URL(page.url());
      const pathname = observed.origin === hubUrl && observed.pathname === "/admin/security" ? "security" : "other";
      const query = observed.search === "" ? "none" : observed.search === "?status=credential" ? "credential" : "other";
      const fragment = observed.hash === "#recovery-code-predecessor" ? "predecessor"
        : observed.hash === "#recovery-code-acknowledgment" ? "acknowledgment"
          : observed.hash === "#admin-content" ? "admin-content" : observed.hash === "" ? "none" : "other";
      throw new Error(`E2E ADMIN browser Back history mismatch (route=${pathname}; query=${query}; fragment=${fragment}).`);
    }
    await expect(credentialSection.locator("ul li code")).toHaveCount(0);
    await expect(acknowledgeRecoveryCodes).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    await expect(recoveryForm).toBeVisible();
    await page.goForward();
    await expect(page).toHaveURL(acknowledgementUrl);
    await expect(page.getByRole("status")).toContainText("Credencial administrativa configurada");
    await expect(credentialSection.locator("ul li code")).toHaveCount(0);
    await expect(acknowledgeRecoveryCodes).toHaveCount(0);
    await expect(recoveryForm).toBeVisible();
    expect(await prisma.administrativeCredential.findUnique({
      where: { userId: fixture.admin.id }, select: { status: true, keyVersion: true }
    })).toEqual(credentialBeforeAcknowledgment);
    expect(await prisma.administrativeRecoveryCode.count({ where: { userId: fixture.admin.id, usedAt: null } })).toBe(10);
    const recoveredAdministrativePassword = randomBytes(32).toString("base64url");
    await recoveryForm.getByLabel("Senha normal atual", { exact: true }).fill(fixture.admin.password);
    await recoveryForm.getByLabel("Código de recuperação administrativa", { exact: true }).fill("invalid-one-time-code");
    await recoveryForm.getByLabel("Nova senha administrativa (16 caracteres ou mais)", { exact: true }).fill(recoveredAdministrativePassword);
    await recoveryForm.getByRole("button", { name: "Recuperar credencial", exact: true }).click();
    await expect(recoveryForm.getByRole("alert")).toContainText("Não foi possível recuperar a credencial");
    await recoveryForm.getByLabel("Senha normal atual", { exact: true }).fill(fixture.admin.password);
    await recoveryForm.getByLabel("Código de recuperação administrativa", { exact: true }).fill(initialAdministrativeRecoveryCode);
    await recoveryForm.getByLabel("Nova senha administrativa (16 caracteres ou mais)", { exact: true }).fill(recoveredAdministrativePassword);
    await recoveryForm.getByRole("button", { name: "Recuperar credencial", exact: true }).click();
    await expect(credentialSection.getByRole("heading", { name: /Códigos de recuperação/u })).toBeVisible();
    await expect(credentialSection.locator("ul li")).toHaveCount(10);
    administrativePassword = recoveredAdministrativePassword;

    const elevationSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Elevação temporária", exact: true }) });
    const elevationForm = elevationSection.locator("form").first();
    adminJourneyPhase = "security-elevation";
    await elevationForm.locator('select[name="scope"]').selectOption("PROJECT_CONNECTION_MANAGE");
    await elevationForm.getByLabel("Senha normal atual", { exact: true }).fill(fixture.admin.password);
    await elevationForm.getByLabel("Senha administrativa", { exact: true }).fill(administrativePassword);
    await elevationForm.getByRole("button", { name: "Solicitar elevação", exact: true }).click();
    const elevationVerificationForm = elevationSection.locator("form").nth(1);
    await expect(elevationVerificationForm.getByLabel("Código", { exact: true })).toBeVisible();
    const elevationRequestKey = await elevationVerificationForm.locator('input[name="requestKey"]').inputValue();
    const elevationCode = await readLatestAdminVerificationCode(prisma, fixture.admin.email, elevationRequestKey);
    await elevationVerificationForm.getByLabel("Código", { exact: true }).fill(elevationCode);
    await elevationVerificationForm.getByRole("button", { name: "Ativar elevação", exact: true }).click();
    await expect(page).toHaveURL(hubUrl + "/admin/security?status=elevation#admin-content");
    const connectionElevationArticle = elevationSection.locator("article").filter({ hasText: "Gerenciar conexões" });
    try {
      await expect(connectionElevationArticle).toBeVisible();
    } catch {
      const [verifiedElevation, authenticatedSession, renderedScopes] = await Promise.all([
        prisma.securityElevation.findUnique({
          where: { requestKey: elevationRequestKey },
          select: { status: true, scope: true, userId: true, sessionId: true, expiresAt: true, manualUntilRevoked: true }
        }),
        prisma.session.findUnique({ where: { tokenHash: hashSessionToken(sessionCookie.value) }, select: { id: true, userId: true, revokedAt: true, expiresAt: true } }),
        elevationSection.locator("article:visible .row-main strong").allTextContents()
      ]);
      const sessionMatches = Boolean(verifiedElevation && authenticatedSession && verifiedElevation.sessionId === authenticatedSession.id);
      const sessionUserMatches = authenticatedSession?.userId === fixture.admin.id;
      const elevationIsValid = Boolean(verifiedElevation && verifiedElevation.status === "ACTIVE" && (verifiedElevation.manualUntilRevoked || verifiedElevation.expiresAt > new Date()));
      const sessionIsValid = Boolean(authenticatedSession && !authenticatedSession.revokedAt && authenticatedSession.expiresAt > new Date());
      throw new Error(`E2E active elevation was not rendered (dbStatus=${verifiedElevation?.status ?? "missing"}; dbScope=${verifiedElevation?.scope ?? "missing"}; adminMatches=${verifiedElevation?.userId === fixture.admin.id}; sessionUserMatches=${sessionUserMatches}; sessionMatches=${sessionMatches}; elevationValid=${elevationIsValid}; sessionValid=${sessionIsValid}; renderedScopes=${renderedScopes.join("|") || "none"}).`);
    }

    await page.getByRole("link", { name: "Conexões", exact: true }).click();
    await expect(page).toHaveURL(hubUrl + "/admin/connections");
    lifecycleConnectionSlug = `secret-lifecycle-${randomBytes(8).toString("hex")}`;
    const lifecycleOrigin = `https://${lifecycleConnectionSlug}.example.invalid`;
    const createConnectionForm = page.getByRole("button", { name: "Registrar conexão", exact: true }).locator("xpath=ancestor::form[1]");
    await createConnectionForm.getByLabel("Nome", { exact: true }).fill("One-time secret lifecycle fixture");
    await createConnectionForm.getByLabel("Identificador (slug)", { exact: true }).fill(lifecycleConnectionSlug);
    await createConnectionForm.getByLabel("Origem HTTPS", { exact: true }).fill(lifecycleOrigin);
    await createConnectionForm.getByLabel("Redirect URIs exatas", { exact: true }).fill(`${lifecycleOrigin}/oidc/callback`);
    adminJourneyPhase = "created-secret-ui-action";
    await createConnectionForm.getByRole("button", { name: "Registrar conexão", exact: true }).click();
    const creationSecretPanel = page.locator("[data-sensitive-one-time-value='true']").filter({ hasText: "Credenciais exibidas uma vez" });
    await expect(creationSecretPanel).toBeVisible();
    oneTimeSecrets.set("created", await creationSecretPanel.locator("code").nth(1).innerText());
    expect(/^[A-Za-z0-9_-]{64}$/u.test(oneTimeSecrets.get("created") ?? ""), "created one-time secret has the expected format").toBe(true);
    const createdConnection = await prisma.projectConnection.findUnique({ where: { slug: lifecycleConnectionSlug }, select: { clientId: true } });
    expect(createdConnection?.clientId).toMatch(/^biel_[A-Za-z0-9_-]{24}$/u);

    adminJourneyPhase = "created-secret-pagehide-navigation-back";
    await page.evaluate(() => {
      const key = "virki-e2e-oidc-secret-lifecycle";
      localStorage.removeItem(`${key}:created-pagehide`);
      localStorage.removeItem(`${key}:created-pageshow`);
      localStorage.removeItem(`${key}:created-navigation`);
      localStorage.removeItem(`${key}:created-notRestoredReasons`);
      localStorage.removeItem(`${key}:created-pagehide-persisted`);
      localStorage.removeItem(`${key}:created-same-document-restored`);
      const documentMarker = {};
      Object.defineProperty(window, "__virkiCreatedSecretDocumentMarker", { value: documentMarker, configurable: true });
      window.addEventListener("pagehide", (event) => {
        const panel = document.querySelector("[data-sensitive-one-time-value='true']");
        localStorage.setItem(`${key}:created-pagehide`, panel ? "still-visible" : "scrubbed");
        localStorage.setItem(`${key}:created-pagehide-persisted`, event.persisted ? "true" : "false");
      }, { once: true });
      window.addEventListener("pageshow", (event) => {
        localStorage.setItem(`${key}:created-pageshow`, event.persisted ? "persisted" : "not-persisted");
        const restoredMarker = (window as Window & { __virkiCreatedSecretDocumentMarker?: object }).__virkiCreatedSecretDocumentMarker;
        localStorage.setItem(`${key}:created-same-document-restored`, event.persisted && restoredMarker === documentMarker ? "true" : "false");
        const navigation = performance.getEntriesByType("navigation")[0] as (PerformanceNavigationTiming & { notRestoredReasons?: { reasons?: Array<{ reason?: unknown }> } }) | undefined;
        localStorage.setItem(`${key}:created-navigation`, navigation?.type ?? "unknown");
        const reasons = (navigation?.notRestoredReasons?.reasons ?? []).slice(0, 8).map(({ reason }) => typeof reason === "string" ? reason.replace(/[^a-z0-9_-]/giu, "").slice(0, 40) : "unknown");
        localStorage.setItem(`${key}:created-notRestoredReasons`, reasons.join(",") || "none");
      });
    });
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    const creationBackResponse = await page.goBack();
    await expect(page).toHaveURL(hubUrl + "/admin/connections");
    const lifecycleConnectionRow = page.locator("article.connection-row").filter({ hasText: lifecycleConnectionSlug });
    await expect(lifecycleConnectionRow).toBeVisible();
    await expect(page.locator("[data-sensitive-one-time-value='true']")).toHaveCount(0);
    const creationSecretAbsentFromHtml = !(await page.content()).includes(oneTimeSecrets.get("created") ?? "");
    const creationSecretAbsentFromAccessibility = !(await page.locator("body").ariaSnapshot()).includes(oneTimeSecrets.get("created") ?? "");
    expect(creationSecretAbsentFromHtml, "created one-time secret is absent from page HTML").toBe(true);
    expect(creationSecretAbsentFromAccessibility, "created one-time secret is absent from the accessibility tree").toBe(true);
    const creationLifecycleSignals = {
      ...(await page.evaluate(() => ({
      pagehide: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:created-pagehide"),
      pagehidePersisted: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:created-pagehide-persisted"),
      pageshow: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:created-pageshow") ?? localStorage.getItem("virki-e2e-oidc-secret-lifecycle:pageshow"),
      sameDocumentRestored: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:created-same-document-restored") ?? (localStorage.getItem("virki-e2e-oidc-secret-lifecycle:pageshow") === "not-persisted" ? "false" : "not-observed"),
      navigation: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:created-navigation") ?? localStorage.getItem("virki-e2e-oidc-secret-lifecycle:navigation"),
      notRestoredReasons: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:created-notRestoredReasons") ?? localStorage.getItem("virki-e2e-oidc-secret-lifecycle:notRestoredReasons")
      }))),
      backResponse: Boolean(creationBackResponse)
    };
    expect(creationLifecycleSignals.pagehide).toBe("scrubbed");
    if (creationLifecycleSignals.pagehidePersisted === "true") {
      expect(creationLifecycleSignals.pageshow).toBe("persisted");
      expect(creationLifecycleSignals.sameDocumentRestored).toBe("true");
    }
    if (creationLifecycleSignals.pageshow === "persisted") expect(creationLifecycleSignals.sameDocumentRestored).toBe("true");
    if (creationLifecycleSignals.pagehidePersisted === "false") {
      expect(creationLifecycleSignals.pageshow).toBe("not-persisted");
      expect(creationLifecycleSignals.sameDocumentRestored).toBe("false");
    }
    console.info(`OIDC created-secret lifecycle: history=back; responseObserved=${creationLifecycleSignals.backResponse}; pagehide=${creationLifecycleSignals.pagehide}; pagehide.persisted=${creationLifecycleSignals.pagehidePersisted ?? "not-observed"}; pageshow.persisted=${creationLifecycleSignals.pageshow ?? "not-observed"}; sameDocumentRestored=${creationLifecycleSignals.sameDocumentRestored ?? "not-observed"}; navigation=${creationLifecycleSignals.navigation ?? "unknown"}; notRestoredReasons=${creationLifecycleSignals.notRestoredReasons ?? "unknown"}`);
    const creationReloadResponse = await page.reload();
    expect(creationReloadResponse?.status()).toBe(200);
    await expect(page.locator("[data-sensitive-one-time-value='true']")).toHaveCount(0);
    const creationSecretAbsentAfterReload = !(await page.content()).includes(oneTimeSecrets.get("created") ?? "");
    const creationSecretAbsentFromAccessibilityAfterReload = !(await page.locator("body").ariaSnapshot()).includes(oneTimeSecrets.get("created") ?? "");
    expect(creationSecretAbsentAfterReload, "created one-time secret is absent after a fresh document reload").toBe(true);
    expect(creationSecretAbsentFromAccessibilityAfterReload, "created one-time secret is absent from accessibility after a fresh document reload").toBe(true);
    await page.goto(`${hubUrl}/admin/accounts`);
    const creationReloadBackResponse = await page.goBack();
    await expect(page).toHaveURL(hubUrl + "/admin/connections");
    await expect(page.locator("[data-sensitive-one-time-value='true']")).toHaveCount(0);
    const creationSecretAbsentAfterReloadBack = !(await page.content()).includes(oneTimeSecrets.get("created") ?? "");
    const creationSecretAbsentFromAccessibilityAfterReloadBack = !(await page.locator("body").ariaSnapshot()).includes(oneTimeSecrets.get("created") ?? "");
    expect(creationSecretAbsentAfterReloadBack, "created one-time secret is absent after a reload followed by Back").toBe(true);
    expect(creationSecretAbsentFromAccessibilityAfterReloadBack, "created one-time secret is absent from accessibility after a reload followed by Back").toBe(true);
    const creationFallbackPageshow = await page.evaluate(() => localStorage.getItem("virki-e2e-oidc-secret-lifecycle:pageshow"));
    expect(creationFallbackPageshow).toBe("not-persisted");
    const creationFallbackNavigation = await page.evaluate(() => (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type ?? "unknown");
    console.info(`OIDC created-secret fallback: reloadResponse=${Boolean(creationReloadResponse)}; backResponseObserved=${Boolean(creationReloadBackResponse)}; pageshow.persisted=${creationFallbackPageshow}; navigation=${creationFallbackNavigation}; secretAbsent=true`);
    oneTimeSecrets.delete("created");

    adminJourneyPhase = "rotated-secret-action";
    await lifecycleConnectionRow.getByRole("button", { name: "Rotacionar secret", exact: true }).click();
    const rotationSecretPanel = lifecycleConnectionRow.locator("[data-sensitive-one-time-value='true']");
    await expect(rotationSecretPanel).toBeVisible();
    oneTimeSecrets.set("rotated", await rotationSecretPanel.locator("code").innerText());
    expect(/^[A-Za-z0-9_-]{64}$/u.test(oneTimeSecrets.get("rotated") ?? ""), "rotated one-time secret has the expected format").toBe(true);

    adminJourneyPhase = "rotated-secret-pagehide-navigation-back";
    await page.evaluate(() => {
      const key = "virki-e2e-oidc-secret-lifecycle";
      localStorage.removeItem(`${key}:rotated-pagehide`);
      localStorage.removeItem(`${key}:rotated-pageshow`);
      localStorage.removeItem(`${key}:rotated-navigation`);
      localStorage.removeItem(`${key}:rotated-notRestoredReasons`);
      localStorage.removeItem(`${key}:rotated-pagehide-persisted`);
      localStorage.removeItem(`${key}:rotated-same-document-restored`);
      const documentMarker = {};
      Object.defineProperty(window, "__virkiRotatedSecretDocumentMarker", { value: documentMarker, configurable: true });
      window.addEventListener("pagehide", (event) => {
        const panel = document.querySelector("[data-sensitive-one-time-value='true']");
        localStorage.setItem(`${key}:rotated-pagehide`, panel ? "still-visible" : "scrubbed");
        localStorage.setItem(`${key}:rotated-pagehide-persisted`, event.persisted ? "true" : "false");
      }, { once: true });
      window.addEventListener("pageshow", (event) => {
        localStorage.setItem(`${key}:rotated-pageshow`, event.persisted ? "persisted" : "not-persisted");
        const restoredMarker = (window as Window & { __virkiRotatedSecretDocumentMarker?: object }).__virkiRotatedSecretDocumentMarker;
        localStorage.setItem(`${key}:rotated-same-document-restored`, event.persisted && restoredMarker === documentMarker ? "true" : "false");
        const navigation = performance.getEntriesByType("navigation")[0] as (PerformanceNavigationTiming & { notRestoredReasons?: { reasons?: Array<{ reason?: unknown }> } }) | undefined;
        localStorage.setItem(`${key}:rotated-navigation`, navigation?.type ?? "unknown");
        const reasons = (navigation?.notRestoredReasons?.reasons ?? []).slice(0, 8).map(({ reason }) => typeof reason === "string" ? reason.replace(/[^a-z0-9_-]/giu, "").slice(0, 40) : "unknown");
        localStorage.setItem(`${key}:rotated-notRestoredReasons`, reasons.join(",") || "none");
      });
    });
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    const rotationBackResponse = await page.goBack();
    await expect(page).toHaveURL(hubUrl + "/admin/connections");
    await expect(page.getByRole("heading", { level: 1, name: "Conexões", exact: true })).toBeVisible();
    await expect(page.locator("[data-sensitive-one-time-value='true']")).toHaveCount(0);
    const rotationSecretAbsentFromHtml = !(await page.content()).includes(oneTimeSecrets.get("rotated") ?? "");
    const rotationSecretAbsentFromAccessibility = !(await page.locator("body").ariaSnapshot()).includes(oneTimeSecrets.get("rotated") ?? "");
    expect(rotationSecretAbsentFromHtml, "rotated one-time secret is absent from page HTML").toBe(true);
    expect(rotationSecretAbsentFromAccessibility, "rotated one-time secret is absent from the accessibility tree").toBe(true);
    const rotationLifecycleSignals = {
      ...(await page.evaluate(() => ({
      pagehide: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:rotated-pagehide"),
      pagehidePersisted: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:rotated-pagehide-persisted"),
      pageshow: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:rotated-pageshow") ?? localStorage.getItem("virki-e2e-oidc-secret-lifecycle:pageshow"),
      sameDocumentRestored: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:rotated-same-document-restored") ?? (localStorage.getItem("virki-e2e-oidc-secret-lifecycle:pageshow") === "not-persisted" ? "false" : "not-observed"),
      navigation: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:rotated-navigation") ?? localStorage.getItem("virki-e2e-oidc-secret-lifecycle:navigation"),
      notRestoredReasons: localStorage.getItem("virki-e2e-oidc-secret-lifecycle:rotated-notRestoredReasons") ?? localStorage.getItem("virki-e2e-oidc-secret-lifecycle:notRestoredReasons")
      }))),
      backResponse: Boolean(rotationBackResponse)
    };
    expect(rotationLifecycleSignals.pagehide).toBe("scrubbed");
    if (rotationLifecycleSignals.pagehidePersisted === "true") {
      expect(rotationLifecycleSignals.pageshow).toBe("persisted");
      expect(rotationLifecycleSignals.sameDocumentRestored).toBe("true");
    }
    if (rotationLifecycleSignals.pageshow === "persisted") expect(rotationLifecycleSignals.sameDocumentRestored).toBe("true");
    if (rotationLifecycleSignals.pagehidePersisted === "false") {
      expect(rotationLifecycleSignals.pageshow).toBe("not-persisted");
      expect(rotationLifecycleSignals.sameDocumentRestored).toBe("false");
    }
    console.info(`OIDC rotated-secret lifecycle: history=back; responseObserved=${rotationLifecycleSignals.backResponse}; pagehide=${rotationLifecycleSignals.pagehide}; pagehide.persisted=${rotationLifecycleSignals.pagehidePersisted ?? "not-observed"}; pageshow.persisted=${rotationLifecycleSignals.pageshow ?? "not-observed"}; sameDocumentRestored=${rotationLifecycleSignals.sameDocumentRestored ?? "not-observed"}; navigation=${rotationLifecycleSignals.navigation ?? "unknown"}; notRestoredReasons=${rotationLifecycleSignals.notRestoredReasons ?? "unknown"}`);
    const rotationReloadResponse = await page.reload();
    expect(rotationReloadResponse?.status()).toBe(200);
    await expect(page.locator("[data-sensitive-one-time-value='true']")).toHaveCount(0);
    const rotationSecretAbsentAfterReload = !(await page.content()).includes(oneTimeSecrets.get("rotated") ?? "");
    const rotationSecretAbsentFromAccessibilityAfterReload = !(await page.locator("body").ariaSnapshot()).includes(oneTimeSecrets.get("rotated") ?? "");
    expect(rotationSecretAbsentAfterReload, "rotated one-time secret is absent after a fresh document reload").toBe(true);
    expect(rotationSecretAbsentFromAccessibilityAfterReload, "rotated one-time secret is absent from accessibility after a fresh document reload").toBe(true);
    await page.goto(`${hubUrl}/admin/accounts`);
    const rotationReloadBackResponse = await page.goBack();
    await expect(page).toHaveURL(hubUrl + "/admin/connections");
    await expect(page.locator("[data-sensitive-one-time-value='true']")).toHaveCount(0);
    const rotationSecretAbsentAfterReloadBack = !(await page.content()).includes(oneTimeSecrets.get("rotated") ?? "");
    const rotationSecretAbsentFromAccessibilityAfterReloadBack = !(await page.locator("body").ariaSnapshot()).includes(oneTimeSecrets.get("rotated") ?? "");
    expect(rotationSecretAbsentAfterReloadBack, "rotated one-time secret is absent after a reload followed by Back").toBe(true);
    expect(rotationSecretAbsentFromAccessibilityAfterReloadBack, "rotated one-time secret is absent from accessibility after a reload followed by Back").toBe(true);
    const rotationFallbackPageshow = await page.evaluate(() => localStorage.getItem("virki-e2e-oidc-secret-lifecycle:pageshow"));
    expect(rotationFallbackPageshow).toBe("not-persisted");
    const rotationFallbackNavigation = await page.evaluate(() => (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type ?? "unknown");
    console.info(`OIDC rotated-secret fallback: reloadResponse=${Boolean(rotationReloadResponse)}; backResponseObserved=${Boolean(rotationReloadBackResponse)}; pageshow.persisted=${rotationFallbackPageshow}; navigation=${rotationFallbackNavigation}; secretAbsent=true`);
    oneTimeSecrets.delete("rotated");

    const activeProjectRow = page.locator("article").filter({ hasText: fixture.projectName });
    const activeEditDetails = activeProjectRow.locator("details").filter({ hasText: "Editar configuração" });
    await expect(activeEditDetails).toHaveAttribute("data-hydrated", "true");
    await activeEditDetails.getByText("Editar configuração", { exact: true }).click();
    const activeNameInput = activeEditDetails.locator('input[name="name"]');
    const originInput = activeEditDetails.locator('input[name="origin"]');
    const activeRedirectUrisInput = activeEditDetails.locator('textarea[name="redirectUris"]');
    const saveButton = activeEditDetails.getByRole("button", { name: "Salvar configuração", exact: true });

    adminJourneyPhase = "connection-invalid-origin-csrf-conflict-and-save";
    await originInput.fill("http://project.e2e.invalid");
    await activeRedirectUrisInput.fill("https://project.e2e.invalid/callback");
    expect(await originInput.evaluate((input) => (input as HTMLInputElement).checkValidity())).toBe(true);
    const formIsNativelyValid = await activeEditDetails.locator("form").evaluate((form) => (form as HTMLFormElement).checkValidity());
    expect(formIsNativelyValid).toBe(true);
    const originBeforeInvalidSave = await prisma.projectConnection.findUnique({ where: { id: fixture.projectConnectionId }, select: { origin: true } });
    if (!originBeforeInvalidSave) throw new Error("E2E project connection disappeared before invalid-origin validation.");
    const invalidSaveResponse = page.waitForResponse((response) => {
      const responseUrl = new URL(response.url());
      return response.request().method() === "POST" && responseUrl.origin === hubUrl && responseUrl.pathname === "/admin/connections";
    }, { timeout: 10_000 });
    await saveButton.click();
    expect((await invalidSaveResponse).status()).toBe(200);
    await expect(activeEditDetails).toHaveAttribute("open", "");
    await expect(activeEditDetails.getByRole("alert")).toContainText("Não foi possível salvar");
    await expect(activeEditDetails.getByRole("alert")).toContainText("valores enviados foram mantidos");
    await expect(originInput).toHaveValue("http://project.e2e.invalid");
    await expect(activeRedirectUrisInput).toHaveValue("https://project.e2e.invalid/callback");
    const originAfterInvalidSave = await prisma.projectConnection.findUnique({ where: { id: fixture.projectConnectionId }, select: { origin: true } });
    expect(originAfterInvalidSave?.origin).toBe(originBeforeInvalidSave.origin);

    await originInput.fill("https://project.e2e.invalid");
    await activeNameInput.fill("Draft preserved after authorization rejection");
    const csrfField = activeEditDetails.locator('input[name="csrfToken"]');
    const validCsrf = await csrfField.inputValue();
    await csrfField.evaluate((element) => { (element as HTMLInputElement).value = "invalid-e2e-csrf"; });
    await saveButton.click();
    await expect(activeEditDetails.getByRole("alert")).toContainText("Não foi possível confirmar sua autorização");
    await expect(activeEditDetails.getByRole("alert")).toContainText("valores enviados foram mantidos");
    await expect(activeNameInput).toHaveValue("Draft preserved after authorization rejection");
    await csrfField.evaluate((element, value) => { (element as HTMLInputElement).value = value; }, validCsrf);
    const unchangedConnection = await prisma.projectConnection.findUnique({ where: { id: fixture.projectConnectionId }, select: { name: true } });
    expect(unchangedConnection?.name).toBe(fixture.projectName);

    await prisma.projectConnection.update({ where: { id: fixture.projectConnectionId }, data: { name: "Concurrent ADMIN update" } });
    await saveButton.click();
    const conflictAlert = activeEditDetails.getByRole("alert");
    await expect(conflictAlert).toContainText("Outro ADMIN alterou esta conexão");
    await expect(conflictAlert).toContainText("valores enviados foram mantidos");
    await expect(activeEditDetails.locator(".conflict-summary")).toContainText("Concurrent ADMIN update");
    await expect(activeNameInput).toHaveValue("Draft preserved after authorization rejection");
    await expect(saveButton).toBeDisabled();
    await activeEditDetails.getByRole("button", { name: "Reaplicar meu rascunho sobre esta versão", exact: true }).click();
    await expect(saveButton).toBeEnabled();
    await saveButton.click();
    await expect(page).toHaveURL(hubUrl + "/admin/connections");
    const savedProjectRow = page.locator("article.connection-row").filter({ hasText: "Draft preserved after authorization rejection" });
    try {
      await expect(savedProjectRow.getByRole("status")).toContainText("Configuração salva.", { timeout: 15_000 });
    } catch {
      const saved = await prisma.projectConnection.findUnique({ where: { id: fixture.projectConnectionId }, select: { name: true } });
      const savedRowVisible = await savedProjectRow.isVisible().catch(() => false);
      const errorVisible = await page.getByRole("alert").isVisible().catch(() => false);
      throw new Error(`E2E ADMIN connection update status is unavailable (persistedDraft=${saved?.name === "Draft preserved after authorization rejection"}; updatedRowVisible=${savedRowVisible}; errorVisible=${errorVisible}; hubResponses=${await hubPageResponses()}).`);
    }
    await expect(savedProjectRow).toBeVisible();
    await expect(savedProjectRow.getByRole("alert")).toHaveCount(0);
    await expect(savedProjectRow.locator("strong")).toContainText("Draft preserved after authorization rejection");
    const updatedConnection = await prisma.projectConnection.findUnique({ where: { id: fixture.projectConnectionId }, select: { name: true, origin: true } });
    expect(updatedConnection).toEqual({ name: "Draft preserved after authorization rejection", origin: "https://project.e2e.invalid" });

    adminJourneyPhase = "expired-elevation-denial";
    const expiryProjectRow = page.locator("article").filter({ hasText: "Draft preserved after authorization rejection" });
    const expiryEditDetails = expiryProjectRow.locator("details").filter({ hasText: "Editar configuração" });
    await expect(expiryEditDetails).toHaveAttribute("open", "");
    const expiryNameInput = expiryEditDetails.locator('input[name="name"]');
    await expiryNameInput.fill("Draft preserved after elevation expires");
    const expiredElevation = await prisma.securityElevation.updateMany({
      where: { requestKey: elevationRequestKey, status: "ACTIVE" },
      data: { expiresAt: new Date(Date.now() - 1_000) }
    });
    expect(expiredElevation.count).toBe(1);
    await expiryEditDetails.getByRole("button", { name: "Salvar configuração", exact: true }).click();
    await expect(expiryEditDetails.getByRole("alert")).toContainText("elevação de segurança");
    await expect(expiryEditDetails.getByRole("alert")).toContainText("valores enviados foram mantidos");
    await expect(expiryNameInput).toHaveValue("Draft preserved after elevation expires");
    const unchangedAfterExpiry = await prisma.projectConnection.findUnique({ where: { id: fixture.projectConnectionId }, select: { name: true } });
    expect(unchangedAfterExpiry?.name).toBe("Draft preserved after authorization rejection");
    adminJourneyPhase = "admin-navigation-and-audit";
    await page.getByRole("link", { name: "Segurança", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/security`);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    await assertAdminSkipLink(page);
    await page.getByRole("link", { name: "Auditoria", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/audit`);
    await expect(page.getByRole("heading", { level: 1, name: "Auditoria", exact: true })).toBeVisible();
    await assertAdminSkipLink(page);

    adminJourneyPhase = "access-boundary-and-logout-revocation";
    const accesslessContext = await browser.newContext();
    try {
      await accesslessContext.addCookies([{
        name: sessionCookieName,
        value: sessionCookie.value,
        url: hubUrl,
        httpOnly: true,
        secure: true,
        sameSite: "Lax"
      }]);
      const accesslessPage = await accesslessContext.newPage();
      const response = await accesslessPage.goto(`${hubUrl}/admin/accounts`);
      expect(response?.status()).toBe(403);
    } finally {
      await accesslessContext.close();
    }

    await page.getByRole("button", { name: "Sair", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/login`);

    await context.addCookies([{
      name: sessionCookieName,
      value: sessionCookie.value,
      url: hubUrl,
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    }]);
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
    adminJourneyPhase = "final-hydration-check";
    expect(firstHydrationMismatchPhase, `Hydration mismatch first occurred during ${firstHydrationMismatchPhase ?? "no phase"}`).toBeUndefined();
    adminJourneyPhase = "complete";
  } finally {
    oneTimeSecrets.clear();
    if (adminJourneyPhase !== "complete") {
      console.error(`E2E ADMIN journey stopped during phase=${adminJourneyPhase}; firstHydrationMismatchPhase=${firstHydrationMismatchPhase ?? "none"}.`);
    }
    if (lifecycleConnectionSlug) await prisma.projectConnection.deleteMany({ where: { slug: lifecycleConnectionSlug } }).catch(() => undefined);
    await context.close().catch(() => undefined);
    await prisma.$disconnect();
  }
});

test("ADMIN recovery is Access-protected, role-bound, independently approved, and revokes the old session", async ({ browser }) => {
  // Multi-step ADMIN journey: every ADMIN sign-in now includes the emailed second-factor step.
  test.setTimeout(90_000);
  const prisma = createE2ePrismaClient();
  const contexts: BrowserContext[] = [];
  const createContext = async () => {
    const context = await browser.newContext();
    contexts.push(context);
    return context;
  };
  const newPassword = randomBytes(32).toString("base64url");
  try {
    const portalContext = await createContext();
    const portalPage = await portalContext.newPage();
    await portalPage.goto(`${portalUrl}/recover`);
    await portalPage.getByLabel("E-mail", { exact: true }).fill(fixture.admin.email);
    await portalPage.getByRole("button", { name: "Enviar instruções", exact: true }).click();
    await expect(portalPage.getByRole("status")).toContainText("Se a conta puder ser recuperada");
    expect(await prisma.accountRecoveryRequest.count({ where: { userId: fixture.admin.id } })).toBe(0);

    const noAccessContext = await createContext();
    const noAccessPage = await noAccessContext.newPage();
    const deniedHubResponse = await noAccessPage.goto(`${hubUrl}/recover`);
    expect(deniedHubResponse?.status()).toBe(403);
    await expect(noAccessPage.getByRole("heading", { name: "Recuperar acesso administrativo", exact: true })).toHaveCount(0);

    const targetContext = await createContext();
    await rememberDevice(targetContext, hubUrl, fixture.admin.deviceToken);
    const targetPage = await targetContext.newPage();
    await addCloudflareAccessHeader(targetPage);
    await targetPage.goto(`${hubUrl}/admin/accounts`);
    await expect(targetPage).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
    await signIn(targetPage, fixture.admin);
    await expect(targetPage.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();

    const hubContext = await createContext();
    const hubPage = await hubContext.newPage();
    const hubRecoveryResponses = observeHubPageResponses(hubPage, "/recover");
    await addCloudflareAccessHeader(hubPage);
    await hubPage.goto(`${hubUrl}/recover`);
    await expect(hubPage.getByRole("heading", { name: "Recuperar acesso administrativo", exact: true })).toBeVisible();
    await hubPage.getByLabel("E-mail", { exact: true }).fill(fixture.admin.email);
    await hubPage.getByRole("button", { name: "Enviar instruções", exact: true }).click();
    await expect(hubPage.getByRole("status")).toContainText("Se a conta puder ser recuperada");

    const recovery = await prisma.accountRecoveryRequest.findFirst({
      where: { userId: fixture.admin.id, status: "PENDING", emailVerifiedAt: null },
      orderBy: { createdAt: "desc" },
      select: { id: true }
    });
    expect(recovery).not.toBeNull();
    if (!recovery) throw new Error("E2E protected ADMIN recovery request was not created.");
    const requestMessage = await readLatestRecoveryEmail(prisma, fixture.admin.email, "account-recovery:");
    const requestKey = requestMessage.actionUrl ? new URL(requestMessage.actionUrl).searchParams.get("request") : null;
    expect(new URL(requestMessage.actionUrl ?? "https://invalid.invalid").origin).toBe(hubUrl);
    expect(requestMessage.code).toMatch(/^\d{6}$/u);
    expect(requestKey).toMatch(/^[A-Za-z0-9_-]{32,100}$/u);

    const portalOpenUrl = new URL(requestMessage.actionUrl ?? `${hubUrl}/recover/open`);
    portalOpenUrl.host = new URL(portalUrl).host;
    await portalPage.goto(portalOpenUrl.toString());
    await expect(portalPage).toHaveURL(`${portalUrl}/recover?error=1`);
    await expect(portalPage.locator('p.form-error[role="alert"]')).toContainText("Não foi possível abrir este link. Solicite novas instruções pelo formulário abaixo.");

    await hubPage.goto(requestMessage.actionUrl!);
    const openedRecoveryUrl = new URL(hubPage.url());
    expect(openedRecoveryUrl.origin).toBe(hubUrl);
    expect(openedRecoveryUrl.pathname).toBe("/recover");
    expect(openedRecoveryUrl.searchParams.has("requestId")).toBe(true);
    const requestCode = hubPage.getByLabel("Código de verificação", { exact: true });
    await expect(requestCode).toBeVisible();
    await requestCode.fill(requestMessage.code === "000000" ? "000001" : "000000");
    await hubPage.getByRole("button", { name: "Verificar e-mail", exact: true }).click();
    await expect(hubPage.locator('p.form-error[role="alert"]')).toContainText("Não foi possível validar o código");
    await expect(hubPage.getByLabel("Código de verificação", { exact: true })).toBeVisible();
    const rejectedRecovery = await prisma.accountRecoveryRequest.findUnique({ where: { id: recovery.id }, select: { emailVerifiedAt: true } });
    expect(rejectedRecovery?.emailVerifiedAt).toBeNull();

    await hubPage.getByLabel("Código de verificação", { exact: true }).fill(requestMessage.code!);
    await hubPage.getByRole("button", { name: "Verificar e-mail", exact: true }).click();
    try {
      await expect(hubPage.getByRole("status")).toContainText("E-mail confirmado. Um administrador analisará a solicitação");
    } catch {
      const verificationUrl = new URL(hubPage.url());
      const recoveryState = await prisma.accountRecoveryRequest.findUnique({
        where: { id: recovery.id },
        select: { status: true, emailVerifiedAt: true }
      });
      const outcome = verificationUrl.searchParams.has("error")
        ? "error"
        : verificationUrl.searchParams.has("verified")
          ? "verified-redirect"
          : verificationUrl.pathname === "/login"
            ? "login-redirect"
            : "no-action-feedback";
      const alertVisible = await hubPage.getByRole("alert").isVisible().catch(() => false);
      const verificationFormVisible = await hubPage.getByLabel("Código de verificação", { exact: true }).isVisible().catch(() => false);
      const verifiedStatusVisible = await hubPage.getByRole("status").isVisible().catch(() => false);
      throw new Error(`E2E ADMIN recovery verification status is unavailable (outcome=${outcome}; state=${recoveryState?.status ?? "missing"}; emailVerified=${Boolean(recoveryState?.emailVerifiedAt)}; alertVisible=${alertVisible}; verificationFormVisible=${verificationFormVisible}; verifiedStatusVisible=${verifiedStatusVisible}; hubResponses=${await hubRecoveryResponses()}).`);
    }
    await expect(hubPage.getByLabel("Código de verificação", { exact: true })).toHaveCount(0);
    await hubPage.reload();
    await expect(hubPage.getByRole("status")).toContainText("E-mail confirmado. Um administrador analisará a solicitação");

    await targetPage.goto(`${hubUrl}/admin/security`);
    await expect(targetPage.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    await expect(targetPage.getByText(fixture.admin.email, { exact: true })).toHaveCount(0);

    const reviewerContext = await createContext();
    await rememberDevice(reviewerContext, hubUrl, fixture.recoveryReviewer.deviceToken);
    const reviewerPage = await reviewerContext.newPage();
    await addCloudflareAccessHeader(reviewerPage);
    await reviewerPage.goto(`${hubUrl}/admin/security`);
    await expect(reviewerPage).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Fsecurity`);
    await signIn(reviewerPage, fixture.recoveryReviewer);
    await expect(reviewerPage.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();

    const recoveryRow = reviewerPage.locator("article.list-row").filter({ hasText: fixture.admin.email });
    const recoveryQueueSnapshot = async () => {
      const [requestState, sessionCookie] = await Promise.all([
        prisma.accountRecoveryRequest.findUnique({
          where: { id: recovery.id },
          select: {
            status: true,
            emailVerifiedAt: true,
            expiresAt: true,
            userId: true,
            user: { select: { role: true, isActive: true, accountStatus: true } }
          }
        }),
        reviewerContext.cookies(hubUrl).then((cookies) => cookies.find((cookie) => cookie.name === sessionCookieName))
      ]);
      const reviewerSession = sessionCookie
        ? await prisma.session.findUnique({
          where: { tokenHash: hashSessionToken(sessionCookie.value) },
          select: { userId: true, revokedAt: true, expiresAt: true }
        })
        : null;
      const queueMatch = reviewerSession
        ? await prisma.accountRecoveryRequest.findFirst({
          where: {
            id: recovery.id,
            ...getPendingAccountRecoveryQueueWhere(new Date(), reviewerSession.userId)
          },
          select: { id: true }
        })
        : null;
      const queueHeading = await reviewerPage.getByRole("heading", { name: /^Recuperação de contas/u }).textContent().catch(() => null);
      return [
        `requestPending=${requestState?.status === "PENDING"}`,
        `emailVerified=${Boolean(requestState?.emailVerifiedAt)}`,
        `requestUnexpired=${Boolean(requestState && requestState.expiresAt > new Date())}`,
        `targetAdminActive=${Boolean(requestState?.user.role === "ADMIN" && requestState.user.isActive && requestState.user.accountStatus === "ACTIVE")}`,
        `reviewerSessionMatchesFixture=${reviewerSession?.userId === fixture.recoveryReviewer.id}`,
        `reviewerSessionActive=${Boolean(reviewerSession && !reviewerSession.revokedAt && reviewerSession.expiresAt > new Date())}`,
        `reviewerDistinctFromTarget=${Boolean(reviewerSession && reviewerSession.userId !== requestState?.userId)}`,
        `queryIncludesRequest=${Boolean(queueMatch)}`,
        `matchingDomRows=${await recoveryRow.count()}`,
        `queueHeading=${queueHeading ?? "missing"}`
      ].join(";");
    };
    const queueBeforeElevation = await recoveryQueueSnapshot();

    const elevationSection = reviewerPage.locator("section.surface").filter({ has: reviewerPage.getByRole("heading", { name: "Elevação temporária", exact: true }) });
    const elevationForm = elevationSection.locator("form").first();
    await elevationForm.locator('select[name="scope"]').selectOption("ACCOUNT_STATE_CHANGE");
    await elevationForm.getByLabel("Senha normal atual", { exact: true }).fill(fixture.recoveryReviewer.password);
    await elevationForm.getByLabel("Senha administrativa", { exact: true }).fill(fixture.recoveryReviewer.administrativePassword);
    await elevationForm.getByRole("button", { name: "Solicitar elevação", exact: true }).click();
    const elevationVerificationForm = elevationSection.locator("form").nth(1);
    await expect(elevationVerificationForm.getByLabel("Código", { exact: true })).toBeVisible();
    const elevationRequestKey = await elevationVerificationForm.locator('input[name="requestKey"]').inputValue();
    const elevationCode = await readLatestAdminVerificationCode(prisma, fixture.recoveryReviewer.email, elevationRequestKey);
    await elevationVerificationForm.getByLabel("Código", { exact: true }).fill(elevationCode);
    await elevationVerificationForm.getByRole("button", { name: "Ativar elevação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=elevation#admin-content`);
    try {
      await expect(recoveryRow).toBeVisible();
    } catch {
      throw new Error(`E2E ADMIN recovery queue omitted the verified target after reviewer elevation (before-elevation: ${queueBeforeElevation}; after-elevation: ${await recoveryQueueSnapshot()}).`);
    }
    await recoveryRow.getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=recovery#admin-content`);

    const approvalMessage = await readLatestRecoveryEmail(prisma, fixture.admin.email, "account-recovery-approved:");
    const approvalUrl = new URL(approvalMessage.actionUrl ?? "https://invalid.invalid");
    expect(approvalUrl.origin).toBe(hubUrl);
    await hubPage.goto(approvalUrl.toString());
    await expect(hubPage.getByRole("status")).toContainText("Defina uma nova senha para concluir o acesso à sua conta.");
    await expect(hubPage.getByLabel("Nova senha", { exact: true })).toBeVisible();
    const recoveryCookies = await hubContext.cookies(hubUrl);
    const activeRecoveryKey = recoveryCookies.find((cookie) => cookie.name.includes("recovery_v2") || cookie.name.includes("__Host-virki_recovery"))?.value;
    expect(activeRecoveryKey).toBe(approvalUrl.searchParams.get("request"));
    expect(recoveryCookies.some((cookie) => cookie.name.includes("recovery_candidate"))).toBe(false);
    await hubPage.getByLabel("Nova senha", { exact: true }).fill(newPassword);
    await hubPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(hubPage).toHaveURL(`${hubUrl}/login?recovered=1`);
    await expect(hubPage.getByRole("status")).toContainText("A senha foi atualizada");

    const recoveredAdmin = await prisma.user.findUnique({ where: { id: fixture.admin.id }, select: { passwordHash: true } });
    expect(recoveredAdmin).not.toBeNull();
    expect(await verifyPassword(recoveredAdmin!.passwordHash, newPassword)).toBe(true);
    expect(await verifyPassword(recoveredAdmin!.passwordHash, fixture.admin.password)).toBe(false);
    expect(await prisma.session.count({ where: { userId: fixture.admin.id, revokedAt: null, expiresAt: { gt: new Date() } } })).toBe(0);
    expect(await prisma.trustedDevice.count({ where: { userId: fixture.admin.id, status: "TRUSTED", revokedAt: null } })).toBe(0);
    expect(await prisma.securityElevation.count({ where: { userId: fixture.admin.id, status: { in: ["PENDING", "ACTIVE"] } } })).toBe(0);
    expect(await prisma.deviceChallenge.count({ where: { userId: fixture.admin.id, status: { in: ["PENDING", "VERIFIED"] }, consumedAt: null } })).toBe(0);
    const oldSessionPage = await targetContext.newPage();
    await oldSessionPage.goto(`${hubUrl}/admin/accounts`);
    await expect(oldSessionPage).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);

    const userContext = await createContext();
    await rememberDevice(userContext, portalUrl, fixture.recoveryTargetUser.deviceToken);
    const userPage = await userContext.newPage();
    await userPage.goto(`${portalUrl}/`);
    await expect(userPage).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
    await signIn(userPage, fixture.recoveryTargetUser);
    await expect(userPage.getByRole("heading", { level: 1, name: "Projetos", exact: true })).toBeVisible();

    await portalPage.goto(`${portalUrl}/recover`);
    await portalPage.getByLabel("E-mail", { exact: true }).fill(fixture.recoveryTargetUser.email);
    await portalPage.getByRole("button", { name: "Enviar instruções", exact: true }).click();
    await expect(portalPage.getByRole("status")).toContainText("Se a conta puder ser recuperada");
    const userRecovery = await prisma.accountRecoveryRequest.findFirst({
      where: { userId: fixture.recoveryTargetUser.id, status: "PENDING", emailVerifiedAt: null },
      orderBy: { createdAt: "desc" },
      select: { id: true }
    });
    expect(userRecovery).not.toBeNull();
    if (!userRecovery) throw new Error("E2E public USER recovery request was not created.");
    const userRequestMessage = await readLatestRecoveryEmail(prisma, fixture.recoveryTargetUser.email, "account-recovery:");
    expect(new URL(userRequestMessage.actionUrl ?? "https://invalid.invalid").origin).toBe(portalUrl);
    await portalPage.goto(userRequestMessage.actionUrl!);
    const userRecoveryCode = portalPage.getByLabel("Código de verificação", { exact: true });
    await expect(userRecoveryCode).toBeVisible();
    await userRecoveryCode.fill(userRequestMessage.code!);
    await portalPage.getByRole("button", { name: "Verificar e-mail", exact: true }).click();
    await expect(portalPage.getByRole("status")).toContainText("E-mail confirmado. Um administrador analisará a solicitação");

    await reviewerPage.goto(`${hubUrl}/admin/security`);
    const userRecoveryRow = reviewerPage.locator("article.list-row").filter({ hasText: fixture.recoveryTargetUser.email });
    await expect(userRecoveryRow).toBeVisible();
    await userRecoveryRow.getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=recovery#admin-content`);
    const userApprovalMessage = await readLatestRecoveryEmail(prisma, fixture.recoveryTargetUser.email, "account-recovery-approved:");
    expect(new URL(userApprovalMessage.actionUrl ?? "https://invalid.invalid").origin).toBe(portalUrl);
    await portalPage.goto(userApprovalMessage.actionUrl!);
    if (new URL(portalPage.url()).searchParams.get("switch") === "1") {
      await expect(portalPage.getByRole("status")).toContainText("Outro link está aberto nesta sessão.");
      await portalPage.getByRole("button", { name: "Continuar com este link", exact: true }).click();
    }
    await expect(portalPage.getByRole("status")).toContainText("Defina uma nova senha para concluir o acesso à sua conta.");
    const newUserPassword = randomBytes(32).toString("base64url");
    await portalPage.getByLabel("Nova senha", { exact: true }).fill(newUserPassword);
    await portalPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(portalPage).toHaveURL(`${portalUrl}/login?recovered=1`);
    const recoveredUser = await prisma.user.findUnique({ where: { id: fixture.recoveryTargetUser.id }, select: { passwordHash: true } });
    expect(recoveredUser).not.toBeNull();
    expect(await verifyPassword(recoveredUser!.passwordHash, newUserPassword)).toBe(true);
    expect(await verifyPassword(recoveredUser!.passwordHash, fixture.recoveryTargetUser.password)).toBe(false);
    expect(await prisma.session.count({ where: { userId: fixture.recoveryTargetUser.id, revokedAt: null, expiresAt: { gt: new Date() } } })).toBe(0);
    expect(await prisma.trustedDevice.count({ where: { userId: fixture.recoveryTargetUser.id, status: "TRUSTED", revokedAt: null } })).toBe(0);
    expect(await prisma.securityElevation.count({ where: { userId: fixture.recoveryTargetUser.id, status: { in: ["PENDING", "ACTIVE"] } } })).toBe(0);
    expect(await prisma.deviceChallenge.count({ where: { userId: fixture.recoveryTargetUser.id, status: { in: ["PENDING", "VERIFIED"] }, consumedAt: null } })).toBe(0);
    await userPage.goto(`${portalUrl}/`);
    await expect(userPage).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
  } finally {
    await Promise.all(contexts.map((context) => context.close().catch(() => undefined)));
    await prisma.$disconnect();
  }
});

function createE2ePrismaClient(): PrismaClient {
  const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
  if (!databaseUrl) throw new Error("Authenticated E2E requires the explicit disposable database fixture.");
  assertDisposableCoreTestDatabase(databaseUrl, process.env);
  return new PrismaClient({ datasources: { db: { url: databaseUrl } } });
}

async function readLatestAdminVerificationCode(prisma: PrismaClient, email: string, requestKey: string): Promise<string> {
  const message = await prisma.emailOutboxMessage.findFirst({
    where: { idempotencyKey: `admin-elevation:${requestKey}`, recipientEmail: email, kind: "ADMIN_EMAIL_VERIFICATION" },
    select: { payload: true }
  });
  if (!message) throw new Error("E2E admin verification message is unavailable.");
  const code = decryptEmailPayload(message.payload).code;
  if (!/^\d{6}$/u.test(code ?? "")) throw new Error("E2E admin verification message is invalid.");
  return code;
}

async function readLatestLoginVerificationCode(prisma: PrismaClient, email: string, ceremonyId: string): Promise<string> {
  const message = await prisma.emailOutboxMessage.findFirst({
    where: {
      idempotencyKey: `security-ceremony:${ceremonyId}`,
      recipientEmail: email,
      kind: { in: ["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"] }
    },
    select: { payload: true }
  });
  if (!message) throw new Error("E2E login verification message is unavailable.");
  const code = decryptEmailPayload(message.payload).code;
  if (!/^\d{6}$/u.test(code ?? "")) throw new Error("E2E login verification message is invalid.");
  return code;
}

async function readLatestRecoveryEmail(prisma: PrismaClient, email: string, idempotencyPrefix: string): Promise<Record<string, string>> {
  const message = await prisma.emailOutboxMessage.findFirst({
    where: { idempotencyKey: { startsWith: idempotencyPrefix }, recipientEmail: email, kind: "ACCOUNT_RECOVERY" },
    orderBy: { createdAt: "desc" },
    select: { payload: true }
  });
  if (!message) throw new Error("E2E account recovery message is unavailable.");
  const payload = decryptEmailPayload(message.payload);
  if (!payload.actionUrl) throw new Error("E2E account recovery action link is unavailable.");
  return payload;
}

async function rememberDevice(context: BrowserContext, url: string, deviceToken: string): Promise<void> {
  await context.addCookies([{
    name: deviceCookieName,
    value: deviceToken,
    url,
    httpOnly: true,
    secure: true,
    sameSite: "Lax"
  }]);
}

async function signIn(page: import("@playwright/test").Page, account: AccountFixture): Promise<void> {
  await page.getByLabel("E-mail", { exact: true }).fill(account.email);
  await page.getByLabel("Senha", { exact: true }).fill(account.password);
  const expectedOrigin = new URL(page.url()).origin;
  const documentOrigin = await page.evaluate(() => window.origin);
  const verificationResponseTrace: string[] = [];
  const recordVerificationResponse = (response: import("@playwright/test").Response) => {
    const responseUrl = new URL(response.url());
    if (responseUrl.origin === expectedOrigin && ["/api/login", "/login/verify", "/login"].includes(responseUrl.pathname)) {
      verificationResponseTrace.push(`${response.request().method()} ${responseUrl.pathname}:${response.status()}`);
    }
  };
  page.on("response", recordVerificationResponse);
  const loginResponsePromise = page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/login" && response.request().method() === "POST"
  );
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  const loginResponse = await loginResponsePromise;
  const requestOrigin = loginResponse.request().headers().origin;
  if (loginResponse.status() === 403) {
    throw new Error(`E2E login request was denied by a security check (${loginDenialDiagnostic(loginResponse.headers())}; document-origin=${safeOriginKind(documentOrigin, expectedOrigin)}; request-origin=${safeOriginKind(requestOrigin, expectedOrigin)}).`);
  }
  expect(documentOrigin).toBe(expectedOrigin);
  expect(requestOrigin).toBe(expectedOrigin);
  const location = loginResponse.headers().location;
  if (loginResponse.status() === 303 && location) {
    const redirect = new URL(location, expectedOrigin);
    if (redirect.pathname === "/login" && redirect.searchParams.get("error") === "1") {
      throw new Error(`E2E login was rejected (${loginDenialDiagnostic(loginResponse.headers())}).`);
    }
    // ADMIN logins always complete an emailed code, even from a remembered browser; USER remembered grants skip this step.
    if (redirect.pathname === "/login/verify") {
      await completeLoginEmailVerification(page, account, redirect, loginResponse.status(), verificationResponseTrace);
    }
  }
}

async function completeLoginEmailVerification(page: import("@playwright/test").Page, account: AccountFixture, verifyUrl: URL, responseStatus: number, responseTrace: string[]): Promise<void> {
  const ceremonyId = verifyUrl.searchParams.get("ceremony") ?? "";
  if (!ceremonyId || verifyUrl.searchParams.get("factor") !== "email") {
    throw new Error("E2E login requested an unsupported second factor.");
  }
  try {
    await page.waitForURL((url) => url.pathname === "/login/verify" && url.searchParams.get("ceremony") === ceremonyId, { timeout: 15_000 });
  } catch {
    const currentUrl = new URL(page.url());
    const expectedQueryKeys = [...verifyUrl.searchParams.keys()].sort().join(",") || "none";
    const currentQueryKeys = [...currentUrl.searchParams.keys()].sort().join(",") || "none";
    throw new Error(`E2E login verification navigation did not complete (response=${responseStatus}; redirect=${verifyUrl.pathname}; redirect-query-keys=${expectedQueryKeys}; current=${currentUrl.pathname}; current-query-keys=${currentQueryKeys}; response-trace=${responseTrace.join(",") || "none"}).`);
  }
  const prisma = createE2ePrismaClient();
  let code: string;
  try {
    code = await readLatestLoginVerificationCode(prisma, account.email, ceremonyId);
  } finally {
    await prisma.$disconnect();
  }
  await page.getByLabel("Código", { exact: true }).fill(code);
  await page.getByRole("button", { name: "Continuar", exact: true }).click();
  try {
    await page.waitForURL((url) => url.pathname !== "/login/verify", { timeout: 15_000 });
  } catch {
    throw new Error("E2E login email verification was not accepted.");
  }
}

function observeHubResponsePolicies(page: import("@playwright/test").Page, pathname: string): () => Promise<string> {
  const pending: Promise<string>[] = [];
  page.on("response", (response) => {
    const responseUrl = new URL(response.url());
    if (responseUrl.origin !== hubUrl || responseUrl.pathname !== pathname || response.request().resourceType() !== "document") return;
    pending.push(Promise.all([
      response.headerValue("cache-control"),
      response.headerValue("pragma"),
      response.headerValue("expires"),
      response.headerValue("permissions-policy"),
      response.headerValue("strict-transport-security"),
      response.headerValue("content-security-policy")
    ]).then(([cacheControl, pragma, expires, permissionsPolicy, strictTransportSecurity, contentSecurityPolicy]) => JSON.stringify({
      method: response.request().method(),
      resourceType: response.request().resourceType(),
      pathname,
      status: response.status(),
      cacheControl: cacheControl ?? "absent",
      pragma: pragma ?? "absent",
      expires: expires ?? "absent",
      permissionsPolicy: permissionsPolicy ?? "absent",
      strictTransportSecurity: strictTransportSecurity ?? "absent",
      contentSecurityPolicy: (contentSecurityPolicy ?? "absent").replace(/'nonce-[^']+'/giu, "'nonce-[redacted]'")
    })).catch(() => JSON.stringify({ pathname, status: response.status(), policy: "unavailable" })));
  });
  return async () => JSON.stringify((await Promise.all(pending)).slice(-4));
}

function observeHubPageResponses(page: import("@playwright/test").Page, pathname: "/admin/connections" | "/recover"): () => Promise<string> {
  const pending: Promise<string>[] = [];
  const allowedAccessReasons = new Set([
    "missing-cloudflare-access-config",
    "invalid-cloudflare-access-config",
    "missing-cloudflare-access-jwt",
    "invalid-cloudflare-access-jwt",
    "expired-cloudflare-access-jwt",
    "invalid-cloudflare-access-audience",
    "invalid-cloudflare-access-issuer",
    "inactive-cloudflare-access-jwt",
    "invalid-cloudflare-access-signature",
    "missing-cloudflare-access-signing-key"
  ]);
  page.on("response", (response) => {
    const responseUrl = new URL(response.url());
    if (responseUrl.origin !== hubUrl || responseUrl.pathname !== pathname) return;
    if (!["document", "fetch"].includes(response.request().resourceType())) return;
    const responseStatus = response.status();
    pending.push(response.headerValue("x-virki-e2e-access-reason").then((reason) => {
      const safeReason = reason && allowedAccessReasons.has(reason) ? reason : "none";
      return `${pathname}:${responseStatus}:access-${safeReason}`;
    }).catch(() => `${pathname}:${responseStatus}:access-unavailable`));
  });
  return async () => {
    const responses = await Promise.all(pending);
    return responses.slice(-8).join(",") || "none";
  };
}

function safeOriginKind(value: string | undefined, expectedOrigin: string): string {
  if (!value) return "missing";
  if (value === "null") return "null-origin";
  return value === expectedOrigin ? "same-origin" : "other-origin";
}

function loginDenialDiagnostic(headers: Record<string, string>): string {
  const ceremonyStages = new Set([
    "transaction-start",
    "account-lookup",
    "account-state",
    "account-lock-query",
    "account-lock-no-match",
    "trusted-device-lookup",
    "remembered-challenges-revoke",
    "remembered-session-create",
    "challenge-revoke",
    "ceremony-rate-limited",
    "challenge-code-hash",
    "challenge-create",
    "outbox-enqueue",
    "transaction-commit"
  ]);
  const allowedReasons = new Set([
    "cloudflare-access",
    "csrf-expired",
    "csrf-invalid",
    "csrf-malformed",
    "csrf-misconfigured",
    "csrf-missing",
    "csrf-wrong-scope",
    "expired-cloudflare-access-jwt",
    "inactive-cloudflare-access-jwt",
    "invalid-cloudflare-access-audience",
    "invalid-cloudflare-access-config",
    "invalid-cloudflare-access-issuer",
    "invalid-cloudflare-access-jwt",
    "invalid-cloudflare-access-signature",
    "missing-cloudflare-access-config",
    "missing-cloudflare-access-jwt",
    "missing-cloudflare-access-signing-key",
    "same-origin-missing-origin",
    "same-origin-missing-host",
    "same-origin-invalid-host",
    "same-origin-malformed-origin",
    "same-origin-null-origin",
    "same-origin-comma-in-origin",
    "same-origin-disallowed-protocol",
    "same-origin-authority-mismatch",
    "same-origin-hostname-mismatch",
    "same-origin-port-mismatch",
    "same-origin-invalid-origin-components",
    "input-too-long",
    "authentication-invalid-credentials",
    "authentication-rate-limited",
    "authentication-limiter-unavailable",
    "role-mismatch",
    "security-ceremony-unavailable"
  ]);
  const routeReason = headers["x-virki-e2e-login-reason"];
  if (routeReason) {
    const stage = routeReason.startsWith("security-ceremony-unavailable-")
      ? routeReason.slice("security-ceremony-unavailable-".length)
      : "";
    const recognized = allowedReasons.has(routeReason) || ceremonyStages.has(stage);
    return `login-route:${recognized ? routeReason : "unrecognized"}`;
  }
  const proxyReason = headers["x-virki-e2e-access-reason"];
  if (proxyReason) {
    const stage = proxyReason.startsWith("security-ceremony-unavailable-")
      ? proxyReason.slice("security-ceremony-unavailable-".length)
      : "";
    const recognized = allowedReasons.has(proxyReason) || ceremonyStages.has(stage);
    return `hub-proxy:${recognized ? proxyReason : "unrecognized"}`;
  }
  return "not-reported";
}

async function assertAdminSkipLink(page: import("@playwright/test").Page): Promise<void> {
  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", { name: "Ir para o conteúdo", exact: true });
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  const main = page.getByRole("main");
  await expect(main).toHaveCount(1);
  await expect(main).toHaveAttribute("id", "admin-content");
  await expect(main).toBeFocused();
}

function isAuthFixture(value: unknown): value is AuthFixture {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  const isAccount = (account: unknown): account is AccountFixture => {
    if (!account || typeof account !== "object") return false;
    const record = account as Record<string, unknown>;
    return typeof record.id === "string" && typeof record.email === "string" && typeof record.password === "string" && typeof record.deviceToken === "string";
  };
  const recoveryReviewer = candidate.recoveryReviewer as Record<string, unknown> | undefined;
  return isAccount(candidate.user) && isAccount(candidate.recoveryTargetUser) && isAccount(candidate.admin) && isAccount(recoveryReviewer) && typeof recoveryReviewer?.administrativePassword === "string" && typeof candidate.projectConnectionId === "string" && typeof candidate.projectName === "string" &&
    typeof candidate.projectLaunchUrl === "string" && new URL(candidate.projectLaunchUrl).hostname.endsWith(".invalid") &&
    typeof candidate.ungrantedProjectName === "string" && typeof candidate.disabledProjectName === "string";
}
