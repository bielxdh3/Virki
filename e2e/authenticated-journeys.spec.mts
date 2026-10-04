import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test, type BrowserContext } from "@playwright/test";
import { SESSION_COOKIE_NAME, DEVICE_COOKIE_NAME } from "@bielos/auth/constants";
import { verifyPassword } from "@bielos/auth";
import { decryptEmailPayload } from "@bielos/auth/email";
import { PrismaClient } from "@bielos/database";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

// @ts-expect-error This JavaScript safety helper has no declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const portalUrl = "https://portal.localhost:3001";
const hubUrl = "https://hub.localhost:3001";
const e2eDatabaseUrl = process.env.BIELOS_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.BIELOS_E2E_AUTH_FIXTURE_FILE;
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

test("ADMIN can sign in to a protected page, navigate, and have the session revoked on logout", async ({ browser }) => {
  const context = await browser.newContext();
  const prisma = createE2ePrismaClient();
  let hydrationMismatch = false;
  try {
    await rememberDevice(context, hubUrl, fixture.admin.deviceToken);
    const page = await context.newPage();
    page.on("console", (message) => {
      if (/hydration|server-rendered html/iu.test(message.text())) hydrationMismatch = true;
    });
    await addCloudflareAccessHeader(page);
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
    await signIn(page, fixture.admin);
    const sessionCookie = (await context.cookies(hubUrl)).find((cookie) => cookie.name === SESSION_COOKIE_NAME);
    expect(sessionCookie?.value).toBeTruthy();
    if (!sessionCookie) throw new Error("Authenticated E2E session cookie was not created.");

    await expect(page).toHaveURL(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    await assertAdminSkipLink(page);
    await page.getByRole("link", { name: "Acessos", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/access`);
    await expect(page.getByRole("heading", { level: 1, name: "Acessos", exact: true })).toBeVisible();
    await expect(page.getByText(`E2E User → ${fixture.projectName}`, { exact: true })).toBeVisible();
    await assertAdminSkipLink(page);

    await page.getByRole("link", { name: "Conexões", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/connections`);
    await assertAdminSkipLink(page);
    const projectRow = page.locator("article").filter({ hasText: fixture.projectName });
    const editDetails = projectRow.locator("details").filter({ hasText: "Editar configuração" });
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

    const credentialSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Credencial administrativa", exact: true }) });
    const credentialForm = credentialSection.locator("form").first();
    const administrativePassword = randomBytes(32).toString("base64url");
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
    await credentialSection.getByRole("button", { name: "Continuar para elevação", exact: true }).click();

    const elevationSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Elevação temporária", exact: true }) });
    const elevationForm = elevationSection.locator("form").first();
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
    await expect(elevationSection.locator("article").filter({ hasText: "Gerenciar conexões" })).toBeVisible();

    await page.getByRole("link", { name: "Conexões", exact: true }).click();
    await expect(page).toHaveURL(hubUrl + "/admin/connections");
    const activeProjectRow = page.locator("article").filter({ hasText: fixture.projectName });
    const activeEditDetails = activeProjectRow.locator("details").filter({ hasText: "Editar configuração" });
    await activeEditDetails.getByText("Editar configuração", { exact: true }).click();
    const activeNameInput = activeEditDetails.locator('input[name="name"]');
    const originInput = activeEditDetails.locator('input[name="origin"]');
    const activeRedirectUrisInput = activeEditDetails.locator('textarea[name="redirectUris"]');
    const saveButton = activeEditDetails.getByRole("button", { name: "Salvar configuração", exact: true });

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
    await expect(page).toHaveURL(hubUrl + "/admin/connections?status=updated");
    await expect(page.getByRole("status")).toContainText("Alteração concluída");
    const savedProjectRow = page.locator("article.connection-row").filter({ hasText: "Draft preserved after authorization rejection" });
    await expect(savedProjectRow).toBeVisible();
    await expect(savedProjectRow.locator("strong")).toContainText("Draft preserved after authorization rejection");
    const updatedConnection = await prisma.projectConnection.findUnique({ where: { id: fixture.projectConnectionId }, select: { name: true, origin: true } });
    expect(updatedConnection).toEqual({ name: "Draft preserved after authorization rejection", origin: "https://project.e2e.invalid" });

    const expiryProjectRow = page.locator("article").filter({ hasText: "Draft preserved after authorization rejection" });
    const expiryEditDetails = expiryProjectRow.locator("details").filter({ hasText: "Editar configuração" });
    await expiryEditDetails.getByText("Editar configuração", { exact: true }).click();
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
    expect(hydrationMismatch).toBe(false);

    await page.getByRole("link", { name: "Segurança", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/security`);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    await assertAdminSkipLink(page);
    await page.getByRole("link", { name: "Auditoria", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/audit`);
    await expect(page.getByRole("heading", { level: 1, name: "Auditoria", exact: true })).toBeVisible();
    await assertAdminSkipLink(page);

    const accesslessContext = await browser.newContext();
    try {
      await accesslessContext.addCookies([{
        name: SESSION_COOKIE_NAME,
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
      name: SESSION_COOKIE_NAME,
      value: sessionCookie.value,
      url: hubUrl,
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    }]);
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
  } finally {
    try {
      await context.close();
    } finally {
      await prisma.$disconnect();
    }
  }
});

test("ADMIN recovery is Access-protected, role-bound, independently approved, and revokes the old session", async ({ browser }) => {
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
    await expect(portalPage.getByRole("alert")).toContainText("não é válido ou expirou");

    await hubPage.goto(requestMessage.actionUrl!);
    const openedRecoveryUrl = new URL(hubPage.url());
    expect(openedRecoveryUrl.origin).toBe(hubUrl);
    expect(openedRecoveryUrl.pathname).toBe("/recover");
    expect(openedRecoveryUrl.searchParams.has("requestId")).toBe(true);
    const requestCode = hubPage.getByLabel("Código de verificação", { exact: true });
    await expect(requestCode).toBeVisible();
    await requestCode.fill(requestMessage.code!);
    await hubPage.getByRole("button", { name: "Verificar e-mail", exact: true }).click();
    await expect(hubPage.getByRole("status")).toContainText("E-mail confirmado. Aguarde a análise administrativa");

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
    const recoveryRow = reviewerPage.locator("article.list-row").filter({ hasText: fixture.admin.email });
    await expect(recoveryRow).toBeVisible();
    await recoveryRow.getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=recovery#admin-content`);

    const approvalMessage = await readLatestRecoveryEmail(prisma, fixture.admin.email, "account-recovery-approved:");
    expect(new URL(approvalMessage.actionUrl ?? "https://invalid.invalid").origin).toBe(hubUrl);
    await hubPage.goto(approvalMessage.actionUrl!);
    await expect(hubPage.getByRole("status")).toContainText("Solicitação aprovada");
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
    await rememberDevice(userContext, portalUrl, fixture.user.deviceToken);
    const userPage = await userContext.newPage();
    await userPage.goto(`${portalUrl}/`);
    await expect(userPage).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
    await signIn(userPage, fixture.user);
    await expect(userPage.getByRole("heading", { level: 1, name: "Projetos", exact: true })).toBeVisible();

    await portalPage.goto(`${portalUrl}/recover`);
    await portalPage.getByLabel("E-mail", { exact: true }).fill(fixture.user.email);
    await portalPage.getByRole("button", { name: "Enviar instruções", exact: true }).click();
    await expect(portalPage.getByRole("status")).toContainText("Se a conta puder ser recuperada");
    const userRecovery = await prisma.accountRecoveryRequest.findFirst({
      where: { userId: fixture.user.id, status: "PENDING", emailVerifiedAt: null },
      orderBy: { createdAt: "desc" },
      select: { id: true }
    });
    expect(userRecovery).not.toBeNull();
    if (!userRecovery) throw new Error("E2E public USER recovery request was not created.");
    const userRequestMessage = await readLatestRecoveryEmail(prisma, fixture.user.email, "account-recovery:");
    expect(new URL(userRequestMessage.actionUrl ?? "https://invalid.invalid").origin).toBe(portalUrl);
    await portalPage.goto(userRequestMessage.actionUrl!);
    const userRecoveryCode = portalPage.getByLabel("Código de verificação", { exact: true });
    await expect(userRecoveryCode).toBeVisible();
    await userRecoveryCode.fill(userRequestMessage.code!);
    await portalPage.getByRole("button", { name: "Verificar e-mail", exact: true }).click();
    await expect(portalPage.getByRole("status")).toContainText("E-mail confirmado. Aguarde a análise administrativa");

    await reviewerPage.goto(`${hubUrl}/admin/security`);
    const userRecoveryRow = reviewerPage.locator("article.list-row").filter({ hasText: fixture.user.email });
    await expect(userRecoveryRow).toBeVisible();
    await userRecoveryRow.getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=recovery#admin-content`);
    const userApprovalMessage = await readLatestRecoveryEmail(prisma, fixture.user.email, "account-recovery-approved:");
    expect(new URL(userApprovalMessage.actionUrl ?? "https://invalid.invalid").origin).toBe(portalUrl);
    await portalPage.goto(userApprovalMessage.actionUrl!);
    await expect(portalPage.getByRole("status")).toContainText("Solicitação aprovada");
    const newUserPassword = randomBytes(32).toString("base64url");
    await portalPage.getByLabel("Nova senha", { exact: true }).fill(newUserPassword);
    await portalPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(portalPage).toHaveURL(`${portalUrl}/login?recovered=1`);
    const recoveredUser = await prisma.user.findUnique({ where: { id: fixture.user.id }, select: { passwordHash: true } });
    expect(recoveredUser).not.toBeNull();
    expect(await verifyPassword(recoveredUser!.passwordHash, newUserPassword)).toBe(true);
    expect(await verifyPassword(recoveredUser!.passwordHash, fixture.user.password)).toBe(false);
    expect(await prisma.session.count({ where: { userId: fixture.user.id, revokedAt: null, expiresAt: { gt: new Date() } } })).toBe(0);
    expect(await prisma.trustedDevice.count({ where: { userId: fixture.user.id, status: "TRUSTED", revokedAt: null } })).toBe(0);
    expect(await prisma.securityElevation.count({ where: { userId: fixture.user.id, status: { in: ["PENDING", "ACTIVE"] } } })).toBe(0);
    expect(await prisma.deviceChallenge.count({ where: { userId: fixture.user.id, status: { in: ["PENDING", "VERIFIED"] }, consumedAt: null } })).toBe(0);
    await userPage.goto(`${portalUrl}/`);
    await expect(userPage).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
  } finally {
    await Promise.all(contexts.map((context) => context.close().catch(() => undefined)));
    await prisma.$disconnect();
  }
});

function createE2ePrismaClient(): PrismaClient {
  const databaseUrl = process.env.BIELOS_E2E_DATABASE_URL?.trim();
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
    name: DEVICE_COOKIE_NAME,
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
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
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
  return isAccount(candidate.user) && isAccount(candidate.admin) && isAccount(recoveryReviewer) && typeof recoveryReviewer?.administrativePassword === "string" && typeof candidate.projectConnectionId === "string" && typeof candidate.projectName === "string" &&
    typeof candidate.projectLaunchUrl === "string" && new URL(candidate.projectLaunchUrl).hostname.endsWith(".invalid") &&
    typeof candidate.ungrantedProjectName === "string" && typeof candidate.disabledProjectName === "string";
}
