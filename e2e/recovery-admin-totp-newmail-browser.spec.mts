import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { getDeviceCookieName, getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { createTotpSecret, encryptTotpSecret } from "@virki/auth/security";
import { PrismaClient } from "@virki/database";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

// @ts-expect-error This JavaScript safety helper has no declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const productionMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const hubUrl = productionMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const portalUrl = productionMode ? "https://portal.localhost" : "https://portal.localhost:3001";
const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();
const sessionCookieName = getSessionCookieName({ NODE_ENV: productionMode ? "production" : "development" });
const deviceCookieName = getDeviceCookieName({ NODE_ENV: productionMode ? "production" : "development" });

test.skip((!databaseUrl || !fixturePath) && process.env.VIRKI_E2E_REQUIRE_RECOVERY !== "true",
  "requires isolated E2E resources; VIRKI_E2E_REQUIRE_RECOVERY=true makes this a mandatory browser gate");

type Reviewer = {
  id: string;
  email: string;
  password: string;
  deviceToken: string;
  administrativePassword: string;
};

async function requireDisposableFixture(): Promise<{ database: PrismaClient; reviewer: Reviewer }> {
  if (!databaseUrl || !fixturePath || !existsSync(fixturePath) ||
      process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("This browser test requires a confirmed, seeded, disposable E2E database.");
  }
  assertDisposableCoreTestDatabase(databaseUrl, process.env);
  if (new URL(databaseUrl).pathname !== "/virki_e2e_test") {
    throw new Error("Expected only the disposable virki_e2e_test PostgreSQL database.");
  }
  const fixture: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!fixture || typeof fixture !== "object" || !("recoveryReviewer" in fixture)) {
    throw new Error("Recovery reviewer fixture is unavailable.");
  }
  const reviewer: unknown = fixture.recoveryReviewer;
  if (!reviewer || typeof reviewer !== "object" ||
      !["id", "email", "password", "deviceToken", "administrativePassword"].every(
        (key) => typeof (reviewer as Record<string, unknown>)[key] === "string" &&
          (reviewer as Record<string, string>)[key].length > 0)) {
    throw new Error("Recovery reviewer fixture is incomplete.");
  }
  return { database: new PrismaClient({ datasources: { db: { url: databaseUrl } } }), reviewer: reviewer as Reviewer };
}

function totpAt(secret: string, now = new Date()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of secret) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("Invalid disposable TOTP seed.");
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now.getTime() / 30_000)));
  const mac = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return String((mac.readUInt32BE(mac[mac.length - 1]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function outboxCode(database: PrismaClient, email: string,
  kind: "ADMIN_EMAIL_VERIFICATION" | "RECOVERY_EMAIL_REBIND", idempotencyKey?: string): Promise<string> {
  const item = await database.emailOutboxMessage.findFirst({
    where: {
      recipientEmail: email, kind,
      ...(idempotencyKey ? { idempotencyKey } : {})
    },
    orderBy: { createdAt: "desc" },
    select: { payload: true }
  });
  if (!item) throw new Error(`The expected ${kind} message was not queued in the disposable outbox.`);
  const code = decryptEmailPayload(item.payload).code;
  expect(code).toMatch(/^\d{6}$/u);
  return code!;
}

async function signInReviewer(page: Page, database: PrismaClient, reviewer: Reviewer): Promise<void> {
  await page.goto(`${hubUrl}/admin/security`);
  await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Fsecurity`);
  await page.getByLabel("E-mail", { exact: true }).fill(reviewer.email);
  await page.getByLabel("Senha", { exact: true }).fill(reviewer.password);
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await page.waitForURL((url) => url.pathname === "/login/verify" &&
    Boolean(url.searchParams.get("ceremony")) && url.searchParams.get("factor") === "email");
  const ceremony = new URL(page.url()).searchParams.get("ceremony");
  expect(ceremony).toBeTruthy();
  const code = await database.emailOutboxMessage.findFirst({
    where: {
      idempotencyKey: `security-ceremony:${ceremony}`,
      recipientEmail: reviewer.email,
      kind: { in: ["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"] }
    },
    select: { payload: true }
  });
  if (!code) throw new Error("Expected the reviewer's actual second-factor login email.");
  const confirmation = decryptEmailPayload(code.payload).code;
  expect(confirmation).toMatch(/^\d{6}$/u);
  await page.getByLabel("Código", { exact: true }).fill(confirmation!);
  await page.getByRole("button", { name: "Continuar", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
}

for (const accountRole of ["ADMIN", "USER"] as const) {
test(`${accountRole} TOTP_ADMIN: independent approval, verified replacement mailbox, one reset and role/browser isolation`, async ({ browser }) => {
  test.setTimeout(180_000);
  const { database, reviewer } = await requireDisposableFixture();
  const contexts: BrowserContext[] = [];
  const newContext = async () => {
    const context = await browser.newContext();
    contexts.push(context);
    return context;
  };
  const ownedEmail = `totp-${accountRole.toLowerCase()}-${randomUUID()}@e2e.invalid`;
  const replacementEmail = `replacement-${accountRole.toLowerCase()}-${randomUUID()}@e2e.invalid`;
  const recoveryOrigin = accountRole === "ADMIN" ? hubUrl : portalUrl;
  const protectedPath = accountRole === "ADMIN" ? "/admin/accounts" : "/account/security";
  const protectedHeading = accountRole === "ADMIN" ? "Contas" : "Segurança";
  const normalPassword = randomBytes(32).toString("base64url");
  const administrativePassword = randomBytes(32).toString("base64url");
  const newPassword = randomBytes(32).toString("base64url");
  const otherPassword = randomBytes(32).toString("base64url");
  try {
    const secret = createTotpSecret();
    const owner = await database.user.create({
      data: {
        email: ownedEmail, emailNormalized: ownedEmail,
        displayName: `Owned TOTP ${accountRole} browser E2E`, role: accountRole,
        accountStatus: "ACTIVE", isActive: true, emailVerifiedAt: new Date(),
        passwordHash: await hashPassword(normalPassword), secondFactorMethod: "TOTP",
        totpFactor: { create: {
          secretCiphertext: encryptTotpSecret(secret),
          keyVersion: 1, status: "ACTIVE", confirmedAt: new Date()
        } },
        ...(accountRole === "ADMIN" ? { administrativeCredential: { create: {
          passwordHash: await hashPassword(administrativePassword), status: "ACTIVE" as const
        } } } : {})
      },
      select: { id: true }
    });
    expect(owner.id).not.toBe(reviewer.id);
    const privilegedBefore = await database.administrativeCredential.findUnique({
      where: { userId: owner.id }, select: { passwordHash: true, status: true, keyVersion: true }
    });
    expect(Boolean(privilegedBefore), "only ADMIN has a separate administrative credential").toBe(accountRole === "ADMIN");
    const oldToken = randomBytes(32).toString("base64url");
    const oldSession = await database.session.create({
      data: {
        userId: owner.id, tokenHash: hashSessionToken(oldToken),
        expiresAt: new Date(Date.now() + 600_000), authenticationMethods: ["pwd", "otp", "mfa"]
      },
      select: { id: true }
    });

    const ownerContext = await newContext();
    await ownerContext.addCookies([{
      name: sessionCookieName, value: oldToken, url: recoveryOrigin,
      httpOnly: true, secure: true, sameSite: "Lax"
    }]);
    const ownerPage = await ownerContext.newPage();
    if (accountRole === "ADMIN") await addCloudflareAccessHeader(ownerPage);
    await ownerPage.goto(`${recoveryOrigin}/${accountRole === "ADMIN" ? "admin" : "account"}/security`);
    await expect(ownerPage.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();

    const reviewerContext = await newContext();
    await reviewerContext.addCookies([{
      name: deviceCookieName,
      value: reviewer.deviceToken, url: hubUrl, httpOnly: true, secure: true, sameSite: "Lax"
    }]);
    const reviewerPage = await reviewerContext.newPage();
    await addCloudflareAccessHeader(reviewerPage);
    await signInReviewer(reviewerPage, database, reviewer);

    // A request on the opposite surface must be synthetic, never a cross-role
    // capability. The USER path proves Hub Access does not turn USER into ADMIN.
    const oppositeOrigin = accountRole === "ADMIN" ? portalUrl : hubUrl;
    const oppositeContext = await newContext();
    const oppositePage = await oppositeContext.newPage();
    if (accountRole === "USER") await addCloudflareAccessHeader(oppositePage);
    expect((await oppositePage.goto(`${oppositeOrigin}/recover`))?.status()).toBe(200);
    await oppositePage.getByLabel("E-mail da conta", { exact: true }).fill(ownedEmail);
    await oppositePage.locator('input[name="method"][value="TOTP_ADMIN"]').check();
    await oppositePage.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    await expect(oppositePage).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]{43}$/u);
    expect(await database.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(0);

    const deniedContext = await newContext();
    const deniedPage = await deniedContext.newPage();
    expect((await deniedPage.goto(`${hubUrl}/recover`))?.status()).toBe(403);

    const recoveryContext = await newContext();
    const recoveryPage = await recoveryContext.newPage();
    if (accountRole === "ADMIN") await addCloudflareAccessHeader(recoveryPage);
    expect((await recoveryPage.goto(`${recoveryOrigin}/recover`))?.status()).toBe(200);
    await expect(recoveryPage.getByRole("heading", { name: accountRole === "ADMIN" ? "Recuperar acesso administrativo" : "Recuperar conta" })).toBeVisible();
    await recoveryPage.getByLabel("E-mail da conta", { exact: true }).fill(ownedEmail);
    await recoveryPage.locator('input[name="method"][value="TOTP_ADMIN"]').check();
    await recoveryPage.locator('textarea[name="comment"]').fill("Revisão TOTP_ADMIN e troca de caixa postal.");
    const requestPost = recoveryPage.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/recover");
    await recoveryPage.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    const startedResponse = await requestPost;
    const setCookieHeaders = (await startedResponse.headersArray())
      .filter((header) => header.name.toLowerCase() === "set-cookie").map((header) => header.value);
    const cookieNames = productionMode
      ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
      : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
    for (const name of cookieNames) {
      expect(setCookieHeaders.some((header) => header.startsWith(`${name}=`)), `Missing ${name}`).toBe(true);
      expect(setCookieHeaders.some((header) => header.startsWith(`${name}=`) && /(?:^|;)\s*Domain=/iu.test(header)),
        `${name} must stay host-only`).toBe(false);
    }
    await expect(recoveryPage).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]{43}$/u);
    const requestId = new URL(recoveryPage.url()).searchParams.get("requestId")!;
    const recovery = await database.accountRecoveryRequest.findUnique({
      where: { id: requestId },
      select: {
        userId: true, status: true, recoveryRole: true, recoveryProofs: true,
        recoveryAdminReview: true, recoveryComment: true, recoveryTotpVerifiedAt: true,
        emailVerifiedAt: true, recoveryNewEmail: true
      }
    });
    expect(recovery).toMatchObject({
      userId: owner.id, status: "PENDING", recoveryRole: accountRole,
      recoveryProofs: ["TOTP"], recoveryAdminReview: true,
      recoveryComment: "Revisão TOTP_ADMIN e troca de caixa postal.",
      recoveryTotpVerifiedAt: null, emailVerifiedAt: null, recoveryNewEmail: null
    });
    const boundCookies = await recoveryContext.cookies(recoveryOrigin);
    for (const name of cookieNames) {
      const cookie = boundCookies.find((item) => item.name === name);
      expect(cookie, `No ${name} cookie`).toBeDefined();
      expect(cookie!.domain).toBe(new URL(recoveryOrigin).hostname);
      expect(cookie!.path).toBe("/");
      expect(cookie!.httpOnly).toBe(true);
      expect(cookie!.value.length).toBeGreaterThan(0);
    }
    expect(boundCookies.find((item) => item.name === cookieNames[2])?.value).toBe(`${requestId}.TOTP_ADMIN`);

    // Public request IDs do not authorize another browser, even if Hub Access
    // is satisfied independently of the browser-bound recovery capabilities.
    const foreignContext = await newContext();
    const foreignPage = await foreignContext.newPage();
    if (accountRole === "ADMIN") await addCloudflareAccessHeader(foreignPage);
    const foreignUrl = `${recoveryOrigin}/recover?requestId=${encodeURIComponent(requestId)}`;
    const foreignResponse = await foreignPage.goto(foreignUrl);
    expect(foreignResponse?.status(), "an unauthorized request ID must render an ordinary Hub page, not a 403/500").toBe(200);
    await expect(foreignPage).toHaveURL(foreignUrl);
    await expect(foreignPage.getByRole("heading", {
      level: 1, name: accountRole === "ADMIN" ? "Recuperar acesso administrativo" : "Recuperar conta", exact: true
    })).toBeVisible();
    await expect(foreignPage.locator('p.form-error[role="alert"]')).toContainText("Este link de recuperação não é mais válido.");
    await expect(foreignPage.locator('[aria-label="Aplicativo autenticador"] input[name="code"]')).toHaveCount(0);
    await expect(foreignPage.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toHaveCount(0);
    await expect(foreignPage.getByLabel("Novo endereço de e-mail")).toHaveCount(0);
    await expect(foreignPage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);

    const reviewRow = reviewerPage.locator("article.list-row").filter({ hasText: ownedEmail });
    await reviewerPage.reload();
    await expect(reviewRow, "unverified TOTP must not enter an approvable queue").toHaveCount(0);
    const totpStage = recoveryPage.locator('[aria-label="Aplicativo autenticador"]');
    await expect(totpStage.locator('input[name="code"]')).toBeVisible();
    const currentTotp = totpAt(secret);
    await totpStage.locator('input[name="code"]').fill(currentTotp === "999999" ? "000000" : "999999");
    await totpStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(totpStage.getByRole("alert")).toContainText("Não foi possível validar o código");
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId }, select: { recoveryTotpVerifiedAt: true }
    })).recoveryTotpVerifiedAt).toBeNull();

    await totpStage.locator('input[name="code"]').fill(totpAt(secret));
    await totpStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(totpStage.getByText("Confirmado.", { exact: true })).toBeVisible();
    await expect(recoveryPage.getByRole("status").filter({ hasText: "aprovação de outro administrador ativo" })).toBeVisible();
    const afterProof = await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, recoveryTotpVerifiedAt: true, emailVerifiedAt: true }
    });
    expect(afterProof.status).toBe("PENDING");
    expect(afterProof.recoveryTotpVerifiedAt).not.toBeNull();
    expect(afterProof.emailVerifiedAt).toBeNull();
    await expect(recoveryPage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    await ownerPage.reload();
    await expect(ownerPage.locator("article.list-row").filter({ hasText: ownedEmail }),
      "the owner cannot review their own recovery, regardless of role or surface").toHaveCount(0);
    await reviewerPage.reload();
    const approvable = reviewerPage.locator("article.list-row").filter({ hasText: ownedEmail });
    await expect(approvable).toBeVisible();
    await expect(approvable.locator('[data-recovery-review-details="true"]')).toContainText("Aplicativo autenticador + aprovação administrativa");

    // Having the reviewer role alone is insufficient. The action must reject
    // approval until the different ADMIN obtains a scoped security elevation.
    await approvable.getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?error=recovery#admin-content`);
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId }, select: { status: true, reviewedByUserId: true }
    }))).toEqual({ status: "PENDING", reviewedByUserId: null });

    const elevation = reviewerPage.locator("section.surface").filter({
      has: reviewerPage.getByRole("heading", { name: "Elevação temporária", exact: true })
    });
    const form = elevation.locator("form").first();
    await form.locator('select[name="scope"]').selectOption("ACCOUNT_STATE_CHANGE");
    await form.getByLabel("Senha normal atual", { exact: true }).fill(reviewer.password);
    await form.getByLabel("Senha administrativa", { exact: true }).fill(reviewer.administrativePassword);
    await form.getByRole("button", { name: "Solicitar elevação", exact: true }).click();
    const verificationForm = elevation.locator("form").nth(1);
    await expect(verificationForm.getByLabel("Código", { exact: true })).toBeVisible();
    const elevationKey = await verificationForm.locator('input[name="requestKey"]').inputValue();
    const elevationCode = await outboxCode(database, reviewer.email, "ADMIN_EMAIL_VERIFICATION", `admin-elevation:${elevationKey}`);
    await verificationForm.getByLabel("Código", { exact: true }).fill(elevationCode);
    await verificationForm.getByRole("button", { name: "Ativar elevação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=elevation#admin-content`);
    await reviewerPage.locator("article.list-row").filter({ hasText: ownedEmail })
      .getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=recovery#admin-content`);
    const approved = await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, reviewedByUserId: true, recoveryNewEmailVerifiedAt: true }
    });
    expect(approved).toMatchObject({ status: "APPROVED", reviewedByUserId: reviewer.id, recoveryNewEmailVerifiedAt: null });
    expect(approved.reviewedByUserId).not.toBe(owner.id);
    // A TOTP proof does not attest ownership of the old mailbox.
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: ownedEmail, kind: "ACCOUNT_RECOVERY" }
    })).toBe(0);
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: ownedEmail, kind: "RECOVERY_EMAIL_REBIND" }
    })).toBe(0);
    await recoveryPage.reload();
    const mailbox = recoveryPage.locator('[aria-label="Verificação do novo e-mail"]');
    await expect(mailbox.getByRole("heading", { name: "Confirme um novo e-mail antes de trocar a senha" })).toBeVisible();
    await expect(recoveryPage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    await mailbox.getByLabel("Novo endereço de e-mail", { exact: true }).fill(replacementEmail);
    await mailbox.getByRole("button", { name: "Enviar código ao novo e-mail", exact: true }).click();
    await expect(mailbox.getByLabel("Código recebido no novo e-mail", { exact: true })).toBeVisible();
    const sent = await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, recoveryNewEmail: true, recoveryNewEmailVerifiedAt: true }
    });
    expect(sent).toMatchObject({
      status: "APPROVED", recoveryNewEmail: replacementEmail, recoveryNewEmailVerifiedAt: null
    });
    expect((await database.user.findUniqueOrThrow({ where: { id: owner.id } })).email).toBe(ownedEmail);
    const mailboxCode = await outboxCode(database, replacementEmail, "RECOVERY_EMAIL_REBIND");
    await mailbox.getByLabel("Código recebido no novo e-mail", { exact: true })
      .fill(mailboxCode === "000000" ? "000001" : "000000");
    await mailbox.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
    await expect(mailbox.getByRole("alert")).toContainText("Código inválido ou expirado");
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId }, select: { recoveryNewEmailVerifiedAt: true }
    })).recoveryNewEmailVerifiedAt).toBeNull();
    await expect(recoveryPage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);

    // Exercise the *real* completeRecoveryAction before any successful
    // replacement-inbox code verification. The product correctly hides its
    // completion form here. On this disposable owned fixture only, briefly
    // render an authentic completion form, then atomically revoke that
    // temporary timestamp before submitting. This tests a stale browser's
    // actual bound Server Action, not a synthetic/CSRF-invalid HTTP POST.
    const mounted = await database.accountRecoveryRequest.updateMany({
      where: {
        id: requestId, userId: owner.id, status: "APPROVED",
        recoveryNewEmail: replacementEmail, recoveryNewEmailVerifiedAt: null
      },
      data: { recoveryNewEmailVerifiedAt: new Date() }
    });
    expect(mounted.count).toBe(1);
    const prematurePage = await recoveryContext.newPage();
    await addCloudflareAccessHeader(prematurePage);
    try {
      const preparedResponse = await prematurePage.goto(recoveryPage.url());
      expect(preparedResponse?.status()).toBe(200);
      await expect(prematurePage.getByRole("heading", {
        level: 1, name: accountRole === "ADMIN" ? "Recuperar acesso administrativo" : "Recuperar conta", exact: true
      })).toBeVisible();
      await expect(prematurePage.getByLabel("Nova senha", { exact: true })).toBeVisible();
      const actualCompletionForm = prematurePage.locator("form").filter({
        has: prematurePage.getByRole("button", { name: "Concluir recuperação", exact: true })
      });
      await expect(actualCompletionForm.locator('input[name="requestId"]')).toHaveValue(requestId);
      await expect(actualCompletionForm.locator('input[name="csrfToken"]')).toHaveValue(/^v2\./u);
    } finally {
      const revoked = await database.accountRecoveryRequest.updateMany({
        where: {
          id: requestId, userId: owner.id, status: "APPROVED",
          recoveryNewEmail: replacementEmail, recoveryNewEmailVerifiedAt: { not: null }
        },
        data: { recoveryNewEmailVerifiedAt: null }
      });
      expect(revoked.count, "the temporary display-only proof must always be revoked").toBe(1);
    }
    const noMailboxProof = await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, recoveryNewEmail: true, recoveryNewEmailVerifiedAt: true, bootstrapSessionId: true }
    });
    expect(noMailboxProof).toEqual({
      status: "APPROVED", recoveryNewEmail: replacementEmail,
      recoveryNewEmailVerifiedAt: null, bootstrapSessionId: null
    });
    const prematureCookies = await recoveryContext.cookies(recoveryOrigin);
    for (const name of cookieNames) {
      expect(prematureCookies.find((cookie) => cookie.name === name)?.value,
        "the rejected POST must carry the originally bound recovery capability").toBe(
          boundCookies.find((cookie) => cookie.name === name)?.value);
    }
    const beforePremature = await database.user.findUniqueOrThrow({
      where: { id: owner.id }, select: { email: true, emailNormalized: true, passwordHash: true }
    });
    const sessionsBeforePremature = await database.session.count({
      where: { userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() } }
    });
    const prematurePassword = randomBytes(32).toString("base64url");
    await prematurePage.getByLabel("Nova senha", { exact: true }).fill(prematurePassword);
    const prematureActionPost = prematurePage.waitForResponse((response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).origin === recoveryOrigin &&
      new URL(response.url()).pathname === "/recover" &&
      Boolean(response.request().headers()["next-action"]));
    await prematurePage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    const prematureResponse = await prematureActionPost;
    expect(prematureResponse.request().postDataBuffer()?.byteLength ?? 0,
      "rejected completion must be a genuine Next Server Action POST with form data").toBeGreaterThan(0);
    expect(new URL(prematureResponse.url()).origin).toBe(recoveryOrigin);
    const prematureHeaders = prematureResponse.request().headers();
    if (prematureHeaders.origin) expect(prematureHeaders.origin).toBe(recoveryOrigin);
    if (prematureHeaders.referer) expect(new URL(prematureHeaders.referer).origin).toBe(recoveryOrigin);
    expect(prematureResponse.status(),
      "a CSRF/Access HTTP403 or server HTTP500 cannot count as a mailbox-proof denial").toBeLessThan(400);
    await expect(prematurePage).toHaveURL(new RegExp(`/recover\\?requestId=${requestId}&error=1`));
    expect(await database.user.findUniqueOrThrow({
      where: { id: owner.id }, select: { email: true, emailNormalized: true, passwordHash: true }
    })).toEqual(beforePremature);
    expect(await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, recoveryNewEmail: true, recoveryNewEmailVerifiedAt: true, bootstrapSessionId: true }
    })).toEqual(noMailboxProof);
    expect(await database.session.count({
      where: { userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() } }
    })).toBe(sessionsBeforePremature);
    expect(await verifyPassword(beforePremature.passwordHash ?? "", prematurePassword)).toBe(false);
    await expect(mailbox.getByLabel("Código recebido no novo e-mail", { exact: true })).toBeVisible();

    await mailbox.getByLabel("Código recebido no novo e-mail", { exact: true }).fill(mailboxCode);
    await mailbox.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
    await expect(recoveryPage.getByRole("status").filter({ hasText: "Novo e-mail confirmado." })).toBeVisible();
    await expect(recoveryPage.getByLabel("Nova senha", { exact: true })).toBeVisible();
    const replacementProof = await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, recoveryNewEmailVerifiedAt: true }
    });
    expect(replacementProof.status).toBe("APPROVED");
    expect(replacementProof.recoveryNewEmailVerifiedAt).not.toBeNull();

    // Keep a real stale HTML form and recovery capability for an actual
    // second Next Server Action POST after the first successful reset.
    const replayPage = await recoveryContext.newPage();
    await addCloudflareAccessHeader(replayPage);
    await replayPage.goto(recoveryPage.url());
    await expect(replayPage.getByLabel("Nova senha", { exact: true })).toBeVisible();
    await replayPage.getByLabel("Nova senha", { exact: true }).fill(otherPassword);
    const priorCookies = (await recoveryContext.cookies(recoveryOrigin))
      .filter((cookie) => cookieNames.includes(cookie.name))
      .map((cookie) => ({
        url: `${recoveryOrigin}/`, name: cookie.name, value: cookie.value,
        expires: cookie.expires, httpOnly: cookie.httpOnly, secure: cookie.secure,
        sameSite: cookie.sameSite
      }));
    expect(priorCookies).toHaveLength(3);
    await recoveryPage.getByLabel("Nova senha", { exact: true }).fill(newPassword);
    const bootstrapDocumentPromise = recoveryPage.waitForResponse((response) =>
      response.request().method() === "GET" &&
      response.request().resourceType() === "document" &&
      new URL(response.url()).origin === recoveryOrigin &&
      new URL(response.url()).pathname === protectedPath);
    await recoveryPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    const bootstrapDocument = await bootstrapDocumentPromise;
    expect(bootstrapDocument.status(), `the recovered ${accountRole} must fetch a real protected document`).toBe(200);
    await expect(recoveryPage).toHaveURL(accountRole === "ADMIN"
      ? `${recoveryOrigin}${protectedPath}`
      : `${recoveryOrigin}${protectedPath}?recovered=password`);
    await expect(recoveryPage.getByRole("heading", { level: 1, name: protectedHeading, exact: true })).toBeVisible();
    const changedUser = await database.user.findUniqueOrThrow({
      where: { id: owner.id }, select: {
        email: true, emailNormalized: true, emailVerifiedAt: true,
        passwordHash: true, secondFactorMethod: true
      }
    });
    expect(changedUser.email).toBe(replacementEmail);
    expect(changedUser.emailNormalized).toBe(replacementEmail);
    expect(changedUser.emailVerifiedAt).not.toBeNull();
    expect(changedUser.secondFactorMethod).toBe("EMAIL");
    expect(await verifyPassword(changedUser.passwordHash ?? "", newPassword)).toBe(true);
    expect(await verifyPassword(changedUser.passwordHash ?? "", normalPassword)).toBe(false);
    expect(await database.administrativeCredential.findUnique({
      where: { userId: owner.id }, select: { passwordHash: true, status: true, keyVersion: true }
    })).toEqual(privilegedBefore);
    if (privilegedBefore) expect(await verifyPassword(privilegedBefore.passwordHash, administrativePassword)).toBe(true);
    expect((await database.totpFactor.findUniqueOrThrow({
      where: { userId: owner.id }, select: { status: true }
    })).status).toBe("REVOKED");
    const consumed = await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, bootstrapSessionId: true, consumedAt: true }
    });
    expect(consumed.status).toBe("CONSUMED");
    expect(consumed.consumedAt).not.toBeNull();
    expect(consumed.bootstrapSessionId).toBeTruthy();
    expect((await database.session.findUniqueOrThrow({
      where: { id: oldSession.id }, select: { revokedAt: true }
    })).revokedAt).not.toBeNull();
    expect(await database.session.count({
      where: { userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() } }
    })).toBe(1);
    const bootstrapSession = await database.session.findUniqueOrThrow({
      where: { id: consumed.bootstrapSessionId! },
      select: { userId: true, tokenHash: true, revokedAt: true, expiresAt: true }
    });
    expect(bootstrapSession.userId).toBe(owner.id);
    expect(bootstrapSession.revokedAt).toBeNull();
    expect(bootstrapSession.expiresAt.getTime()).toBeGreaterThan(Date.now());
    const bootstrapCookies = (await recoveryContext.cookies(recoveryOrigin))
      .filter((cookie) => cookie.name === sessionCookieName && cookie.value.length > 0);
    expect(bootstrapCookies, "the recovered browser must receive exactly one host-bound Hub session cookie").toHaveLength(1);
    expect(bootstrapCookies[0]!.domain).toBe(new URL(recoveryOrigin).hostname);
    expect(bootstrapCookies[0]!.path).toBe("/");
    expect(bootstrapCookies[0]!.httpOnly).toBe(true);
    expect(bootstrapCookies[0]!.secure).toBe(productionMode);
    expect(hashSessionToken(bootstrapCookies[0]!.value),
      "the browser session token must match the exact persisted bootstrap session").toBe(bootstrapSession.tokenHash);
    const oldProtectedPath = accountRole === "ADMIN" ? "/admin/security" : "/account/security";
    await ownerPage.goto(`${recoveryOrigin}${oldProtectedPath}`);
    // The ADMIN protected route preserves an allowlisted returnTo. The USER
    // account-security page intentionally uses a plain /login redirect when
    // its old session has been revoked (see account/security/page.tsx).
    await expect(ownerPage).toHaveURL(accountRole === "ADMIN"
      ? `${recoveryOrigin}/login?returnTo=${encodeURIComponent(oldProtectedPath)}`
      : `${recoveryOrigin}/login`);
    await expect(recoveryContext.cookies(recoveryOrigin).then((cookies) =>
      cookies.filter((cookie) => cookieNames.includes(cookie.name)))).resolves.toHaveLength(0);

    const sessionRowsBeforeReplay = await database.session.count({ where: { userId: owner.id } });
    await recoveryContext.addCookies(priorCookies);
    const replayResponsePromise = replayPage.waitForResponse((response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).origin === recoveryOrigin &&
      new URL(response.url()).pathname === "/recover" &&
      Boolean(response.request().headers()["next-action"]));
    await replayPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    const replayResponse = await replayResponsePromise;
    expect(replayResponse.request().postDataBuffer()?.byteLength ?? 0).toBeGreaterThan(0);
    expect(replayResponse.status(), "a server/CSRF error is not a valid single-use replay denial").toBeGreaterThanOrEqual(200);
    expect(replayResponse.status()).toBeLessThan(400);
    const deniedUrl = `${recoveryOrigin}/recover?requestId=${requestId}&error=1`;
    await expect(replayPage).toHaveURL(deniedUrl);
    const deniedDocument = await replayPage.goto(deniedUrl);
    expect(deniedDocument?.status(), "the consumed capability must render a real invalid-link document").toBe(200);
    await expect(replayPage.getByRole("heading", {
      level: 1, name: accountRole === "ADMIN" ? "Recuperar acesso administrativo" : "Recuperar conta", exact: true
    })).toBeVisible();
    // A replay with a still-bound browser cookie follows the generic
    // error=1 message; the older invalid-link copy is for missing proof
    // cookies. Security is verified by no completion form, unchanged
    // CONSUMED DB row, unchanged password, and no extra session or email.
    await expect(replayPage.locator('p.form-error[role="alert"]'))
      .toContainText("Não foi possível concluir esta etapa. O link pode ter expirado");
    await expect(replayPage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const replayed = await database.user.findUniqueOrThrow({ where: { id: owner.id } });
    expect(await verifyPassword(replayed.passwordHash ?? "", newPassword)).toBe(true);
    expect(await verifyPassword(replayed.passwordHash ?? "", otherPassword)).toBe(false);
    expect(replayed.email).toBe(replacementEmail);
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId }, select: { status: true, bootstrapSessionId: true }
    }))).toEqual({ status: "CONSUMED", bootstrapSessionId: consumed.bootstrapSessionId });
    expect(await database.session.count({
      where: { userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() } }
    })).toBe(1);
    expect(await database.session.count({ where: { userId: owner.id } }),
      "the replay must not mint another session, even if immediately revoked").toBe(sessionRowsBeforeReplay);
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: replacementEmail, kind: "PASSWORD_CHANGED" }
    })).toBe(1);
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: ownedEmail, kind: "RECOVERY_EMAIL_REBIND_NOTICE" }
    }), "the unreachable old inbox only receives a nonsecret account-change notice").toBe(1);

    // Bootstrap proves immediate protected access, but the owner must also
    // authenticate from a NEW browser with the replacement mailbox and new
    // normal password. This exercises real login + emailed MFA, not a DB hash
    // comparison or a session that survived the recovery ceremony.
    const freshContext = await newContext();
    const freshPage = await freshContext.newPage();
    if (accountRole === "ADMIN") await addCloudflareAccessHeader(freshPage);
    expect((await freshPage.goto(`${recoveryOrigin}${protectedPath}`))?.status()).toBe(200);
    await expect(freshPage).toHaveURL(`${recoveryOrigin}/login?returnTo=${encodeURIComponent(protectedPath)}`);
    await freshPage.getByLabel("E-mail", { exact: true }).fill(replacementEmail);
    await freshPage.getByLabel("Senha", { exact: true }).fill(newPassword);
    const loginPost = freshPage.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).origin === recoveryOrigin &&
      new URL(response.url()).pathname === "/api/login");
    await freshPage.getByRole("button", { name: "Entrar", exact: true }).click();
    expect((await loginPost).status()).toBe(303);
    await freshPage.waitForURL((url) => url.pathname === "/login/verify" &&
      url.searchParams.get("factor") === "email" && Boolean(url.searchParams.get("ceremony")));
    const loginCeremony = new URL(freshPage.url()).searchParams.get("ceremony")!;
    const loginEmail = await database.emailOutboxMessage.findFirst({
      where: {
        recipientEmail: replacementEmail, idempotencyKey: `security-ceremony:${loginCeremony}`,
        kind: { in: ["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"] }
      }, select: { payload: true }
    });
    expect(loginEmail, `fresh ${accountRole} login must require real, newly emailed MFA`).not.toBeNull();
    const loginCode = decryptEmailPayload(loginEmail!.payload).code;
    expect(loginCode).toMatch(/^\d{6}$/u);
    await freshPage.getByLabel("Código", { exact: true }).fill(loginCode!);
    const freshDocument = freshPage.waitForResponse((response) =>
      response.request().method() === "GET" && response.request().resourceType() === "document" &&
      new URL(response.url()).origin === recoveryOrigin && new URL(response.url()).pathname === protectedPath);
    await freshPage.getByRole("button", { name: "Continuar", exact: true }).click();
    expect((await freshDocument).status()).toBe(200);
    await expect(freshPage).toHaveURL(`${recoveryOrigin}${protectedPath}`);
    await expect(freshPage.getByRole("heading", { level: 1, name: protectedHeading, exact: true })).toBeVisible();
    const freshCookie = (await freshContext.cookies(recoveryOrigin))
      .find((cookie) => cookie.name === sessionCookieName && cookie.value.length > 0);
    expect(freshCookie).toBeDefined();
    expect(freshCookie!.domain).toBe(new URL(recoveryOrigin).hostname);
    expect(freshCookie!.httpOnly).toBe(true);
    const freshSession = await database.session.findFirstOrThrow({
      where: { tokenHash: hashSessionToken(freshCookie!.value) },
      select: { id: true, userId: true, revokedAt: true, expiresAt: true }
    });
    expect(freshSession.userId).toBe(owner.id);
    expect(freshSession.id).not.toBe(consumed.bootstrapSessionId);
    expect(freshSession.revokedAt).toBeNull();
    expect(freshSession.expiresAt.getTime()).toBeGreaterThan(Date.now());
  } finally {
    // AuditLog is append-only and its actor FK RESTRICTs deletes. Never
    // UPDATE/DELETE audit rows or attempt a fragile User FK cleanup. The
    // dedicated disposable E2E runner drops virki_e2e_test after the suite.
    const closes = await Promise.allSettled(contexts.map((context) => context.close()));
    // Keep this owner-labelled fixture and its outbox/audit receipts intact.
    await database.$disconnect();
    expect(closes.every((result) => result.status === "fulfilled"),
      "every browser context must close").toBe(true);
  }
});
}
