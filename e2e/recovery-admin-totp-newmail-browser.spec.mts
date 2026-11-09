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

test("ADMIN TOTP_ADMIN: independent approval, verified replacement mailbox, one reset and role/browser isolation", async ({ browser }) => {
  test.setTimeout(180_000);
  const { database, reviewer } = await requireDisposableFixture();
  const contexts: BrowserContext[] = [];
  const newContext = async () => {
    const context = await browser.newContext();
    contexts.push(context);
    return context;
  };
  const ownedEmail = `totp-admin-${randomUUID()}@e2e.invalid`;
  const replacementEmail = `replacement-admin-${randomUUID()}@e2e.invalid`;
  const normalPassword = randomBytes(32).toString("base64url");
  const administrativePassword = randomBytes(32).toString("base64url");
  const newPassword = randomBytes(32).toString("base64url");
  const otherPassword = randomBytes(32).toString("base64url");
  let ownerId: string | undefined;
  try {
    const secret = createTotpSecret();
    const owner = await database.user.create({
      data: {
        email: ownedEmail, emailNormalized: ownedEmail,
        displayName: "Owned TOTP ADMIN browser E2E", role: "ADMIN",
        accountStatus: "ACTIVE", isActive: true, emailVerifiedAt: new Date(),
        passwordHash: await hashPassword(normalPassword), secondFactorMethod: "TOTP",
        totpFactor: { create: {
          secretCiphertext: encryptTotpSecret(secret),
          keyVersion: 1, status: "ACTIVE", confirmedAt: new Date()
        } },
        administrativeCredential: { create: {
          passwordHash: await hashPassword(administrativePassword), status: "ACTIVE"
        } }
      },
      select: { id: true }
    });
    ownerId = owner.id;
    expect(owner.id).not.toBe(reviewer.id);
    const privilegedBefore = await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: owner.id },
      select: { passwordHash: true, status: true, keyVersion: true }
    });
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
      name: sessionCookieName, value: oldToken, url: hubUrl,
      httpOnly: true, secure: true, sameSite: "Lax"
    }]);
    const ownerPage = await ownerContext.newPage();
    await addCloudflareAccessHeader(ownerPage);
    await ownerPage.goto(`${hubUrl}/admin/security`);
    await expect(ownerPage.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();

    const reviewerContext = await newContext();
    await reviewerContext.addCookies([{
      name: deviceCookieName,
      value: reviewer.deviceToken, url: hubUrl, httpOnly: true, secure: true, sameSite: "Lax"
    }]);
    const reviewerPage = await reviewerContext.newPage();
    await addCloudflareAccessHeader(reviewerPage);
    await signInReviewer(reviewerPage, database, reviewer);

    // A Portal recovery cannot claim an ADMIN identity, even when the method
    // is displayed there for legitimate USER accounts.
    const portalContext = await newContext();
    const portalPage = await portalContext.newPage();
    await portalPage.goto(`${portalUrl}/recover`);
    await portalPage.getByLabel("E-mail da conta", { exact: true }).fill(ownedEmail);
    await portalPage.locator('input[name="method"][value="TOTP_ADMIN"]').check();
    await portalPage.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    await expect(portalPage).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]{43}$/u);
    expect(await database.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(0);

    const deniedContext = await newContext();
    const deniedPage = await deniedContext.newPage();
    expect((await deniedPage.goto(`${hubUrl}/recover`))?.status()).toBe(403);

    const recoveryContext = await newContext();
    const recoveryPage = await recoveryContext.newPage();
    await addCloudflareAccessHeader(recoveryPage);
    await recoveryPage.goto(`${hubUrl}/recover`);
    await expect(recoveryPage.getByRole("heading", { name: "Recuperar acesso administrativo" })).toBeVisible();
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
      userId: owner.id, status: "PENDING", recoveryRole: "ADMIN",
      recoveryProofs: ["TOTP"], recoveryAdminReview: true,
      recoveryComment: "Revisão TOTP_ADMIN e troca de caixa postal.",
      recoveryTotpVerifiedAt: null, emailVerifiedAt: null, recoveryNewEmail: null
    });
    const boundCookies = await recoveryContext.cookies(hubUrl);
    for (const name of cookieNames) {
      const cookie = boundCookies.find((item) => item.name === name);
      expect(cookie, `No ${name} cookie`).toBeDefined();
      expect(cookie!.domain).toBe(new URL(hubUrl).hostname);
      expect(cookie!.path).toBe("/");
      expect(cookie!.httpOnly).toBe(true);
      expect(cookie!.value.length).toBeGreaterThan(0);
    }
    expect(boundCookies.find((item) => item.name === cookieNames[2])?.value).toBe(`${requestId}.TOTP_ADMIN`);

    // Public request IDs do not authorize another browser, even with its own
    // valid synthetic Access header.
    const foreignContext = await newContext();
    const foreignPage = await foreignContext.newPage();
    await addCloudflareAccessHeader(foreignPage);
    await foreignPage.goto(`${hubUrl}/recover?requestId=${encodeURIComponent(requestId)}`);
    await expect(foreignPage.locator('[aria-label="Aplicativo autenticador"] input[name="code"]')).toHaveCount(0);
    await expect(foreignPage.getByLabel("Novo endereço de e-mail")).toHaveCount(0);

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
      "the owner must not review their own recovery").toHaveCount(0);
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
    const priorCookies = (await recoveryContext.cookies(hubUrl))
      .filter((cookie) => cookieNames.includes(cookie.name))
      .map((cookie) => ({
        url: `${hubUrl}/`, name: cookie.name, value: cookie.value,
        expires: cookie.expires, httpOnly: cookie.httpOnly, secure: cookie.secure,
        sameSite: cookie.sameSite
      }));
    expect(priorCookies).toHaveLength(3);
    await recoveryPage.getByLabel("Nova senha", { exact: true }).fill(newPassword);
    await recoveryPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(recoveryPage).toHaveURL(`${hubUrl}/admin/accounts`);
    await expect(recoveryPage.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
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
    expect(await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: owner.id }, select: { passwordHash: true, status: true, keyVersion: true }
    })).toEqual(privilegedBefore);
    expect(await verifyPassword(privilegedBefore.passwordHash, administrativePassword)).toBe(true);
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
    expect((await database.session.findUniqueOrThrow({
      where: { id: consumed.bootstrapSessionId! },
      select: { userId: true, revokedAt: true }
    }))).toEqual({ userId: owner.id, revokedAt: null });
    await ownerPage.goto(`${hubUrl}/admin/security`);
    await expect(ownerPage).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Fsecurity`);
    await expect(recoveryContext.cookies(hubUrl).then((cookies) =>
      cookies.filter((cookie) => cookieNames.includes(cookie.name)))).resolves.toHaveLength(0);

    await recoveryContext.addCookies(priorCookies);
    const replayResponsePromise = replayPage.waitForResponse((response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).origin === hubUrl &&
      new URL(response.url()).pathname === "/recover" &&
      Boolean(response.request().headers()["next-action"]));
    await replayPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    const replayResponse = await replayResponsePromise;
    expect(replayResponse.request().postDataBuffer()?.byteLength ?? 0).toBeGreaterThan(0);
    await expect(replayPage).toHaveURL(new RegExp(`/recover\\?requestId=${requestId}&error=1`));
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
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: replacementEmail, kind: "PASSWORD_CHANGED" }
    })).toBe(1);
  } finally {
    // AuditLog is append-only and its actor FK RESTRICTs deletes. Never
    // UPDATE/DELETE audit rows or use a privileged cleanup role in this spec.
    const closes = await Promise.allSettled(contexts.map((context) => context.close()));
    try {
      if (ownerId) {
        await database.emailOutboxMessage.deleteMany({
          where: { recipientEmail: { in: [ownedEmail, replacementEmail] } }
        });
        // A reviewer session or a protected-page read may have written an
        // immutable audit event naming this ADMIN. Retain the user in that
        // case for FK integrity; the harness destroys virki_e2e_test after CI.
        if (await database.auditLog.count({ where: { actorUserId: ownerId } }) === 0) {
          await database.user.deleteMany({ where: { id: ownerId } });
        }
      }
    } finally {
      await database.$disconnect();
    }
    expect(closes.every((result) => result.status === "fulfilled"),
      "every browser context must close").toBe(true);
  }
});
