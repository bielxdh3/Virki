import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { PrismaClient } from "@virki/database";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { SESSION_COOKIE_NAME } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { hashRecoveryRequestKey, requestAccountRecovery } from "@virki/auth/security";
// @ts-expect-error The disposable-database guard is a JavaScript safety helper without a declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const portalUrl = "https://portal.localhost:3001";
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
test.skip(!e2eDatabaseUrl, "Recovery/invitation E2E requires an explicit disposable PostgreSQL fixture.");

type AuthFixture = { admin: { id: string }; user: { id: string; password: string } };

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
  try {
    const { provisionInvitedUserAccount } = await import("@virki/auth/account-invitation");
    const email = `${randomUUID()}.invited@e2e.invalid`;
    await provisionInvitedUserAccount({ id: fixture.admin.id }, { email, displayName: "E2E Invitee" });
    const account = await database.user.findUnique({ where: { emailNormalized: email }, select: { id: true, passwordHash: true } });
    expect(account).not.toBeNull();
    const message = await database.emailOutboxMessage.findFirst({ where: { recipientEmail: email, kind: "ACCOUNT_INVITATION" }, select: { payload: true } });
    expect(message).not.toBeNull();
    if (!account || !message) throw new Error("Invitation E2E fixture was not created.");
    const actionUrl = decryptEmailPayload(message.payload).actionUrl;
    if (!actionUrl || new URL(actionUrl).origin !== portalUrl) throw new Error("Invitation E2E link is invalid.");
    const spoofedUrl = new URL(actionUrl);
    spoofedUrl.searchParams.set("purpose", "RECOVERY");
    const page = await context.newPage();
    await page.goto(spoofedUrl.toString());
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
    await expect(page.getByRole("alert")).toContainText("Não foi possível abrir este link.");
    await expect(page.getByLabel("Criar senha", { exact: true })).toHaveCount(0);
    expect(await database.user.findUnique({ where: { id: account.id }, select: { passwordHash: true } })).toEqual({ passwordHash: activated?.passwordHash });
  } finally {
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

test("USER TOTP confirmation hides the enrollment secret and recovery codes after success", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("TOTP E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const context = await browser.newContext();
  let sessionId: string | undefined;
  try {
    const token = randomBytes(32).toString("base64url");
    const session = await database.session.create({ data: {
      userId: fixture.user.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 600_000), authenticationMethods: ["pwd", "otp", "mfa"]
    }, select: { id: true } });
    sessionId = session.id;
    await context.addCookies([{ name: SESSION_COOKIE_NAME, value: token, url: portalUrl, httpOnly: true, secure: true, sameSite: "Lax" }]);
    const page = await context.newPage();
    await page.goto(`${portalUrl}/account/security`);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const factorSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Autenticação multifator", exact: true }) });
    await factorSection.getByLabel("Senha atual", { exact: true }).fill(fixture.user.password);
    await factorSection.getByRole("button", { name: "Configurar aplicativo autenticador", exact: true }).click();
    const secretElement = factorSection.locator("code");
    await expect(secretElement).toHaveCount(1);
    const secret = (await secretElement.textContent())?.trim() ?? "";
    expect(secret).toMatch(/^[A-Z2-7]+=*$/u);
    const code = currentTotpCode(secret);
    await factorSection.getByLabel("Código atual do aplicativo", { exact: true }).fill(code);
    await factorSection.getByRole("button", { name: "Ativar TOTP", exact: true }).click();
    await expect(factorSection.getByRole("heading", { name: "Códigos de recuperação — exibidos uma vez", exact: true })).toBeVisible();
    const codes = await factorSection.locator("section[aria-live='polite'] li code").allTextContents();
    expect(codes).toHaveLength(10);
    await expect(factorSection.getByText(secret, { exact: true })).toHaveCount(0);
    expect(await page.content()).not.toContain(secret);
    expect(await database.recoveryCode.count({ where: { userId: fixture.user.id, usedAt: null } })).toBe(10);

    await page.reload();
    await expect(factorSection.getByText("Aplicativo autenticador (TOTP) ativo.", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Códigos de recuperação — exibidos uma vez", exact: true })).toHaveCount(0);
    await expect(page.getByText(secret, { exact: true })).toHaveCount(0);
    for (const recoveryCode of codes) await expect(page.getByText(recoveryCode, { exact: true })).toHaveCount(0);
  } finally {
    if (sessionId) await database.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
    await context.close();
    await database.$disconnect();
  }
});

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
