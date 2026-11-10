import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { createTotpSecret, encryptTotpSecret, hashRecoveryCode } from "@virki/auth/security";
import { PrismaClient } from "@virki/database";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

// @ts-expect-error The reviewed disposable database guard is JavaScript without a declaration.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const productionHubMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const hubUrl = productionHubMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();
const sessionCookieName = getSessionCookieName({ NODE_ENV: productionHubMode ? "production" : "development" });

test.skip((!databaseUrl || !fixturePath) && process.env.VIRKI_E2E_REQUIRE_RECOVERY !== "true",
  "Requires isolated E2E resources; VIRKI_E2E_REQUIRE_RECOVERY=true makes this a mandatory browser gate.");

async function confirmedDatabase(): Promise<PrismaClient> {
  if (!databaseUrl || !fixturePath || !existsSync(fixturePath) ||
    process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("Administrative credential browser E2E requires a seeded disposable database.");
  }
  assertDisposableCoreTestDatabase(databaseUrl, process.env);
  if (new URL(databaseUrl).pathname !== "/virki_e2e_test") {
    throw new Error("Administrative credential browser E2E is restricted to virki_e2e_test.");
  }
  const fixture: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!fixture || typeof fixture !== "object" || !("admin" in fixture)) {
    throw new Error("An isolated E2E global-setup fixture is required.");
  }
  return new PrismaClient({ datasources: { db: { url: databaseUrl } } });
}

function totpAt(secret: string, now = new Date()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const character of secret) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid owned TOTP seed.");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return String((digest.readUInt32BE(digest[digest.length - 1]! & 0xf) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

function recoveryForm(page: Page) {
  const credential = page.locator("section.surface").filter({
    has: page.getByRole("heading", { name: "Credencial administrativa", exact: true })
  });
  return credential.locator("form").filter({
    has: page.getByRole("button", { name: "Recuperar por TOTP", exact: true })
  });
}

async function fillTotpRecovery(page: Page, normalPassword: string, code: string, newAdminPassword: string) {
  const form = recoveryForm(page);
  await expect(form).toBeVisible();
  await form.locator('input[name="normalPassword"]').fill(normalPassword);
  await form.locator('input[name="totpCode"]').fill(code);
  await form.locator('input[name="newPassword"]').fill(newAdminPassword);
  await form.locator('input[name="confirmPassword"]').fill(newAdminPassword);
  return form;
}

test("ADMIN separate credential: normal password + active TOTP rotates codes, denies replay, and enables new emailed elevation", async ({ browser }) => {
  test.setTimeout(180_000);
  const database = await confirmedDatabase();
  const contexts: BrowserContext[] = [];
  const context = await browser.newContext();
  contexts.push(context);
  const ownerEmail = `admin-totp-credential-${randomUUID()}@e2e.invalid`;
  const normalPassword = randomBytes(32).toString("base64url");
  const oldAdminPassword = randomBytes(32).toString("base64url");
  const newAdminPassword = randomBytes(32).toString("base64url");
  const replayCandidate = randomBytes(32).toString("base64url");

  try {
    const totpSecret = createTotpSecret();
    const oldRecoveryCodes = Array.from({ length: 10 }, () => randomBytes(9).toString("hex").toUpperCase());
    const admin = await database.user.create({
      data: {
        email: ownerEmail, emailNormalized: ownerEmail,
        displayName: "Owned ADMIN TOTP credential browser E2E", role: "ADMIN",
        isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
        passwordHash: await hashPassword(normalPassword), secondFactorMethod: "TOTP",
        totpFactor: { create: {
          secretCiphertext: encryptTotpSecret(totpSecret), keyVersion: 1,
          confirmedAt: new Date(), status: "ACTIVE"
        } },
        administrativeCredential: { create: {
          passwordHash: await hashPassword(oldAdminPassword), status: "ACTIVE"
        } },
        administrativeRecoveryCodes: { create: oldRecoveryCodes.map((value) => ({
          codeHash: hashRecoveryCode(value)
        })) }
      },
      select: { id: true, passwordHash: true, secondFactorMethod: true }
    });
    const factorBefore = await database.totpFactor.findUniqueOrThrow({
      where: { userId: admin.id },
      select: { secretCiphertext: true, keyVersion: true, status: true, confirmedAt: true, lastUsedStep: true }
    });
    const originalNormalHash = admin.passwordHash;
    const oldCredential = await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: admin.id }, select: { passwordHash: true, status: true, keyVersion: true }
    });
    expect(oldCredential.status).toBe("ACTIVE");
    expect(oldCredential.keyVersion).toBe(1);

    const sessionToken = randomBytes(32).toString("base64url");
    const activeSession = await database.session.create({
      data: {
        userId: admin.id, tokenHash: hashSessionToken(sessionToken),
        expiresAt: new Date(Date.now() + 600_000), authenticationMethods: ["pwd", "otp", "mfa"]
      }, select: { id: true }
    });
    const otherSession = await database.session.create({
      data: {
        userId: admin.id, tokenHash: hashSessionToken(randomBytes(32).toString("base64url")),
        expiresAt: new Date(Date.now() + 600_000), authenticationMethods: ["pwd", "otp", "mfa"]
      }, select: { id: true }
    });
    const oldElevation = await database.securityElevation.create({
      data: {
        requestKey: randomBytes(32).toString("base64url"), userId: admin.id,
        sessionId: activeSession.id, protocolVersion: 1, credentialKeyVersion: oldCredential.keyVersion,
        scope: "ACCOUNT_STATE_CHANGE", challengeHash: "owned-disposable-fixture",
        status: "ACTIVE", activatedAt: new Date(), expiresAt: new Date(Date.now() + 600_000)
      }, select: { id: true }
    });

    await context.addCookies([{
      name: sessionCookieName, value: sessionToken, url: hubUrl,
      httpOnly: true, secure: true, sameSite: "Lax"
    }]);
    const page = await context.newPage();
    await addCloudflareAccessHeader(page);
    const initialPage = await page.goto(`${hubUrl}/admin/security`);
    expect(initialPage?.status()).toBe(200);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", {
      name: "Recuperar credencial por aplicativo autenticador (TOTP)", exact: true
    })).toBeVisible();
    await expect(recoveryForm(page).locator('input[name="csrfToken"]')).toHaveValue(/^v2\./u);
    await expect(recoveryForm(page).locator('input[name="recoveryCode"]')).toHaveCount(0);

    // The actual browser action must refuse an invalid TOTP without changing
    // the separate administrative credential or consuming recovery codes.
    const invalidTotp = totpAt(totpSecret) === "000000" ? "999999" : "000000";
    const invalidForm = await fillTotpRecovery(page, normalPassword, invalidTotp, newAdminPassword);
    const rejectedAction = page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/admin/security" &&
      Boolean(response.request().headers()["next-action"]));
    await invalidForm.getByRole("button", { name: "Recuperar por TOTP", exact: true }).click();
    const rejectedResponse = await rejectedAction;
    expect(rejectedResponse.status(), "a server error is not a valid negative proof").toBeLessThan(400);
    await expect(invalidForm.getByRole("alert")).toContainText("Não foi possível recuperar a credencial");
    expect(await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: admin.id }, select: { passwordHash: true, status: true, keyVersion: true }
    })).toEqual(oldCredential);
    expect(await database.administrativeRecoveryCode.count({ where: { userId: admin.id } })).toBe(10);

    // Render a second real form before the success; its stale Server Action
    // will be used to prove one TOTP step cannot reset the credential twice.
    const stalePage = await context.newPage();
    await addCloudflareAccessHeader(stalePage);
    expect((await stalePage.goto(`${hubUrl}/admin/security`))?.status()).toBe(200);
    await expect(recoveryForm(stalePage)).toBeVisible();
    const stepCode = totpAt(totpSecret);
    await fillTotpRecovery(stalePage, normalPassword, stepCode, replayCandidate);
    const validForm = await fillTotpRecovery(page, normalPassword, stepCode, newAdminPassword);
    const successAction = page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/admin/security" &&
      Boolean(response.request().headers()["next-action"]));
    await validForm.getByRole("button", { name: "Recuperar por TOTP", exact: true }).click();
    expect((await successAction).status()).toBeLessThan(400);
    const credentialSection = page.locator("section.surface").filter({
      has: page.getByRole("heading", { name: "Credencial administrativa", exact: true })
    });
    await expect(credentialSection.getByRole("heading", {
      name: "Códigos de recuperação — exibidos uma vez", exact: true
    })).toBeVisible();
    const visibleCodes = await credentialSection.locator("[data-sensitive-one-time-value] ul li code").allTextContents();
    expect(visibleCodes).toHaveLength(10);
    expect(new Set(visibleCodes).size).toBe(10);
    const newRecoveryHashes = (await database.administrativeRecoveryCode.findMany({
      where: { userId: admin.id }, select: { codeHash: true, usedAt: true }
    })).map((record) => record.codeHash);
    expect(newRecoveryHashes).toHaveLength(10);
    expect(new Set(newRecoveryHashes)).toEqual(new Set(visibleCodes.map(hashRecoveryCode)));
    for (const old of oldRecoveryCodes) expect(newRecoveryHashes).not.toContain(hashRecoveryCode(old));

    const changed = await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: admin.id }, select: { passwordHash: true, status: true, keyVersion: true }
    });
    expect(changed.status).toBe("ACTIVE");
    expect(changed.keyVersion).toBe(oldCredential.keyVersion + 1);
    expect(await verifyPassword(changed.passwordHash, newAdminPassword)).toBe(true);
    expect(await verifyPassword(changed.passwordHash, oldAdminPassword)).toBe(false);
    expect((await database.user.findUniqueOrThrow({
      where: { id: admin.id }, select: { passwordHash: true, secondFactorMethod: true }
    }))).toEqual({ passwordHash: originalNormalHash, secondFactorMethod: admin.secondFactorMethod });
    expect(await verifyPassword(originalNormalHash ?? "", normalPassword)).toBe(true);
    const factorAfter = await database.totpFactor.findUniqueOrThrow({
      where: { userId: admin.id },
      select: { secretCiphertext: true, keyVersion: true, status: true, confirmedAt: true, lastUsedStep: true }
    });
    expect(factorAfter).toMatchObject({
      secretCiphertext: factorBefore.secretCiphertext,
      keyVersion: factorBefore.keyVersion, status: "ACTIVE",
      confirmedAt: factorBefore.confirmedAt
    });
    expect(factorAfter.lastUsedStep).not.toBeNull();
    expect(factorAfter.lastUsedStep).not.toBe(factorBefore.lastUsedStep);
    expect((await database.securityElevation.findUniqueOrThrow({
      where: { id: oldElevation.id }, select: { status: true, revokedAt: true }
    })).status).toBe("REVOKED");
    expect((await database.session.findUniqueOrThrow({
      where: { id: otherSession.id }, select: { revokedAt: true }
    })).revokedAt).not.toBeNull();
    expect((await database.session.findUniqueOrThrow({
      where: { id: activeSession.id }, select: { revokedAt: true }
    })).revokedAt).toBeNull();
    expect(await database.auditLog.count({
      where: { actorUserId: admin.id, eventType: "ADMIN_CREDENTIAL_TOTP_RECOVERED", result: "SUCCESS" }
    })).toBe(1);

    const staleForm = recoveryForm(stalePage);
    const replayAction = stalePage.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/admin/security" &&
      Boolean(response.request().headers()["next-action"]));
    await staleForm.getByRole("button", { name: "Recuperar por TOTP", exact: true }).click();
    const replayResponse = await replayAction;
    expect(replayResponse.status()).toBeLessThan(400);
    expect(replayResponse.request().postDataBuffer()?.byteLength ?? 0).toBeGreaterThan(0);
    await expect(staleForm.getByRole("alert")).toContainText("Não foi possível recuperar a credencial");
    const afterReplay = await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: admin.id }, select: { passwordHash: true, status: true, keyVersion: true }
    });
    expect(afterReplay).toEqual(changed);
    expect(await verifyPassword(afterReplay.passwordHash, replayCandidate)).toBe(false);
    expect((await database.totpFactor.findUniqueOrThrow({
      where: { userId: admin.id }, select: { lastUsedStep: true }
    })).lastUsedStep).toBe(factorAfter.lastUsedStep);
    expect(new Set((await database.administrativeRecoveryCode.findMany({
      where: { userId: admin.id }, select: { codeHash: true }
    })).map((item) => item.codeHash))).toEqual(new Set(newRecoveryHashes));
    expect(await database.auditLog.count({
      where: { actorUserId: admin.id, eventType: "ADMIN_CREDENTIAL_TOTP_RECOVERED", result: "SUCCESS" }
    })).toBe(1);

    // Dismiss ephemeral codes before starting an independent, real
    // ADMIN_CREDENTIAL_CHANGE elevation on the still-live Hub session.
    const acknowledgment = credentialSection.getByRole("button", { name: "Já guardei os novos códigos", exact: true });
    await expect(acknowledgment).toBeDisabled();
    await credentialSection.getByRole("checkbox", {
      name: /Guardei os dez códigos de recuperação fora do Virki/u
    }).check();
    await acknowledgment.click();
    await expect(page).toHaveURL(`${hubUrl}/admin/security?status=totp-recovered#admin-content`);
    await expect(page.locator("[data-sensitive-one-time-value]")).toHaveCount(0);

    const elevationSection = page.locator("section.surface").filter({
      has: page.getByRole("heading", { name: "Elevação temporária", exact: true })
    });
    const elevationStart = elevationSection.locator("form").filter({
      has: page.getByRole("button", { name: "Solicitar elevação", exact: true })
    });
    await elevationStart.locator('select[name="scope"]').selectOption("ADMIN_CREDENTIAL_CHANGE");
    await elevationStart.locator('input[name="normalPassword"]').fill(normalPassword);
    await elevationStart.locator('input[name="administrativePassword"]').fill(oldAdminPassword);
    await elevationStart.getByRole("button", { name: "Solicitar elevação", exact: true }).click();
    await expect(elevationStart.getByRole("alert")).toContainText("Não foi possível solicitar");
    await expect(elevationSection.getByRole("button", { name: "Ativar elevação" })).toHaveCount(0);
    // The failed useActionState response may rerender the form with its first
    // default scope. Re-select the explicit privileged scope on the actual
    // successful submission instead of accepting ACCOUNT_STATE_CHANGE.
    await elevationStart.locator('select[name="scope"]').selectOption("ADMIN_CREDENTIAL_CHANGE");
    await expect(elevationStart.locator('select[name="scope"]')).toHaveValue("ADMIN_CREDENTIAL_CHANGE");
    await elevationStart.locator('input[name="normalPassword"]').fill(normalPassword);
    await elevationStart.locator('input[name="administrativePassword"]').fill(newAdminPassword);
    await elevationStart.getByRole("button", { name: "Solicitar elevação", exact: true }).click();
    const elevationVerify = elevationSection.locator("form").filter({
      has: page.getByRole("button", { name: "Ativar elevação", exact: true })
    });
    await expect(elevationVerify).toBeVisible();
    const requestKey = await elevationVerify.locator('input[name="requestKey"]').inputValue();
    expect(requestKey.length).toBeGreaterThan(10);
    const pendingElevation = await database.securityElevation.findUniqueOrThrow({
      where: { requestKey }, select: { userId: true, sessionId: true, status: true, scope: true, credentialKeyVersion: true }
    });
    expect(pendingElevation).toEqual({
      userId: admin.id, sessionId: activeSession.id, status: "PENDING",
      scope: "ADMIN_CREDENTIAL_CHANGE", credentialKeyVersion: changed.keyVersion
    });
    const outbox = await database.emailOutboxMessage.findFirst({
      where: { idempotencyKey: `admin-elevation:${requestKey}`, recipientEmail: ownerEmail, kind: "ADMIN_EMAIL_VERIFICATION" },
      select: { payload: true }
    });
    expect(outbox, "an actual elevation must enqueue an email OTP").not.toBeNull();
    const emailedCode = decryptEmailPayload(outbox!.payload).code;
    expect(emailedCode).toMatch(/^\d{6}$/u);
    await elevationVerify.locator('input[name="code"]').fill(emailedCode!);
    await elevationVerify.getByRole("button", { name: "Ativar elevação", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/security?status=elevation#admin-content`);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const activatedElevation = await database.securityElevation.findUniqueOrThrow({
      where: { requestKey }, select: { status: true, activatedAt: true, credentialKeyVersion: true }
    });
    expect(activatedElevation.status).toBe("ACTIVE");
    expect(activatedElevation.activatedAt).not.toBeNull();
    expect(activatedElevation.credentialKeyVersion).toBe(changed.keyVersion);
    expect(await database.auditLog.count({
      where: { actorUserId: admin.id, eventType: "ADMIN_ELEVATION_ACTIVATED", result: "SUCCESS" }
    })).toBe(1);
  } finally {
    // AuditLog is immutable with an actor FK RESTRICT. Never mutate audit
    // rows or delete this account; CI disposes of virki_e2e_test as a whole.
    const closed = await Promise.allSettled(contexts.map((item) => item.close()));
    await database.$disconnect();
    expect(closed.every((result) => result.status === "fulfilled")).toBe(true);
  }
});
