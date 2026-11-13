import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { PrismaClient } from "@virki/database";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { hashAuditIdentifier } from "@virki/auth/audit";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { createTotpSecret, encryptTotpSecret, hashEmailAddress, hashRecoveryRequestKey, hashSecurityCode } from "@virki/auth/security";
// @ts-expect-error This reviewed JS guard has no separate type declaration.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const productionMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const portalUrl = productionMode ? "https://portal.localhost" : "https://portal.localhost:3001";
const hubUrl = productionMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();

// The E2E global-setup creates owner-labelled fixtures on a private disposable
// database. This suite never provisions identities in shared/production data.
test.skip((!e2eDatabaseUrl || !fixturePath) && process.env.VIRKI_E2E_REQUIRE_RECOVERY !== "true" &&
  process.env.VIRKI_E2E_REQUIRE_RECOVERY_PASSKEYS !== "true" && process.env.VIRKI_E2E_PASSKEYS !== "true",
  "requires isolated E2E resources; VIRKI_E2E_REQUIRE_RECOVERY=true makes this a mandatory gate");

type Actor = { id: string; email: string };
type Fixture = { user: Actor; admin: Actor; recoveryReviewer: Actor };
type RecoveryCookie = { name: string; domain: string; path: string; httpOnly: boolean; secure: boolean; sameSite: string; value: string };

async function requireFixture(): Promise<{ fixture: Fixture; database: PrismaClient }> {
  if (!e2eDatabaseUrl || !fixturePath || process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("A confirmed owned disposable E2E database is required.");
  }
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  if (new URL(e2eDatabaseUrl).pathname !== "/virki_e2e_test") {
    throw new Error("Recovery browser tests require the dedicated E2E database name.");
  }
  // When the local owner-admitted Windows runner requests PG18, verify the
  // connected database version from the actual test client too; a runner
  // manifest or environment flag alone must never attest a PG18 browser run.
  if (process.env.VIRKI_E2E_POSTGRES_MAJOR === "18") {
    const probe = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
    try {
      const version = await probe.$queryRaw<Array<{ version_num: number }>>`SELECT current_setting('server_version_num')::integer AS version_num`;
      expect(version).toHaveLength(1);
      expect(version[0]?.version_num).toBeGreaterThanOrEqual(180000);
      expect(version[0]?.version_num).toBeLessThan(190000);
    } finally {
      await probe.$disconnect();
    }
  }
  const parsed: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!parsed || typeof parsed !== "object") throw new Error("Missing E2E account fixture.");
  const value = parsed as Record<string, unknown>;
  for (const role of ["user", "admin", "recoveryReviewer"] as const) {
    const actor = value[role];
    if (!actor || typeof actor !== "object" || typeof (actor as Actor).id !== "string" ||
        typeof (actor as Actor).email !== "string") throw new Error("Invalid E2E account fixture.");
  }
  return { fixture: value as Fixture, database: new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } }) };
}

async function openRecovery(browser: Browser, surface: "portal" | "hub") {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    if (surface === "hub") await addCloudflareAccessHeader(page);
    const base = surface === "portal" ? portalUrl : hubUrl;
    await page.goto(`${base}/recover`);
    return { context, page, base };
  } catch (error) {
    // A navigation or synthetic Access setup failure occurs before the caller
    // can register this context for its own cleanup.
    await context.close();
    throw error;
  }
}

async function startSelectedRecovery(page: Page, email: string, method: "TOTP_EMAIL" | "PASSKEY_EMAIL" | "PASSKEY_TOTP" | "PASSKEY_ADMIN"): Promise<string> {
  await page.getByLabel("E-mail da conta", { exact: true }).fill(email);
  await page.locator(`input[name="method"][value="${method}"]`).check();
  const selectedPost = page.waitForResponse((response) => response.request().method() === "POST" &&
    new URL(response.url()).pathname === "/recover");
  await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
  const postResponse = await selectedPost;
  const setCookieHeaders = (await postResponse.headersArray()).filter((header) => header.name.toLowerCase() === "set-cookie").map((header) => header.value);
  // In production-Hub rehearsals both TLS hostnames reach the Hub's :443 proxy,
  // which forwards /recover into Next with NODE_ENV=production. The standalone
  // public-site dev service on :3000 is not the origin of this recovery action.
  const cookieNames = productionMode
    ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
    : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
  for (const name of cookieNames) {
    const issued = setCookieHeaders.find((header) => header.startsWith(`${name}=`));
    expect(issued, `server must issue ${name} in this recovery response`).toBeDefined();
    expect(/(?:^|;)\s*Domain=/iu.test(issued!), "recovery cookie must be host-only without a Domain attribute").toBe(false);
  }
  await expect(page).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]+$/u);
  const publicRequestId = new URL(page.url()).searchParams.get("requestId") ?? "";
  expect(publicRequestId).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  if (method === "TOTP_EMAIL" || method === "PASSKEY_EMAIL") {
    await expect(page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toBeVisible();
  } else if (method === "PASSKEY_TOTP") {
    await expect(page.locator('[aria-label="Aplicativo autenticador"] input[name="code"]')).toBeVisible();
  } else {
    await expect(page.locator('[aria-label="Chave de acesso"] button')).toBeVisible();
  }
  return publicRequestId;
}

async function startSelectedTotpEmail(page: Page, email: string): Promise<string> {
  return startSelectedRecovery(page, email, "TOTP_EMAIL");
}

async function assertBoundCookies(context: BrowserContext, base: string, requestId: string,
  method: "TOTP_EMAIL" | "PASSKEY_EMAIL" | "PASSKEY_TOTP" | "PASSKEY_ADMIN" = "TOTP_EMAIL"): Promise<void> {
  const cookies = await context.cookies(base);
  const host = new URL(base).hostname;
  const names = productionMode
    ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
    : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
  for (const name of names) {
    const cookie = cookies.find((candidate) => candidate.name === name) as RecoveryCookie | undefined;
    expect(cookie, `${name} must be issued only by the selected recovery host`).toBeDefined();
    expect(cookie!.domain).toBe(host);
    expect(cookie!.path).toBe("/");
    expect(cookie!.httpOnly).toBe(true);
    expect(cookie!.sameSite).toBe("Lax");
    expect(cookie!.secure).toBe(productionMode);
    expect(cookie!.value.length).toBeGreaterThan(0);
  }
  expect(cookies.find((cookie) => cookie.name === names[2])?.value).toBe(`${requestId}.${method}`);
  expect(cookies.some((cookie) => cookie.name === "virki_recovery" && cookie.value.length > 0),
    "legacy path-scoped recovery cookie must not remain active").toBe(false);
}

function totpAt(secret: string, at = new Date()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const character of secret) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid test TOTP secret.");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return String((digest.readUInt32BE(digest[digest.length - 1]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

// Explicit CI opt-in must fail rather than silently skip a missing physical
// browser/credential run. Playwright uses only isolated Linux TLS/NSS and DB.
const mandatoryPasskeyRecovery = process.env.VIRKI_E2E_REQUIRE_RECOVERY_PASSKEYS === "true";
const physicalPasskeyEnabled = process.env.VIRKI_E2E_PASSKEYS === "true";

async function enrollVirtualRecoveryCredential(page: Page, database: PrismaClient, owner: Actor): Promise<void> {
  const options = await generateRegistrationOptions({
    rpName: "Virki E2E", rpID: "portal.localhost", userID: Buffer.from(owner.id, "utf8"),
    userName: owner.email, attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: [-7], timeout: 60_000
  });
  // A real CDP virtual authenticator creates the non-exportable private key.
  // Only its public key is persisted to this test-owned disposable PG account.
  const registration = await page.evaluate(async (input) => {
    const bytes = (encoded: string) => Uint8Array.from(
      atob(encoded.replace(/-/gu, "+").replace(/_/gu, "/")), (character) => character.charCodeAt(0));
    const encode = (buffer: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
    const credential = await navigator.credentials.create({ publicKey: {
      rp: input.rp,
      user: { ...input.user, id: bytes(input.user.id) },
      challenge: bytes(input.challenge), pubKeyCredParams: input.pubKeyCredParams,
      authenticatorSelection: input.authenticatorSelection, timeout: input.timeout, attestation: "none"
    } }) as PublicKeyCredential;
    const attestation = credential.response as AuthenticatorAttestationResponse;
    return {
      id: credential.id, rawId: encode(credential.rawId), type: "public-key" as const,
      response: {
        clientDataJSON: encode(attestation.clientDataJSON),
        attestationObject: encode(attestation.attestationObject),
        transports: attestation.getTransports() as Array<"internal" | "usb" | "nfc" | "ble" | "hybrid">
      },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: (credential.authenticatorAttachment ?? undefined) as "platform" | "cross-platform" | undefined
    };
  }, options);
  const verified = await verifyRegistrationResponse({
    response: registration, expectedChallenge: options.challenge,
    expectedRPID: "portal.localhost", expectedOrigin: portalUrl, requireUserVerification: true
  });
  expect(verified.verified).toBe(true);
  expect(verified.registrationInfo).toBeDefined();
  const info = verified.registrationInfo!;
  await database.passkeyCredential.create({ data: {
    userId: owner.id, name: "E2E recovery key",
    credentialId: info.credential.id, publicKey: Buffer.from(info.credential.publicKey),
    counter: BigInt(info.credential.counter), transports: info.credential.transports ?? [],
    backupEligible: info.credentialDeviceType === "multiDevice",
    backupState: info.credentialBackedUp, rpID: "portal.localhost"
  } });
  expect(await database.passkeyCredential.count({ where: {
    userId: owner.id, credentialId: registration.id, revokedAt: null
  } })).toBe(1);
}

for (const method of ["PASSKEY_EMAIL", "PASSKEY_TOTP"] as const) {
  test("USER " + method + ": Chromium CDP assertion + Next recovery actions, CSRF, replay and cookies", async ({ browser }) => {
    test.skip(!mandatoryPasskeyRecovery && !physicalPasskeyEnabled,
      "Physical passkey recovery requires the explicit VIRKI_E2E_PASSKEYS opt-in.");
    test.setTimeout(180_000);
    if (!physicalPasskeyEnabled || productionMode) {
      throw new Error("Mandatory WebAuthn recovery requires a non-production E2E Hub with explicit passkey flag.");
    }
    const { database } = await requireFixture();
    const contexts: BrowserContext[] = [];
    const ownerEmail = randomUUID() + "." + method.toLowerCase() + "@e2e.invalid";
    const password = randomBytes(32).toString("base64url");
    const totpSecret = method === "PASSKEY_TOTP" ? createTotpSecret() : undefined;
    let ownerId: string | undefined;
    let replacementEmail: string | undefined;
    try {
      const owner = await database.user.create({ data: {
        email: ownerEmail, emailNormalized: ownerEmail, displayName: ownerEmail,
        passwordHash: await hashPassword(password), role: "USER",
        isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
        secondFactorMethod: totpSecret ? "TOTP" : "EMAIL",
        ...(totpSecret ? { totpFactor: { create: {
          secretCiphertext: encryptTotpSecret(totpSecret), keyVersion: 1,
          status: "ACTIVE", confirmedAt: new Date()
        } } } : {})
      }, select: { id: true, email: true } });
      ownerId = owner.id;
      const context = await browser.newContext();
      contexts.push(context);
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
        protocol: "ctap2", transport: "internal", hasResidentKey: true,
        hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true
      } });
      try {
        await page.goto(portalUrl + "/recover");
        expect(await page.evaluate(() => window.isSecureContext)).toBe(true);
        await enrollVirtualRecoveryCredential(page, database, owner);

        // A tampered actual form must not mint a new capability even for an
        // enrolled account. It runs in a separate cookie jar from recovery.
        const csrf = await openRecovery(browser, "portal");
        contexts.push(csrf.context);
        const before = await database.accountRecoveryRequest.count({ where: { userId: owner.id } });
        await csrf.page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
        await csrf.page.locator('input[name="method"][value="' + method + '"]').check();
        await csrf.page.locator('form input[name="csrfToken"]').first()
          .evaluate((input) => { (input as HTMLInputElement).value = "invalid-w20-csrf"; });
        const denied = csrf.page.waitForResponse((response) =>
          response.request().method() === "POST" && new URL(response.url()).origin === portalUrl &&
          new URL(response.url()).pathname === "/recover");
        await csrf.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
        expect((await denied).status()).toBe(403);
        expect(await database.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(before);
        expect((await csrf.context.cookies(portalUrl)).filter((cookie) => cookie.name.includes("recovery"))).toHaveLength(0);

        const globalBefore = await database.accountRecoveryRequest.count();
        const requestId = await startSelectedRecovery(page, ownerEmail, method);
        await assertBoundCookies(context, portalUrl, requestId, method);
        expect((await context.cookies(hubUrl)).filter((cookie) => cookie.name.includes("recovery"))).toHaveLength(0);
        const preProof = (await page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim();
        const visiblePreProof = (await page.locator("main").innerText()).trim();

        const synthetic = await openRecovery(browser, "portal");
        contexts.push(synthetic.context);
        const syntheticId = await startSelectedRecovery(synthetic.page, "absent-" + randomUUID() + "@e2e.invalid", method);
        await assertBoundCookies(synthetic.context, portalUrl, syntheticId, method);
        expect(syntheticId).not.toBe(requestId);
        expect((await synthetic.page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim()).toBe(preProof);
        expect((await synthetic.page.locator("main").innerText()).trim()).toBe(visiblePreProof);
        expect(await database.accountRecoveryRequest.count()).toBe(globalBefore + 1);
        expect(await database.accountRecoveryRequest.count({ where: { id: syntheticId } })).toBe(0);
        const unbound = await openRecovery(browser, "portal");
        contexts.push(unbound.context);
        const foreignUrl = portalUrl + "/recover?requestId=" + encodeURIComponent(requestId);
        const foreignResponse = await unbound.page.goto(foreignUrl);
        expect(foreignResponse?.status(), "foreign browser must receive the real recovery document, not 403/500").toBe(200);
        await expect(unbound.page).toHaveURL(foreignUrl);
        await expect(unbound.page.getByRole("heading", { level: 1, name: "Recuperar conta" })).toBeVisible();
        await expect(unbound.page.locator('p.form-error[role="alert"]')).toContainText(
          "Este link de recuperação não é mais válido."
        );
        await expect(unbound.page.locator('section[aria-label="Confirmação de identidade"]')).toHaveCount(0);
        await expect(unbound.page.locator('input[name="code"]')).toHaveCount(0);
        await expect(unbound.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);

        // Neither assertion nor verification is fabricated in Node. The
        // actual React click calls both Next Server Actions using WebAuthn.get.
        const actionCalls: string[] = [];
        page.on("response", (response) => {
          if (response.request().method() === "POST" && new URL(response.url()).pathname === "/recover" &&
              response.request().headers()["next-action"]) actionCalls.push(response.url());
        });
        await page.getByRole("button", { name: "Confirmar com passkey" }).click();
        await expect(page.locator('[aria-label="Chave de acesso"]')).toContainText("Confirmada.", { timeout: 25_000 });
        expect(actionCalls.length, "start and finish passkey Server Actions must execute").toBeGreaterThanOrEqual(2);
        const partial = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
        expect(partial.recoveryPasskeyVerifiedAt).not.toBeNull();
        expect(partial.status).toBe("PENDING");
        await expect(page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
        expect((await database.passkeyChallenge.findMany({ where: {
          userId: owner.id, ceremony: "RECOVERY"
        } })).some((challenge) => challenge.consumedAt !== null)).toBe(true);

        if (method === "PASSKEY_EMAIL") {
          const message = await database.emailOutboxMessage.findFirst({
            where: { recipientEmail: ownerEmail, kind: "ACCOUNT_RECOVERY" },
            orderBy: { createdAt: "desc" }, select: { payload: true }
          });
          const code = message ? decryptEmailPayload(message.payload).code : undefined;
          expect(code).toMatch(/^\d{6}$/u);
          const email = page.locator('[aria-label="E-mail cadastrado"]');
          await email.locator('input[name="code"]').fill(code!);
          await email.getByRole("button", { name: "Confirmar", exact: true }).click();
        } else {
          const otp = page.locator('[aria-label="Aplicativo autenticador"]');
          await otp.locator('input[name="code"]').fill(totpAt(totpSecret!));
          await otp.getByRole("button", { name: "Confirmar", exact: true }).click();
        }
        await expect.poll(async () => (await database.accountRecoveryRequest.findUniqueOrThrow({
          where: { id: requestId }, select: { status: true }
        })).status).toBe("APPROVED");

        let completionPage = page;
        if (method === "PASSKEY_TOTP") {
          const mailbox = page.locator('section[aria-label="Verificação do novo e-mail"]');
          await expect(mailbox).toBeVisible();
          await expect(page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
          replacementEmail = randomUUID() + ".replacement@e2e.invalid";
          await mailbox.locator('input[name="newEmail"]').fill(replacementEmail);
          await mailbox.getByRole("button", { name: "Enviar código ao novo e-mail" }).click();
          await expect(mailbox.locator('input[name="code"]')).toBeVisible({ timeout: 20_000 });
          const message = await database.emailOutboxMessage.findFirst({
            where: { recipientEmail: replacementEmail, kind: "RECOVERY_EMAIL_REBIND" },
            orderBy: { createdAt: "desc" }, select: { payload: true }
          });
          const code = message ? decryptEmailPayload(message.payload).code : undefined;
          expect(code).toMatch(/^\d{6}$/u);
          // A hidden password form is not an authorization boundary. Prepare
          // a genuine completion form on another page in the bound browser,
          // then revoke the display-only timestamp BEFORE its Next action.
          // The mailbox page can reload from its own Server Action effect:
          // reloading it here would race that navigation and its React state.
          const requestBeforeDenial = await database.accountRecoveryRequest.findUniqueOrThrow({
            where: { id: requestId },
            select: {
              userId: true, status: true, recoveryRole: true, recoveryProofs: true,
              recoveryAdminReview: true, recoveryPasskeyVerifiedAt: true, recoveryTotpVerifiedAt: true,
              recoveryNewEmail: true, recoveryNewEmailChallengeHash: true,
              recoveryNewEmailExpiresAt: true, recoveryNewEmailVerifiedAt: true,
              requestKeyHash: true, recoveryBrowserHash: true, bootstrapSessionId: true
            }
          });
          expect(requestBeforeDenial.userId).toBe(owner.id);
          expect(requestBeforeDenial.status).toBe("APPROVED");
          expect(requestBeforeDenial.recoveryRole).toBe("USER");
          expect(requestBeforeDenial.recoveryProofs).toEqual(["PASSKEY", "TOTP"]);
          expect(requestBeforeDenial.recoveryAdminReview).toBe(false);
          expect(requestBeforeDenial.recoveryPasskeyVerifiedAt).not.toBeNull();
          expect(requestBeforeDenial.recoveryTotpVerifiedAt).not.toBeNull();
          expect(requestBeforeDenial.recoveryNewEmail).toBe(replacementEmail);
          expect(requestBeforeDenial.recoveryNewEmailChallengeHash).toBeTruthy();
          expect(requestBeforeDenial.recoveryNewEmailExpiresAt?.getTime()).toBeGreaterThan(Date.now());
          expect(requestBeforeDenial.recoveryNewEmailVerifiedAt).toBeNull();
          expect(requestBeforeDenial.bootstrapSessionId).toBeNull();
          const [requestCookieName, browserCookieName, intentCookieName] = productionMode
            ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
            : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
          const cookiesBeforeDenial = await context.cookies(portalUrl);
          const requestCookie = cookiesBeforeDenial.find((cookie) => cookie.name === requestCookieName);
          const browserCookie = cookiesBeforeDenial.find((cookie) => cookie.name === browserCookieName);
          const intentCookie = cookiesBeforeDenial.find((cookie) => cookie.name === intentCookieName);
          expect(requestCookie?.value.length).toBeGreaterThan(0);
          expect(browserCookie?.value.length).toBeGreaterThan(0);
          expect(intentCookie?.value).toBe(requestId + "." + method);
          expect(hashRecoveryRequestKey(requestCookie!.value) === requestBeforeDenial.requestKeyHash,
            "completion must use the exact request capability bound to this request").toBe(true);
          expect(createHash("sha256").update("Virki recovery browser v1:")
            .update(browserCookie!.value).digest("hex") === requestBeforeDenial.recoveryBrowserHash,
            "completion must use the original browser-token binding").toBe(true);
          const userBeforeDenial = await database.user.findUniqueOrThrow({
            where: { id: owner.id },
            select: { email: true, emailNormalized: true, passwordHash: true, secondFactorMethod: true }
          });
          const sessionsBeforeDenial = await database.session.count({
            where: { userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() } }
          });
          expect(sessionsBeforeDenial, "a new recovery owner must have no active session before completion").toBe(0);
          const sessionRowsBeforeDenial = await database.session.count({ where: { userId: owner.id } });
          expect(sessionRowsBeforeDenial).toBe(0);
          const mounted = await database.accountRecoveryRequest.updateMany({
            where: {
              id: requestId, userId: owner.id, status: "APPROVED",
              recoveryNewEmail: replacementEmail, recoveryNewEmailVerifiedAt: null
            },
            data: { recoveryNewEmailVerifiedAt: new Date() }
          });
          expect(mounted.count).toBe(1);
          const prematurePage = await context.newPage();
          try {
            const preparedResponse = await prematurePage.goto(page.url());
            expect(preparedResponse?.status(), "prepared recovery document must return HTTP 200").toBe(200);
            await expect(prematurePage).toHaveURL(portalUrl + "/recover?requestId=" + requestId);
            await expect(prematurePage.getByRole("heading", { level: 1, name: "Recuperar conta" })).toBeVisible();
            await expect(prematurePage.getByLabel("Nova senha", { exact: true })).toBeVisible({ timeout: 20_000 });
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
            expect(revoked.count, "the temporary display-only mailbox proof must always be revoked").toBe(1);
          }
          const unverifiedRequest = await database.accountRecoveryRequest.findUniqueOrThrow({
            where: { id: requestId },
            select: {
              userId: true, status: true, recoveryRole: true, recoveryProofs: true,
              recoveryAdminReview: true, recoveryPasskeyVerifiedAt: true, recoveryTotpVerifiedAt: true,
              recoveryNewEmail: true, recoveryNewEmailChallengeHash: true,
              recoveryNewEmailExpiresAt: true, recoveryNewEmailVerifiedAt: true,
              requestKeyHash: true, recoveryBrowserHash: true, bootstrapSessionId: true
            }
          });
          expect(unverifiedRequest).toEqual(requestBeforeDenial);
          const cookiesAtPost = await context.cookies(portalUrl);
          for (const original of [requestCookie, browserCookie, intentCookie]) {
            expect(cookiesAtPost.find((cookie) => cookie.name === original!.name)?.value,
              "rejected completion must use the original browser-bound cookies").toBe(original!.value);
          }
          const prematurePassword = "premature-" + randomUUID() + "-password";
          await prematurePage.getByLabel("Nova senha", { exact: true }).fill(prematurePassword);
          const prematurePost = prematurePage.waitForResponse((response) =>
            response.request().method() === "POST" && new URL(response.url()).origin === portalUrl &&
            new URL(response.url()).pathname === "/recover" &&
            Boolean(response.request().headers()["next-action"]));
          await prematurePage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
          const rejectedPost = await prematurePost;
          expect(rejectedPost.status(), "a rejected action must return an HTTP response or redirect, never a 403/500")
            .toBeGreaterThanOrEqual(200);
          expect(rejectedPost.status()).toBeLessThan(400);
          expect(rejectedPost.request().postDataBuffer()?.byteLength ?? 0).toBeGreaterThan(0);
          // Next's browser-bound Server Action may omit Origin. Assert the
          // exact same-origin endpoint, and validate Origin/Referer if sent.
          const rejectedRequest = rejectedPost.request();
          expect(new URL(rejectedRequest.url()).origin).toBe(portalUrl);
          expect(new URL(rejectedRequest.url()).pathname).toBe("/recover");
          const { origin, referer } = rejectedRequest.headers();
          if (origin !== undefined) expect(origin).toBe(portalUrl);
          if (referer !== undefined) expect(new URL(referer).origin).toBe(portalUrl);
          await expect(prematurePage).toHaveURL(portalUrl + "/recover?requestId=" + requestId + "&error=1", { timeout: 20_000 });
          expect(await database.user.findUniqueOrThrow({
            where: { id: owner.id },
            select: { email: true, emailNormalized: true, passwordHash: true, secondFactorMethod: true }
          })).toEqual(userBeforeDenial);
          expect(await database.accountRecoveryRequest.findUniqueOrThrow({
            where: { id: requestId },
            select: {
              userId: true, status: true, recoveryRole: true, recoveryProofs: true,
              recoveryAdminReview: true, recoveryPasskeyVerifiedAt: true, recoveryTotpVerifiedAt: true,
              recoveryNewEmail: true, recoveryNewEmailChallengeHash: true,
              recoveryNewEmailExpiresAt: true, recoveryNewEmailVerifiedAt: true,
              requestKeyHash: true, recoveryBrowserHash: true, bootstrapSessionId: true
            }
          })).toEqual(unverifiedRequest);
          expect(await database.session.count({
            where: { userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() } }
          })).toBe(sessionsBeforeDenial);
          expect(await database.session.count({ where: { userId: owner.id } }),
            "a denied completion must not create even a revoked or expired session").toBe(sessionRowsBeforeDenial);
          expect(await verifyPassword(userBeforeDenial.passwordHash ?? "", prematurePassword)).toBe(false);
          // The mailbox Server Action reloads its original React page. A
          // successful denied completion in another tab can race that reload,
          // leaving a stale/missing input without changing the recovery DB.
          // Verify the canonical document and resume in a fresh page that
          // shares the original three bound capability cookies.
          completionPage = await context.newPage();
          const mailboxDocument = await completionPage.goto(portalUrl + "/recover?requestId=" + requestId);
          expect(mailboxDocument?.status(), "new mailbox continuation must be a real HTTP 200 document").toBe(200);
          await expect(completionPage).toHaveURL(portalUrl + "/recover?requestId=" + requestId);
          await expect(completionPage.getByRole("heading", { level: 1, name: "Recuperar conta" })).toBeVisible();
          await assertBoundCookies(context, portalUrl, requestId, method);
          await expect(completionPage.locator('section[aria-label="Verificação do novo e-mail"] input[name="code"]')).toBeVisible();
          const wrongCode = code === "000000" ? "000001" : "000000";
          await completionPage.locator('section[aria-label="Verificação do novo e-mail"] input[name="code"]').fill(wrongCode);
          await completionPage.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
          await expect(completionPage.locator('section[aria-label="Verificação do novo e-mail"] [role="alert"]'))
            .toContainText("Código inválido ou expirado");
          expect((await database.accountRecoveryRequest.findUniqueOrThrow({
            where: { id: requestId }, select: { recoveryNewEmailVerifiedAt: true }
          })).recoveryNewEmailVerifiedAt).toBeNull();
          await completionPage.locator('section[aria-label="Verificação do novo e-mail"] input[name="code"]').fill(code!);
          await completionPage.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
        }
        await expect(completionPage.getByLabel("Nova senha", { exact: true })).toBeVisible({ timeout: 20_000 });

        // A separate cookie jar is not sufficient: App Router can revalidate
        // and unmount an idle completion form after the winning reset. Submit
        // its real hydrated React Server Action BEFORE the winner, hold that
        // browser-generated HTTP POST at Playwright's network boundary, and
        // forward it only AFTER the winner has consumed the request.
        const oldCookies = (await context.cookies(portalUrl))
          .filter((cookie) => cookie.name.includes("recovery"))
          .map((cookie) => ({
            url: portalUrl + "/", name: cookie.name, value: cookie.value,
            httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite, expires: cookie.expires
          }));
        expect(oldCookies, "replay must retain all three original browser-bound recovery cookies").toHaveLength(3);
        const staleContext = await browser.newContext();
        contexts.push(staleContext);
        await staleContext.addCookies(oldCookies);
        const stale = await staleContext.newPage();
        const staleDocument = await stale.goto(completionPage.url());
        expect(staleDocument?.status(), "stale form must come from a real recovery document").toBe(200);
        await expect(stale.getByLabel("Nova senha", { exact: true })).toBeVisible();
        await expect(stale.locator('form input[name="requestId"]')).toHaveValue(requestId);
        const staleCsrf = await stale.locator('form input[name="csrfToken"]').inputValue();
        expect(/^v2\./u.test(staleCsrf), "stale form must have a real recovery CSRF token").toBe(true);
        const rejectedPassword = "replay-" + randomUUID() + "-password";
        await stale.getByLabel("Nova senha", { exact: true }).fill(rejectedPassword);
        let releaseHeldReplay!: () => void;
        const replayRelease = new Promise<void>((resolve) => { releaseHeldReplay = resolve; });
        type HeldPost = { url: string; method: string; body: string; headers: Record<string, string> };
        let observeHeldReplay!: (post: HeldPost) => void;
        const heldReplay = new Promise<HeldPost>((resolve) => {
          observeHeldReplay = resolve;
        });
        let forwardHeldReplay = false;
        let heldPostCount = 0;
        type ForwardedPost = { status: number; redirect?: string; error?: string };
        let recordForwardedPost!: (result: ForwardedPost) => void;
        const forwardedPost = new Promise<ForwardedPost>((resolve) => { recordForwardedPost = resolve; });
        await stale.route("**/recover**", async (route) => {
          const request = route.request();
          if (request.method() !== "POST" || new URL(request.url()).origin !== portalUrl ||
              new URL(request.url()).pathname !== "/recover") {
            await route.continue();
            return;
          }
          heldPostCount += 1;
          if (heldPostCount !== 1) { await route.abort(); return; }
          // The request and all its cookie headers already exist in Chromium;
          // neither the agent nor Node fabricates a new proof or Server Action.
          observeHeldReplay({ url: request.url(), method: request.method(), body: request.postData() ?? "",
            headers: await request.allHeaders() });
          await replayRelease;
          if (!forwardHeldReplay) { await route.abort(); return; }
          try {
            // continue() can leave a previously held App Router navigation
            // without a browser response. Forward the EXACT intercepted,
            // browser-generated Next action through Playwright's route.fetch,
            // then fulfill that same browser request with the live response.
            // No payload, capability cookie or Server Action is fabricated.
            const upstream = await route.fetch({ maxRedirects: 0, timeout: 20_000 });
            await route.fulfill({ response: upstream });
            // Next.js Server Actions express a rejected replay's redirect via
            // x-action-redirect (or Location for a plain HTTP redirect). This
            // is the response from the actual held POST, not a synthetic GET.
            recordForwardedPost({ status: upstream.status(),
              redirect: upstream.headers()["x-action-redirect"]?.split(";", 1)[0] ?? upstream.headers().location });
          } catch (error) {
            recordForwardedPost({ status: 0, error: error instanceof Error ? error.message : "forwarding failed" });
            await route.abort().catch(() => undefined);
          }
        });
        // Do not await a navigation while the real action request is paused.
        const staleClickOutcome = stale.getByRole("button", { name: "Concluir recuperação", exact: true })
          .click({ noWaitAfter: true }).then(() => undefined, (error: unknown) => error);
        let arrivalTimeout: ReturnType<typeof setTimeout> | undefined;
        const winningPassword = "signed-" + randomUUID() + "-password";
        let consumed: Awaited<ReturnType<typeof database.accountRecoveryRequest.findUniqueOrThrow>>;
        let winnerPasswordHash: string | null = null;
        let winnerBootstrapTokenHash = "";
        let sessionRowsBeforeReplay = -1;
        try {
          const post = await Promise.race([
            heldReplay,
            staleClickOutcome.then((error) => {
              if (error) throw error;
              return heldReplay;
            }),
            new Promise<never>((_, reject) => {
              arrivalTimeout = setTimeout(() => reject(new Error(
                "Genuine stale React recovery POST was not intercepted within 15s."
              )), 15_000);
            })
          ]);
          clearTimeout(arrivalTimeout);
          arrivalTimeout = undefined;
          expect(post.method).toBe("POST");
          expect(new URL(post.url).origin, "held action must target the exact issuing Portal origin").toBe(portalUrl);
          expect(new URL(post.url).pathname).toBe("/recover");
          expect(Boolean(post.headers["next-action"]), "the stale POST must come from a hydrated React Server Action").toBe(true);
          expect(post.body.includes(requestId), "the held genuine form must carry this exact recovery request ID").toBe(true);
          expect(post.body.includes(rejectedPassword), "the held form must carry the stale password, not the winner's").toBe(true);
          expect(post.body.includes(staleCsrf), "the held action must carry its real page-issued CSRF token").toBe(true);
          // Chromium/Next may omit Origin even on a legitimate Server Action.
          // Never turn that valid request into a false-red; validate only when
          // present, while always checking the actual request target above.
          if (post.headers.origin) expect(post.headers.origin).toBe(portalUrl);
          if (post.headers.referer) {
            // Referrer-Policy may legitimately truncate this to the origin.
            expect(new URL(post.headers.referer).origin).toBe(portalUrl);
          }
          for (const original of oldCookies) {
            expect((post.headers.cookie ?? "").includes(original.name + "=" + original.value),
              "the held HTTP POST must carry all three original browser-bound recovery cookies").toBe(true);
          }
          const beforeWinner = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
          expect(beforeWinner.status, "the stale browser must dispatch before the winning consume").toBe("APPROVED");
          await completionPage.getByLabel("Nova senha", { exact: true }).fill(winningPassword);
          await completionPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
          await expect(completionPage).toHaveURL(portalUrl + "/account/security?recovered=password", { timeout: 25_000 });
          const recovered = await database.user.findUniqueOrThrow({ where: { id: owner.id } });
          expect(await verifyPassword(recovered.passwordHash ?? "", winningPassword)).toBe(true);
          expect(recovered.emailNormalized).toBe(replacementEmail ?? ownerEmail);
          winnerPasswordHash = recovered.passwordHash;
          consumed = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
          expect(consumed.status).toBe("CONSUMED");
          expect(consumed.bootstrapSessionId, "the consumed request must identify its unique bootstrap session").toBeTruthy();
          expect(await database.passkeyCredential.count({ where: { userId: owner.id, revokedAt: null } })).toBe(0);
          if (totpSecret) expect((await database.totpFactor.findUniqueOrThrow({ where: { userId: owner.id } })).status).toBe("REVOKED");
          const session = (await context.cookies(portalUrl)).find((cookie) =>
            cookie.name === getSessionCookieName({ NODE_ENV: "development" }));
          expect(session).toBeDefined();
          expect(session!.domain).toBe("portal.localhost");
          expect(session!.httpOnly).toBe(true);
          expect(session!.secure).toBe(productionMode);
          const bootstrap = await database.session.findUniqueOrThrow({ where: { id: consumed.bootstrapSessionId! } });
          expect(bootstrap.userId, "bootstrap session must belong to the recovered owner").toBe(owner.id);
          expect(bootstrap.revokedAt, "bootstrap session must not be revoked").toBeNull();
          expect(bootstrap.expiresAt.getTime()).toBeGreaterThan(Date.now());
          expect(bootstrap.tokenHash, "browser session cookie must be the actual bootstrap session token")
            .toBe(hashSessionToken(session!.value));
          winnerBootstrapTokenHash = bootstrap.tokenHash;
          const protectedUrl = portalUrl + "/account/security";
          const protectedDocument = await completionPage.goto(protectedUrl);
          expect(protectedDocument?.status(), "fresh protected document GET must return HTTP 200").toBe(200);
          await expect(completionPage).toHaveURL(protectedUrl);
          await expect(completionPage.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
          await expect(completionPage.locator("header.page-header")).toContainText(ownerEmail);
          expect((await context.cookies(portalUrl)).filter((cookie) => cookie.name.includes("recovery"))).toHaveLength(0);
          const replayCookies = await staleContext.cookies(portalUrl);
          for (const original of oldCookies) {
            expect(replayCookies.find((cookie) => cookie.name === original.name)?.value).toBe(original.value);
          }
          sessionRowsBeforeReplay = await database.session.count({ where: { userId: owner.id } });
          expect(heldPostCount, "only one genuine stale completion POST may be dispatched").toBe(1);
          forwardHeldReplay = true;
        } finally {
          if (arrivalTimeout) clearTimeout(arrivalTimeout);
          // A failed winner/precondition aborts the pending POST instead of
          // accidentally authorizing the stale password on this test owner;
          // even a missing POST fails within 15s, not the full E2E timeout.
          releaseHeldReplay();
        }
        const actualForward = await forwardedPost;
        expect(actualForward.error, "the original Next POST must reach the server after consumption").toBeUndefined();
        expect(actualForward.status, "server must handle the browser-originated stale completion").toBeGreaterThanOrEqual(200);
        expect(actualForward.status, "a 403/500 response cannot prove one-time replay rejection").toBeLessThan(400);
        // Some Chromium/Next combinations do not dispatch a Playwright page
        // 'response' event for a previously paused fetch after route.fulfill,
        // despite route.fetch proving that the original Next POST reached the
        // server. Do not mistake this instrumentation gap for an application
        // denial. Require its *actual* redirect header, never status alone.
        expect(actualForward.redirect, "replay Server Action must return the exact handled error redirect").toBeTruthy();
        const rejectedRedirect = new URL(actualForward.redirect!, portalUrl);
        const expectedRejectedUrl = portalUrl + "/recover?requestId=" + requestId + "&error=1";
        expect(rejectedRedirect.href).toBe(expectedRejectedUrl);
        const staleClickError = await staleClickOutcome;
        if (staleClickError) throw staleClickError;
        // The rejected target must itself render as a canonical HTTP 200
        // document with no revived proof or password input; a 403/500 document
        // or a bare URL change must never satisfy the replay test.
        const rejectedDocument = await stale.goto(expectedRejectedUrl);
        expect(rejectedDocument?.status(), "denied replay target must render HTTP 200").toBe(200);
        await expect(stale).toHaveURL(expectedRejectedUrl);
        await expect(stale.getByRole("heading", { level: 1, name: "Recuperar conta" })).toBeVisible();
        await expect(stale.locator("p.form-error[role='alert']")).toBeVisible();
        await expect(stale.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
        const unchanged = await database.user.findUniqueOrThrow({ where: { id: owner.id } });
        expect(await verifyPassword(unchanged.passwordHash ?? "", winningPassword)).toBe(true);
        expect(await verifyPassword(unchanged.passwordHash ?? "", rejectedPassword)).toBe(false);
        expect(unchanged.passwordHash, "replayed completion must not even rehash the winning password").toBe(winnerPasswordHash);
        expect(unchanged.emailNormalized).toBe(replacementEmail ?? ownerEmail);
        const replayedRequest = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
        expect(replayedRequest.status).toBe("CONSUMED");
        expect(replayedRequest.bootstrapSessionId).toBe(consumed.bootstrapSessionId);
        expect(await database.session.count({ where: {
          userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() }
        } })).toBe(1);
        expect(await database.session.count({ where: { userId: owner.id } }),
          "denied replay must not create even a revoked or expired session").toBe(sessionRowsBeforeReplay);
        const bootstrapAfterReplay = await database.session.findUniqueOrThrow({ where: { id: consumed.bootstrapSessionId! } });
        expect(bootstrapAfterReplay.tokenHash).toBe(winnerBootstrapTokenHash);
        expect(bootstrapAfterReplay.revokedAt).toBeNull();
      } finally {
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
      }
    } finally {
      const closed = await Promise.allSettled(contexts.map((context) => context.close()));
      try {
        if (ownerId) {
          // Every deletion is limited to this randomized test fixture.
          await database.session.deleteMany({ where: { userId: ownerId } });
          await database.accountRecoveryRequest.deleteMany({ where: { userId: ownerId } });
          await database.passkeyChallenge.deleteMany({ where: { userId: ownerId } });
          await database.passkeyCredential.deleteMany({ where: { userId: ownerId } });
          await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: { in: [
            ownerEmail, ...(replacementEmail ? [replacementEmail] : [])
          ] } } });
          await database.totpFactor.deleteMany({ where: { userId: ownerId } });
          // Leave only the audit-bound owner for the disposable E2E database's
          // teardown. Runtime tests may not DELETE real AuditLog references.
        }
      } finally {
        await database.$disconnect();
      }
      expect(closed.every((result) => result.status === "fulfilled"),
        "every isolated browser context must close").toBe(true);
    }
  });
}

test("USER PASSKEY_ADMIN: signed Portal passkey, independent Hub approval, replacement inbox and fresh normal login", async ({ browser }) => {
  test.skip(!mandatoryPasskeyRecovery && !physicalPasskeyEnabled,
    "Physical USER PASSKEY_ADMIN recovery requires VIRKI_E2E_PASSKEYS=true.");
  test.setTimeout(180_000);
  if (!physicalPasskeyEnabled || productionMode) {
    throw new Error("USER PASSKEY_ADMIN requires the explicit non-production Portal RP WebAuthn gate.");
  }
  const { database, fixture } = await requireFixture();
  const reviewer = fixture.recoveryReviewer as Actor & { password?: string; administrativePassword?: string };
  const contexts: BrowserContext[] = [];
  const newContext = async () => {
    const context = await browser.newContext();
    contexts.push(context);
    return context;
  };
  const ownerEmail = `user-passkey-admin-${randomUUID()}@e2e.invalid`;
  const replacementEmail = `user-passkey-admin-new-${randomUUID()}@e2e.invalid`;
  const oldPassword = randomBytes(32).toString("base64url");
  const newPassword = randomBytes(32).toString("base64url");
  const replayPassword = randomBytes(32).toString("base64url");
  const sessionCookieName = getSessionCookieName({ NODE_ENV: "development" });
  let cdp: Awaited<ReturnType<BrowserContext["newCDPSession"]>> | undefined;
  let authenticatorId: string | undefined;

  // Both actors log in through their real password + email-MFA browser flow;
  // a database-created reviewer session would not prove independent login.
  async function signInWithEmailMfa(page: Page, origin: string, path: string, email: string, password: string) {
    const loginDocument = await page.goto(origin + path);
    expect(loginDocument?.status()).toBe(200);
    await expect(page).toHaveURL(origin + "/login?returnTo=" + encodeURIComponent(path));
    await page.getByLabel("E-mail", { exact: true }).fill(email);
    await page.getByLabel("Senha", { exact: true }).fill(password);
    const loginPost = page.waitForResponse((response) => response.request().method() === "POST" &&
      new URL(response.url()).origin === origin && new URL(response.url()).pathname === "/api/login");
    await page.getByRole("button", { name: "Entrar", exact: true }).click();
    expect((await loginPost).status()).toBe(303);
    await page.waitForURL((url) => url.pathname === "/login/verify" &&
      url.searchParams.get("factor") === "email" && Boolean(url.searchParams.get("ceremony")));
    const ceremony = new URL(page.url()).searchParams.get("ceremony")!;
    const emailProof = await database.emailOutboxMessage.findFirst({ where: {
      recipientEmail: email, idempotencyKey: `security-ceremony:${ceremony}`,
      kind: { in: ["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"] }
    }, select: { payload: true } });
    expect(emailProof, "real login must issue an email MFA challenge").not.toBeNull();
    const code = decryptEmailPayload(emailProof!.payload).code;
    expect(code).toMatch(/^\d{6}$/u);
    await page.getByLabel("Código", { exact: true }).fill(code!);
    await page.getByRole("button", { name: "Continuar", exact: true }).click();
    await expect(page).toHaveURL(origin + path);
  }

  try {
    expect(typeof reviewer.password).toBe("string");
    expect(typeof reviewer.administrativePassword).toBe("string");
    expect(await database.user.findUniqueOrThrow({ where: { id: reviewer.id }, select: {
      role: true, isActive: true, accountStatus: true
    } })).toMatchObject({ role: "ADMIN", isActive: true, accountStatus: "ACTIVE" });
    const owner = await database.user.create({ data: {
      email: ownerEmail, emailNormalized: ownerEmail, displayName: "Owned USER Portal PASSKEY_ADMIN E2E",
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
      passwordHash: await hashPassword(oldPassword), secondFactorMethod: "EMAIL"
    }, select: { id: true, email: true } });
    expect(owner.id).not.toBe(reviewer.id);
    const oldToken = randomBytes(32).toString("base64url");
    const oldSession = await database.session.create({ data: {
      userId: owner.id, tokenHash: hashSessionToken(oldToken),
      authenticationMethods: ["pwd", "otp", "mfa"], expiresAt: new Date(Date.now() + 600_000)
    }, select: { id: true } });
    const oldContext = await newContext();
    await oldContext.addCookies([{ name: sessionCookieName, value: oldToken, url: portalUrl,
      secure: true, httpOnly: true, sameSite: "Lax" }]);
    const oldPage = await oldContext.newPage();
    expect((await oldPage.goto(portalUrl + "/account/security"))?.status()).toBe(200);
    await expect(oldPage.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();

    const recoveryContext = await newContext();
    const recoveryPage = await recoveryContext.newPage();
    await recoveryPage.goto(portalUrl + "/recover");
    expect(await recoveryPage.evaluate(() => window.isSecureContext)).toBe(true);
    cdp = await recoveryContext.newCDPSession(recoveryPage);
    await cdp.send("WebAuthn.enable");
    let signedAssertions = 0;
    cdp.on("WebAuthn.credentialAsserted", () => { signedAssertions += 1; });
    ({ authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true
    } }));
    await enrollVirtualRecoveryCredential(recoveryPage, database, owner);
    // PASSKEY_ADMIN has no preceding EMAIL/TOTP owner proof, so the server
    // correctly omits allowCredentials. A discoverable resident credential is
    // mandatory; do not weaken the anonymous WebAuthn challenge policy.
    const registered = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    expect(registered.credentials, "the real CDP authenticator must contain exactly one credential").toHaveLength(1);
    expect(registered.credentials[0]?.isResidentCredential,
      "PASSKEY_ADMIN must use a resident/discoverable Portal-RP credential").toBe(true);
    const credential = await database.passkeyCredential.findFirstOrThrow({ where: {
      userId: owner.id, revokedAt: null
    } });
    expect(credential.rpID, "the USER proof must be enrolled for Portal, never Hub").toBe("portal.localhost");
    expect(await database.administrativeCredential.count({ where: { userId: owner.id } })).toBe(0);
    const requestId = await startSelectedRecovery(recoveryPage, ownerEmail, "PASSKEY_ADMIN");
    await assertBoundCookies(recoveryContext, portalUrl, requestId, "PASSKEY_ADMIN");
    expect((await recoveryContext.cookies(hubUrl)).some((cookie) => cookie.name.includes("recovery"))).toBe(false);
    expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId }, select: {
      userId: true, recoveryRole: true, recoveryProofs: true, recoveryAdminReview: true,
      status: true, recoveryPasskeyVerifiedAt: true, reviewedByUserId: true
    } })).toMatchObject({
      userId: owner.id, recoveryRole: "USER", recoveryProofs: ["PASSKEY"],
      recoveryAdminReview: true, status: "PENDING", recoveryPasskeyVerifiedAt: null,
      reviewedByUserId: null
    });

    const wrongContext = await newContext();
    const wrongPage = await wrongContext.newPage();
    const stolenDocument = await wrongPage.goto(`${portalUrl}/recover?requestId=${requestId}`);
    expect(stolenDocument?.status()).toBe(200);
    await expect(wrongPage.locator('p.form-error[role="alert"]')).toContainText("Este link de recuperação não é mais válido");
    await expect(wrongPage.locator('[aria-label="Chave de acesso"] button')).toHaveCount(0);
    await expect(wrongPage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);

    const reviewerContext = await newContext();
    const reviewerPage = await reviewerContext.newPage();
    await addCloudflareAccessHeader(reviewerPage);
    await signInWithEmailMfa(reviewerPage, hubUrl, "/admin/security", reviewer.email, reviewer.password!);
    await expect(reviewerPage.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
    await expect(reviewerPage.locator("article.list-row").filter({ hasText: ownerEmail }),
      "an unproven passkey must not enter the reviewer queue").toHaveCount(0);

    const passkeyPosts: number[] = [];
    let dispatchedPasskeyPosts = 0;
    recoveryPage.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).origin === portalUrl &&
          new URL(request.url()).pathname === "/recover" && request.headers()["next-action"]) {
        dispatchedPasskeyPosts += 1;
      }
    });
    recoveryPage.on("response", (response) => {
      if (response.request().method() === "POST" && new URL(response.url()).origin === portalUrl &&
          new URL(response.url()).pathname === "/recover" && response.request().headers()["next-action"]) {
        passkeyPosts.push(response.status());
      }
    });
    const passkeyStage = recoveryPage.locator('[aria-label="Chave de acesso"]');
    const passkeyButton = passkeyStage.getByRole("button", { name: "Confirmar com passkey" });
    // SSR must not expose a clickable button before the React WebAuthn handler
    // hydrates. The client enables it only when the handler is installed.
    await expect(passkeyButton).toBeEnabled();
    await passkeyButton.click();
    try {
      await expect(passkeyStage).toContainText("Confirmada.", { timeout: 25_000 });
    } catch (error) {
      const challenges = await database.passkeyChallenge.findMany({
        where: { userId: owner.id, ceremony: "RECOVERY" },
        select: { consumedAt: true }
      });
      const proof = await database.accountRecoveryRequest.findUniqueOrThrow({
        where: { id: requestId }, select: { recoveryPasskeyVerifiedAt: true }
      });
      // All observations are categorical/count-only. Never log credential IDs,
      // challenges, assertions, recovery cookies, CSRF values or OTPs.
      const diagnostic = {
        nextPostsDispatched: dispatchedPasskeyPosts,
        nextPostStatusClasses: passkeyPosts.map((status) => Math.floor(status / 100)),
        signedAssertions, storedChallenges: challenges.length,
        consumedChallenges: challenges.filter((challenge) => challenge.consumedAt !== null).length,
        proofPersisted: proof.recoveryPasskeyVerifiedAt !== null,
        uiErrorVisible: await passkeyStage.getByRole("alert").isVisible().catch(() => false)
      };
      throw new Error(`Portal PASSKEY_ADMIN signed proof did not complete: ${JSON.stringify(diagnostic)}`, { cause: error });
    }
    expect(signedAssertions, "the real Chromium virtual authenticator must sign an assertion").toBeGreaterThan(0);
    expect(dispatchedPasskeyPosts, "browser must dispatch both Next WebAuthn actions").toBeGreaterThanOrEqual(2);
    expect(passkeyPosts.length, "browser must complete both Next WebAuthn actions").toBeGreaterThanOrEqual(2);
    expect((await database.passkeyChallenge.findMany({ where: {
      userId: owner.id, ceremony: "RECOVERY"
    } })).some((challenge) => challenge.consumedAt !== null)).toBe(true);
    expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId }, select: {
      status: true, recoveryPasskeyVerifiedAt: true, reviewedByUserId: true
    } })).toMatchObject({ status: "PENDING", reviewedByUserId: null,
      recoveryPasskeyVerifiedAt: expect.any(Date) });
    expect(await database.emailOutboxMessage.count({ where: {
      recipientEmail: ownerEmail, kind: "ACCOUNT_RECOVERY"
    } })).toBe(0);

    await reviewerPage.reload();
    const reviewRow = reviewerPage.locator("article.list-row").filter({ hasText: ownerEmail });
    await expect(reviewRow).toBeVisible();
    await expect(reviewRow.locator('[data-recovery-review-details="true"]'))
      .toContainText("Passkey + aprovação administrativa");
    await reviewRow.getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?error=recovery#admin-content`);
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId }, select: { status: true, reviewedByUserId: true }
    }))).toEqual({ status: "PENDING", reviewedByUserId: null });

    const elevation = reviewerPage.locator("section.surface").filter({
      has: reviewerPage.getByRole("heading", { name: "Elevação temporária", exact: true })
    });
    const elevationForm = elevation.locator("form").first();
    await elevationForm.locator('select[name="scope"]').selectOption("ACCOUNT_STATE_CHANGE");
    await elevationForm.getByLabel("Senha normal atual", { exact: true }).fill(reviewer.password!);
    await elevationForm.getByLabel("Senha administrativa", { exact: true }).fill(reviewer.administrativePassword!);
    await elevationForm.getByRole("button", { name: "Solicitar elevação", exact: true }).click();
    const verify = elevation.locator("form").nth(1);
    await expect(verify.getByLabel("Código", { exact: true })).toBeVisible();
    const elevationKey = await verify.locator('input[name="requestKey"]').inputValue();
    const elevationMessage = await database.emailOutboxMessage.findFirst({ where: {
      recipientEmail: reviewer.email, kind: "ADMIN_EMAIL_VERIFICATION",
      idempotencyKey: `admin-elevation:${elevationKey}`
    }, select: { payload: true } });
    expect(elevationMessage, "separate Hub reviewer must complete a real scoped OTP elevation").not.toBeNull();
    const elevationCode = decryptEmailPayload(elevationMessage!.payload).code;
    expect(elevationCode).toMatch(/^\d{6}$/u);
    await verify.getByLabel("Código", { exact: true }).fill(elevationCode!);
    await verify.getByRole("button", { name: "Ativar elevação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=elevation#admin-content`);
    await reviewerPage.locator("article.list-row").filter({ hasText: ownerEmail })
      .getByRole("button", { name: "Aprovar recuperação", exact: true }).click();
    await expect(reviewerPage).toHaveURL(`${hubUrl}/admin/security?status=recovery#admin-content`);
    expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId }, select: {
      status: true, reviewedByUserId: true, recoveryNewEmailVerifiedAt: true
    } })).toEqual({ status: "APPROVED", reviewedByUserId: reviewer.id, recoveryNewEmailVerifiedAt: null });

    await recoveryPage.reload();
    const mailbox = recoveryPage.locator('section[aria-label="Verificação do novo e-mail"]');
    await expect(mailbox.getByLabel("Novo endereço de e-mail", { exact: true })).toBeVisible();
    await expect(recoveryPage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    await mailbox.getByLabel("Novo endereço de e-mail", { exact: true }).fill(replacementEmail);
    await mailbox.getByRole("button", { name: "Enviar código ao novo e-mail", exact: true }).click();
    await expect(mailbox.getByLabel("Código recebido no novo e-mail", { exact: true })).toBeVisible();
    const replacementMessage = await database.emailOutboxMessage.findFirst({ where: {
      recipientEmail: replacementEmail, kind: "RECOVERY_EMAIL_REBIND"
    }, orderBy: { createdAt: "desc" }, select: { payload: true } });
    expect(replacementMessage, "only the new inbox receives a recovery OTP").not.toBeNull();
    const replacementCode = decryptEmailPayload(replacementMessage!.payload).code;
    expect(replacementCode).toMatch(/^\d{6}$/u);
    await mailbox.getByLabel("Código recebido no novo e-mail", { exact: true })
      .fill(replacementCode === "000000" ? "000001" : "000000");
    await mailbox.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
    await expect(mailbox.getByRole("alert")).toContainText("Código inválido ou expirado");
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId }, select: { recoveryNewEmailVerifiedAt: true }
    })).recoveryNewEmailVerifiedAt).toBeNull();
    await mailbox.getByLabel("Código recebido no novo e-mail", { exact: true }).fill(replacementCode!);
    await mailbox.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
    await expect(recoveryPage.getByLabel("Nova senha", { exact: true })).toBeVisible();
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId }, select: { recoveryNewEmailVerifiedAt: true }
    })).recoveryNewEmailVerifiedAt).not.toBeNull();

    // Dispatch an authentic Next completion POST before the winner consumes the
    // request. Holding it at the network boundary avoids a stale unmounted form.
    const priorCookies = (await recoveryContext.cookies(portalUrl))
      .filter((cookie) => cookie.name.includes("recovery"))
      .map((cookie) => ({ name: cookie.name, value: cookie.value, url: portalUrl + "/",
        secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite, expires: cookie.expires }));
    expect(priorCookies).toHaveLength(3);
    expect(priorCookies.map((cookie) => cookie.name).sort()).toEqual(
      ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"].sort());
    const beforeWinner = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
    expect(beforeWinner.status).toBe("APPROVED");
    expect(beforeWinner.bootstrapSessionId).toBeNull();
    expect(beforeWinner.requestKeyHash).toBe(hashRecoveryRequestKey(
      priorCookies.find((cookie) => cookie.name === "virki_recovery_v2")!.value));
    expect(beforeWinner.recoveryBrowserHash).toBe(createHash("sha256")
      .update("Virki recovery browser v1:")
      .update(priorCookies.find((cookie) => cookie.name === "virki_recovery_browser")!.value).digest("hex"));
    expect(priorCookies.find((cookie) => cookie.name === "virki_recovery_intent")?.value)
      .toBe(requestId + ".PASSKEY_ADMIN");
    const staleContext = await newContext();
    await staleContext.addCookies(priorCookies);
    const stalePage = await staleContext.newPage();
    expect((await stalePage.goto(recoveryPage.url()))?.status()).toBe(200);
    await expect(stalePage.getByLabel("Nova senha", { exact: true })).toBeVisible();
    await expect(stalePage.locator('form input[name="requestId"]')).toHaveValue(requestId);
    const staleCsrf = await stalePage.locator('form input[name="csrfToken"]').inputValue();
    expect(staleCsrf).toMatch(/^v2\./u);
    const consumedAuditWhere = {
      eventType: "ACCOUNT_RECOVERY_CONSUMED", result: "SUCCESS", resource: "identity.recovery",
      metadata: { path: ["requestRef"], equals: hashAuditIdentifier(requestId) }
    };
    await stalePage.getByLabel("Nova senha", { exact: true }).fill(replayPassword);
    let releaseReplay!: () => void;
    const replayGate = new Promise<void>((resolve) => { releaseReplay = resolve; });
    type HeldReplay = { url: string; method: string; body: string; headers: Record<string, string> };
    let receiveReplay!: (post: HeldReplay) => void;
    const heldReplay = new Promise<HeldReplay>((resolve) => { receiveReplay = resolve; });
    type ForwardResult = { status: number; redirect?: string; error?: string };
    let resolveForward!: (result: ForwardResult) => void;
    const forwardedReplay = new Promise<ForwardResult>((resolve) => { resolveForward = resolve; });
    let allowReplayForward = false;
    let stalePostCount = 0;
    await stalePage.route("**/recover**", async (route) => {
      const request = route.request();
      if (request.method() !== "POST" || new URL(request.url()).origin !== portalUrl ||
          new URL(request.url()).pathname !== "/recover") {
        await route.continue();
        return;
      }
      stalePostCount += 1;
      if (stalePostCount !== 1) { await route.abort(); return; }
      receiveReplay({ url: request.url(), method: request.method(),
        body: request.postData() ?? "", headers: await request.allHeaders() });
      await replayGate;
      if (!allowReplayForward) { await route.abort(); return; }
      try {
        const upstream = await route.fetch({ maxRedirects: 0, timeout: 20_000 });
        await route.fulfill({ response: upstream });
        resolveForward({ status: upstream.status(),
          redirect: upstream.headers()["x-action-redirect"]?.split(";", 1)[0] ?? upstream.headers().location });
      } catch (error) {
        resolveForward({ status: 0, error: error instanceof Error ? error.message : "forwarding failed" });
        await route.abort().catch(() => undefined);
      }
    });
    const staleClick = stalePage.getByRole("button", { name: "Concluir recuperação", exact: true })
      .click({ noWaitAfter: true }).then(() => undefined, (error: unknown) => error);
    let arrivalTimer: ReturnType<typeof setTimeout> | undefined;
    let changed!: Awaited<ReturnType<typeof database.user.findUniqueOrThrow>>;
    let consumed!: Awaited<ReturnType<typeof database.accountRecoveryRequest.findUniqueOrThrow>>;
    let sessionsAtWinner!: Awaited<ReturnType<typeof database.session.findMany>>;
    let successAuditsAtWinner = -1;
    try {
      const post = await Promise.race([
        heldReplay,
        staleClick.then((error) => { if (error) throw error; return heldReplay; }),
        new Promise<never>((_, reject) => {
          arrivalTimer = setTimeout(() => reject(new Error(
            "Genuine Next recovery POST was not intercepted before consume.")), 15_000);
        })
      ]);
      expect(post.method).toBe("POST");
      expect(new URL(post.url).origin).toBe(portalUrl);
      expect(new URL(post.url).pathname).toBe("/recover");
      expect(post.headers["next-action"], "replay must come from a real Next Server Action").toBeTruthy();
      expect(post.body).toContain(requestId);
      expect(post.body).toContain(staleCsrf);
      expect(post.body).toContain(replayPassword);
      expect(post.body).not.toContain(newPassword);
      if (post.headers.origin) expect(post.headers.origin).toBe(portalUrl);
      if (post.headers.referer) expect(new URL(post.headers.referer).origin).toBe(portalUrl);
      for (const cookie of priorCookies) {
        expect((post.headers.cookie ?? "").split("; ").includes(cookie.name + "=" + cookie.value),
          "the held POST must carry each exact original recovery capability").toBe(true);
        expect((await staleContext.cookies(portalUrl)).find((item) => item.name === cookie.name)?.value)
          .toBe(cookie.value);
      }
      expect((await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).status)
        .toBe("APPROVED");
      expect(stalePostCount).toBe(1);
    await recoveryPage.getByLabel("Nova senha", { exact: true }).fill(newPassword);
    await recoveryPage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(recoveryPage).toHaveURL(`${portalUrl}/account/security?recovered=password`, { timeout: 25_000 });
    changed = await database.user.findUniqueOrThrow({ where: { id: owner.id } });
    expect(changed.email).toBe(replacementEmail);
    expect(changed.emailNormalized).toBe(replacementEmail);
    expect(await verifyPassword(changed.passwordHash ?? "", newPassword)).toBe(true);
    expect(await verifyPassword(changed.passwordHash ?? "", oldPassword)).toBe(false);
    expect(changed.secondFactorMethod).toBe("EMAIL");
    expect((await database.passkeyCredential.findUniqueOrThrow({ where: { id: credential.id } })).revokedAt).not.toBeNull();
    consumed = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
    expect(consumed.status).toBe("CONSUMED");
    expect(consumed.bootstrapSessionId).toBeTruthy();
    expect(consumed.reviewedByUserId).toBe(reviewer.id);
    expect((await database.session.findUniqueOrThrow({ where: { id: oldSession.id } })).revokedAt).not.toBeNull();
    const bootstrapCookie = (await recoveryContext.cookies(portalUrl))
      .find((cookie) => cookie.name === sessionCookieName && Boolean(cookie.value));
    expect(bootstrapCookie).toBeDefined();
    const bootstrap = await database.session.findUniqueOrThrow({ where: { id: consumed.bootstrapSessionId! } });
    expect(bootstrap.tokenHash).toBe(hashSessionToken(bootstrapCookie!.value));
    expect(bootstrap.revokedAt).toBeNull();
    await oldPage.goto(portalUrl + "/account/security");
    await expect(oldPage).toHaveURL(portalUrl + "/login");
    sessionsAtWinner = await database.session.findMany({ where: { userId: owner.id }, orderBy: { id: "asc" } });
    successAuditsAtWinner = await database.auditLog.count({ where: consumedAuditWhere });
    expect(successAuditsAtWinner, "the winning request must emit exactly one scoped successful recovery audit").toBe(1);
    expect(stalePostCount).toBe(1);
    allowReplayForward = true;
    } finally {
      if (arrivalTimer) clearTimeout(arrivalTimer);
      releaseReplay();
    }

    const forwarded = await forwardedReplay;
    expect(forwarded.error, "the held original browser POST must reach the server").toBeUndefined();
    expect(forwarded.status, "replay must return a handled Next Server Action").toBeGreaterThanOrEqual(200);
    expect(forwarded.status, "HTTP 403/500 cannot prove replay rejection").toBeLessThan(400);
    const rejectedUrl = portalUrl + "/recover?requestId=" + requestId + "&error=1";
    expect(forwarded.redirect, "actual rejected Server Action must redirect to the original request").toBeTruthy();
    expect(new URL(forwarded.redirect!, portalUrl).href).toBe(rejectedUrl);
    const clickError = await staleClick;
    if (clickError) throw clickError;
    const rejectedDocument = await stalePage.goto(rejectedUrl);
    expect(rejectedDocument?.status()).toBe(200);
    await expect(stalePage).toHaveURL(rejectedUrl);
    await expect(stalePage.locator('p.form-error[role="alert"]')).toBeVisible();
    await expect(stalePage.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const replayed = await database.user.findUniqueOrThrow({ where: { id: owner.id } });
    expect(replayed, "replay must not change any user fields").toEqual(changed);
    expect(await verifyPassword(replayed.passwordHash ?? "", replayPassword)).toBe(false);
    expect(await database.session.findMany({ where: { userId: owner.id }, orderBy: { id: "asc" } }),
      "replay must not create or modify any session").toEqual(sessionsAtWinner);
    expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } }),
      "replay must preserve consumed state and original bootstrap binding").toEqual(consumed);
    expect(await database.auditLog.count({ where: consumedAuditWhere }),
      "replay must not mint another successful recovery audit for this request").toBe(successAuditsAtWinner);

    const freshContext = await newContext();
    const freshPage = await freshContext.newPage();
    await signInWithEmailMfa(freshPage, portalUrl, "/account/security", replacementEmail, newPassword);
    await expect(freshPage.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
    const freshCookie = (await freshContext.cookies(portalUrl))
      .find((cookie) => cookie.name === sessionCookieName && Boolean(cookie.value));
    expect(freshCookie).toBeDefined();
    const freshSession = await database.session.findFirstOrThrow({
      where: { tokenHash: hashSessionToken(freshCookie!.value) },
      select: { id: true, userId: true, revokedAt: true }
    });
    expect(freshSession).toMatchObject({ userId: owner.id, revokedAt: null });
    expect(freshSession.id).not.toBe(consumed.bootstrapSessionId);
  } finally {
    if (cdp && authenticatorId) await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => undefined);
    await cdp?.detach().catch(() => undefined);
    const closed = await Promise.allSettled(contexts.map((context) => context.close()));
    // Recovery and elevation write immutable audit references to the owned USER;
    // the disposable runner owns database teardown, so do not delete those rows.
    await database.$disconnect();
    expect(closed.every((result) => result.status === "fulfilled")).toBe(true);
  }
});

test("USER TOTP+EMAIL: same-browser restart retains the live partially proven capability only", async ({ browser }) => {
  test.setTimeout(120_000);
  const { database } = await requireFixture();
  const contexts: BrowserContext[] = [];
  const ownerEmail = `${randomUUID()}.resume@e2e.invalid`;
  let ownerId: string | undefined;
  try {
    const secret = createTotpSecret();
    const owner = await database.user.create({ data: {
      email: ownerEmail, emailNormalized: ownerEmail, displayName: "Owned resume E2E fixture",
      passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
      secondFactorMethod: "TOTP",
      totpFactor: { create: {
        secretCiphertext: encryptTotpSecret(secret), keyVersion: 1, status: "ACTIVE", confirmedAt: new Date()
      } }
    }, select: { id: true } });
    ownerId = owner.id;
    const real = await openRecovery(browser, "portal");
    contexts.push(real.context);
    const originalId = await startSelectedTotpEmail(real.page, ownerEmail);
    const names = productionMode
      ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
      : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
    const originalCookies = (await real.context.cookies(portalUrl)).filter(cookie => names.includes(cookie.name));
    expect(originalCookies).toHaveLength(3);
    // Deterministic same-browser two-tab race with no application test hook:
    // finish the second POST on the wire but hold its HTTP response before
    // the browser can apply Set-Cookie. Confirm TOTP in the first tab while
    // the later restart response is withheld, then release it out of order.
    const competingTab = await real.context.newPage();
    await competingTab.goto(portalUrl + "/recover");
    await competingTab.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
    await competingTab.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    let restartFetched = false;
    let releaseRestart = () => {};
    const heldRestart = new Promise<void>(resolve => { releaseRestart = resolve; });
    await competingTab.route(/\/recover(?:\?.*)?$/u, async route => {
      if (route.request().method() !== "POST") return route.continue();
      const response = await route.fetch({ maxRedirects: 0 });
      restartFetched = true;
      await heldRestart;
      await route.fulfill({ response });
    });
    const restartClick = competingTab.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    const totpStage = real.page.locator('[aria-label="Aplicativo autenticador"]');
    try {
      await expect.poll(() => restartFetched, {
        timeout: 20_000, message: "second POST must finish server-side before TOTP proof"
      }).toBe(true);
      // Playwright's route.fetch() uses this context's cookie jar and applies
      // the intercepted response's Set-Cookie early. Undo that harness effect
      // so the browser retains the original cookies UNTIL route.fulfill().
      // This restores the real-world wire ordering rather than masking the bug.
      await real.context.addCookies(originalCookies);
      for (const original of originalCookies) {
        expect((await real.context.cookies(portalUrl)).find(cookie => cookie.name === original.name)?.value)
          .toBe(original.value);
      }
      await totpStage.locator('input[name="code"]').fill(totpAt(secret));
      await totpStage.getByRole("button", { name: "Confirmar", exact: true }).click();
      await expect(totpStage).toContainText("Confirmado.");
    } finally {
      releaseRestart();
    }
    await restartClick;
    for (const prior of originalCookies) {
      const current = (await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
      expect(current?.value, "delayed restart response must not erase newly proven TOTP capability").toBe(prior.value);
      expect(current?.expires, "no silent expiry extension across raced POSTs").toBe(prior.expires);
    }
    await competingTab.close();
    const partial = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: originalId } });
    expect(partial.status).toBe("PENDING");
    expect(partial.recoveryTotpVerifiedAt).not.toBeNull();
    expect(partial.emailVerifiedAt).toBeNull();
    // A normal browser refresh or bookmarked recovery URL must remain usable
    // after losing the non-authorizing intent hint. Re-submitting the original
    // email/method form must not be a prerequisite for resuming a proven factor.
    const savedIntent = originalCookies.find(cookie => cookie.name === names[2]);
    expect(savedIntent).toBeDefined();
    for (const damage of ["missing", "malformed", "foreign-request", "wrong-method"] as const) {
      if (damage === "missing") {
        await real.context.clearCookies({ name: names[2] });
      } else {
        await real.context.addCookies([{
          name: names[2], url: portalUrl,
          value: damage === "malformed" ? "bad-intent"
            : damage === "wrong-method" ? `${originalId}.EMAIL_ADMIN`
              : `${randomBytes(32).toString("base64url")}.TOTP_EMAIL`,
          httpOnly: true, secure: productionMode, sameSite: "Lax"
        }]);
      }
      await real.page.goto(`${portalUrl}/recover?requestId=${originalId}`);
      await expect(real.page.locator('[aria-label="Aplicativo autenticador"]'))
        .toContainText("Confirmado.");
      await expect(real.page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toBeVisible();
      for (const prior of originalCookies.filter(cookie => cookie.name !== names[2])) {
        const after = (await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
        expect(after?.value, `${damage} direct GET must preserve ${prior.name}`).toBe(prior.value);
        expect(after?.expires).toBe(prior.expires);
      }
      await real.context.addCookies([savedIntent!]);
    }
    const originalMessages = await database.emailOutboxMessage.count({
      where: { recipientEmail: ownerEmail, kind: "ACCOUNT_RECOVERY" }
    });
    // A malformed second POST used to destroy the original capability even
    // when its TOTP proof was already durable. It must be harmless.
    await real.page.goto(`${portalUrl}/recover`);
    await real.page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
    await real.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await real.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).evaluate(button => {
      const form = button.closest("form");
      if (!form) throw new Error("Recovery form missing.");
      const malformed = document.createElement("input");
      malformed.name = "comment";
      malformed.value = "disallowed-for-TOTP_EMAIL";
      malformed.type = "hidden";
      form.appendChild(malformed);
    });
    const malformedPost = real.page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/recover");
    await real.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    const malformedAction = await malformedPost;
    const malformedBody = malformedAction.request().postDataBuffer()?.toString("utf8") ?? "";
    expect(/name="(?:_\d+_)?comment"/u.test(malformedBody),
      "malformed recovery POST must truly submit the extra disallowed field").toBe(true);
    expect(malformedBody.includes("disallowed-for-TOTP_EMAIL")).toBe(true);
    await expect(real.page).toHaveURL(`${portalUrl}/recover?requestId=${originalId}`);
    for (const prior of originalCookies) {
      expect((await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name)?.value).toBe(prior.value);
    }
    // An alternate mailbox form must also not discard an in-progress recovery.
    await real.page.goto(`${portalUrl}/recover`);
    const foreignEmail = `absent-${randomUUID()}@e2e.invalid`;
    await real.page.getByLabel("E-mail da conta", { exact: true }).fill(foreignEmail);
    await real.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    const foreignPost = real.page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/recover");
    await real.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    expect(((await foreignPost).request().postDataBuffer()?.toString("utf8") ?? "").includes(foreignEmail),
      "alternate mailbox must be submitted through a real POST").toBe(true);
    await expect(real.page).toHaveURL(`${portalUrl}/recover?requestId=${originalId}`);
    for (const prior of originalCookies) {
      expect((await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name)?.value).toBe(prior.value);
    }
    await real.page.goto(`${portalUrl}/recover`);
    await real.page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
    await real.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    const restartPost = real.page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/recover");
    await real.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    const restarted = await restartPost;
    expect(restarted.status()).toBeGreaterThanOrEqual(200);
    expect(restarted.status()).toBeLessThan(400);
    await expect(real.page).toHaveURL(`${portalUrl}/recover?requestId=${originalId}`);
    for (const prior of originalCookies) {
      const current = (await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
      expect(current?.value, `restart must not replace ${prior.name}`).toBe(prior.value);
      expect(current?.expires, "restart must not extend a recovery capability's TTL").toBe(prior.expires);
    }
    // Intent is a UI hint, not the authority for the already-proven bearer pair.
    // Corrupt only that hint while leaving both real capability cookies intact.
    const originalIntent = originalCookies.find(cookie => cookie.name === names[2]);
    expect(originalIntent).toBeDefined();
    for (const intentDamage of ["missing", "corrupted", "valid-but-foreign-id"] as const) {
      if (intentDamage === "missing") {
        await real.context.clearCookies({ name: names[2] });
      } else {
        await real.context.addCookies([{
          name: names[2],
          value: intentDamage === "corrupted"
            ? "corrupted-intent"
            : `${randomBytes(32).toString("base64url")}.TOTP_EMAIL`,
          url: portalUrl,
          httpOnly: true, secure: productionMode, sameSite: "Lax"
        }]);
      }
      await real.page.goto(`${portalUrl}/recover`);
      await real.page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
      await real.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
      const corruptPost = real.page.waitForResponse(response => response.request().method() === "POST" &&
        new URL(response.url()).pathname === "/recover");
      await real.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
      const corruptAction = await corruptPost;
      expect(corruptAction.status()).toBeGreaterThanOrEqual(200);
      expect(corruptAction.status()).toBeLessThan(400);
      for (const prior of originalCookies.filter(cookie => cookie.name !== names[2])) {
        const current = (await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
        expect(current?.value, `${intentDamage} non-authoritative intent must not erase ${prior.name}`).toBe(prior.value);
        expect(current?.expires).toBe(prior.expires);
      }
      // The server may rehydrate the NON-authorizing hint only after genuine
      // key+browser proof and live TOTP binding, never from the forged ID.
      await expect(real.page).toHaveURL(`${portalUrl}/recover?requestId=${originalId}`);
      expect((await real.context.cookies(portalUrl)).find(cookie => cookie.name === names[2])?.value)
        .toBe(originalIntent!.value);
      await expect(real.page.locator('[aria-label="Aplicativo autenticador"]')).toContainText("Confirmado.");
    }
    expect(await database.accountRecoveryRequest.count({ where: { userId: ownerId } })).toBe(1);
    expect(await database.emailOutboxMessage.count({ where: { recipientEmail: ownerEmail, kind: "ACCOUNT_RECOVERY" } }))
      .toBe(originalMessages);
    const independent = await openRecovery(browser, "portal");
    contexts.push(independent.context);
    const syntheticId = await startSelectedTotpEmail(independent.page, ownerEmail);
    expect(syntheticId).not.toBe(originalId);
    expect(await database.accountRecoveryRequest.count({ where: { userId: ownerId } })).toBe(1);
    const syntheticPair = (await independent.context.cookies(portalUrl))
      .filter(cookie => names.slice(0, 2).includes(cookie.name));
    expect(syntheticPair).toHaveLength(2);
    await independent.context.addCookies([{
      name: names[2], value: `${randomBytes(32).toString("base64url")}.TOTP_EMAIL`,
      url: portalUrl, httpOnly: true, secure: productionMode, sameSite: "Lax"
    }]);
    await independent.page.goto(`${portalUrl}/recover`);
    await independent.page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
    await independent.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await independent.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    await expect(independent.page).toHaveURL(`${portalUrl}/recover?restart=1`);
    await expect(independent.page.getByText("A recuperação anterior foi preservada.", { exact: false })).toBeVisible();
    for (const prior of syntheticPair) {
      expect((await independent.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name)?.value)
        .toBe(prior.value);
    }
    // A legitimate typo correction remains possible after an affirmative
    // browser-visible acknowledgement, without teaching the browser whether
    // the previous attempt was synthetic or a real unproven request.
    await independent.page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
    await independent.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await independent.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u }).check();
    const syntheticRetry = independent.page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/recover");
    await independent.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    expect((await syntheticRetry).status()).toBeLessThan(400);
    // A synthetic request contains no independently proven recovery to lose.
    // A user correcting a typo must be able to request a new recovery rather
    // than being trapped behind the first synthetic pair's one-hour cookie TTL.
    await expect(independent.page).toHaveURL(/\/recover\?requestId=/u);
    const retriedSyntheticId = new URL(independent.page.url()).searchParams.get("requestId");
    expect(retriedSyntheticId).not.toBe(syntheticId);
    expect(retriedSyntheticId).not.toBe(originalId);
    for (const prior of syntheticPair) {
      const current = (await independent.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
      expect(current?.value, "a synthetic retry may rotate only its own unproven bearer pair").not.toBe(prior.value);
    }
    expect(await database.accountRecoveryRequest.count({ where: { userId: ownerId } })).toBe(1);
    const message = await database.emailOutboxMessage.findFirst({
      where: { recipientEmail: ownerEmail, kind: "ACCOUNT_RECOVERY" },
      orderBy: { createdAt: "desc" }, select: { payload: true }
    });
    const emailCode = message ? decryptEmailPayload(message.payload).code : undefined;
    expect(emailCode).toMatch(/^\d{6}$/u);
    // Even when a later proof POST races the missing hint, only the original
    // cryptographically bound pair (not UI intent) authorizes that transition.
    await real.context.clearCookies({ name: names[2] });
    await real.page.goto(`${portalUrl}/recover?requestId=${originalId}`);
    const emailStage = real.page.locator('[aria-label="E-mail cadastrado"]');
    await emailStage.locator('input[name="code"]').fill(emailCode!);
    await emailStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(real.page.getByText("Confirmações concluídas.", { exact: false })).toBeVisible();
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: originalId } })).status).toBe("APPROVED");
  } finally {
    const closed = await Promise.allSettled(contexts.map(context => context.close()));
    try {
      if (ownerId) {
        await database.accountRecoveryRequest.deleteMany({ where: { userId: ownerId } });
        await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: ownerEmail } });
        await database.totpFactor.deleteMany({ where: { userId: ownerId } });
        await database.user.deleteMany({ where: { id: ownerId, email: ownerEmail } });
      }
    } finally {
      await database.$disconnect();
    }
    expect(closed.every(result => result.status === "fulfilled")).toBe(true);
  }
});

test("USER modern proven recovery survives legacy link GET and POST until explicit switch", async ({ browser }) => {
  test.setTimeout(120_000);
  const { database } = await requireFixture();
  const contexts: BrowserContext[] = [];
  const modernEmail = `${randomUUID()}.modern-open@e2e.invalid`;
  const legacyEmail = `${randomUUID()}.legacy-open@e2e.invalid`;
  let modernUserId: string | undefined;
  let legacyUserId: string | undefined;
  try {
    const secret = createTotpSecret();
    const [modernUser, legacyUser] = await Promise.all([
      database.user.create({ data: {
        email: modernEmail, emailNormalized: modernEmail, displayName: "Owned modern link fixture",
        passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
        role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
        secondFactorMethod: "TOTP", totpFactor: { create: {
          secretCiphertext: encryptTotpSecret(secret), keyVersion: 1, status: "ACTIVE", confirmedAt: new Date()
        } }
      }, select: { id: true } }),
      database.user.create({ data: {
        email: legacyEmail, emailNormalized: legacyEmail, displayName: "Owned legacy link fixture",
        passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
        role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date()
      }, select: { id: true } })
    ]);
    modernUserId = modernUser.id;
    legacyUserId = legacyUser.id;
    const legacyKey = randomBytes(24).toString("base64url");
    const legacy = await database.accountRecoveryRequest.create({ data: {
      userId: legacyUserId, requestKeyHash: hashRecoveryRequestKey(legacyKey),
      emailAddressHash: hashEmailAddress(legacyEmail),
      emailChallengeHash: hashSecurityCode("123456"), purpose: "RECOVERY",
      expiresAt: new Date(Date.now() + 30 * 60_000)
    }, select: { id: true } });
    const real = await openRecovery(browser, "portal");
    contexts.push(real.context);
    const modernId = await startSelectedTotpEmail(real.page, modernEmail);
    const names = productionMode
      ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
      : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
    const totpStage = real.page.locator('[aria-label="Aplicativo autenticador"]');
    await totpStage.locator('input[name="code"]').fill(totpAt(secret));
    await totpStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(totpStage).toContainText("Confirmado.");
    const partial = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: modernId } });
    expect(partial.status).toBe("PENDING");
    expect(partial.recoveryTotpVerifiedAt).not.toBeNull();
    const original = (await real.context.cookies(portalUrl)).filter(cookie => names.includes(cookie.name));
    expect(original).toHaveLength(3);
    const checkOriginal = async () => {
      const current = await real.context.cookies(portalUrl);
      for (const before of original) {
        const after = current.find(cookie => cookie.name === before.name);
        expect(after?.value, `legacy link must not replace ${before.name}`).toBe(before.value);
        expect(after?.expires, "legacy link must not extend modern cookie TTL").toBe(before.expires);
      }
      expect(current.find(cookie => cookie.name.includes("recovery_candidate"))?.value).toBe(legacyKey);
    };
    const getResponse = await real.page.goto(`${portalUrl}/recover/open?request=${encodeURIComponent(legacyKey)}`);
    expect(getResponse?.status()).toBe(200);
    await expect(real.page).toHaveURL(new RegExp(`/recover\\?requestId=${legacy.id}&switch=1$`));
    await expect(real.page.getByRole("button", { name: "Continuar com este link" })).toBeVisible();
    await checkOriginal();
    await real.page.goto(`${portalUrl}/recover?request=${encodeURIComponent(legacyKey)}`);
    await real.page.getByRole("button", { name: "Continuar recuperação" }).click();
    await expect(real.page).toHaveURL(new RegExp(`/recover\\?switch=1&requestId=${legacy.id}$`));
    await checkOriginal();
    // Intent is a display hint, not authority to delete a verified capability.
    // Simulate a corrupt hint while preserving the real HttpOnly owner key.
    const hint = original.find(cookie => cookie.name === names[2])!;
    await real.context.addCookies([{
      name: hint.name, value: "malformed-intent", url: `${portalUrl}/`,
      httpOnly: hint.httpOnly, secure: hint.secure, sameSite: hint.sameSite, expires: hint.expires
    }]);
    await real.page.goto(`${portalUrl}/recover/open?request=${encodeURIComponent(legacyKey)}`);
    await expect(real.page).toHaveURL(new RegExp(`/recover\\?requestId=${legacy.id}&switch=1$`));
    const afterCorruption = await real.context.cookies(portalUrl);
    expect(afterCorruption.find(cookie => cookie.name === names[0])?.value).toBe(original.find(cookie => cookie.name === names[0])?.value);
    expect(afterCorruption.find(cookie => cookie.name === names[1])?.value).toBe(original.find(cookie => cookie.name === names[1])?.value);
    await real.context.addCookies([{
      name: hint.name, value: hint.value, url: `${portalUrl}/`,
      httpOnly: hint.httpOnly, secure: hint.secure, sameSite: hint.sameSite, expires: hint.expires
    }]);
    const foreign = await openRecovery(browser, "portal");
    contexts.push(foreign.context);
    const syntheticId = await startSelectedTotpEmail(foreign.page, `absent-${randomUUID()}@e2e.invalid`);
    expect(syntheticId).not.toBe(modernId);
    const syntheticCookies = await foreign.context.cookies(portalUrl);
    expect(syntheticCookies.find(cookie => cookie.name === names[2])?.value).toBe(`${syntheticId}.TOTP_EMAIL`);
    await foreign.page.goto(`${portalUrl}/recover/open?request=${encodeURIComponent(legacyKey)}`);
    await expect(foreign.page).toHaveURL(new RegExp(`/recover\\?requestId=${legacy.id}&switch=1$`));
    expect((await foreign.context.cookies(portalUrl)).find(cookie => cookie.name === names[0])?.value)
      .toBe(syntheticCookies.find(cookie => cookie.name === names[0])?.value);
    const fresh = await openRecovery(browser, "portal");
    contexts.push(fresh.context);
    await fresh.page.goto(`${portalUrl}/recover/open?request=${encodeURIComponent(legacyKey)}`);
    await expect(fresh.page).toHaveURL(`${portalUrl}/recover?requestId=${legacy.id}`);
    const adopted = await fresh.context.cookies(portalUrl);
    expect(adopted.find(cookie => cookie.name === names[0])?.value).toBe(legacyKey);
    expect(adopted.find(cookie => cookie.name === names[1])?.value ?? "").toBe("");
    expect(adopted.find(cookie => cookie.name === names[2])?.value ?? "").toBe("");
    const message = await database.emailOutboxMessage.findFirst({
      where: { recipientEmail: modernEmail, kind: "ACCOUNT_RECOVERY" },
      orderBy: { createdAt: "desc" }, select: { payload: true }
    });
    const code = message ? decryptEmailPayload(message.payload).code : undefined;
    expect(code).toMatch(/^\d{6}$/u);
    await real.page.goto(`${portalUrl}/recover?requestId=${modernId}`);
    const emailStage = real.page.locator('[aria-label="E-mail cadastrado"]');
    await emailStage.locator('input[name="code"]').fill(code!);
    await emailStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(real.page.getByText("Confirmações concluídas.", { exact: false })).toBeVisible();
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: modernId } })).status).toBe("APPROVED");
    await real.page.goto(`${portalUrl}/recover?requestId=${legacy.id}&switch=1`);
    await expect(real.page.getByRole("button", { name: "Continuar com este link" })).toBeVisible();
    const explicitPost = real.page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/recover" && Boolean(response.request().headers()["next-action"]));
    await real.page.getByRole("button", { name: "Continuar com este link" }).click();
    const explicitResponse = await explicitPost;
    expect(explicitResponse.status()).toBeGreaterThanOrEqual(200);
    expect(explicitResponse.status()).toBeLessThan(400);
    await expect.poll(async () => {
      const current = await real.context.cookies(portalUrl);
      return current.find(cookie => cookie.name === names[0])?.value === legacyKey;
    }, { timeout: 15_000, message: "only confirmed switch may replace the primary recovery key" }).toBe(true);
    await expect.poll(() => {
      const url = new URL(real.page.url());
      return {
        pathname: url.pathname, legacyId: url.searchParams.get("requestId") === legacy.id,
        hasError: url.searchParams.has("error")
      };
    }, { timeout: 15_000 }).toEqual({ pathname: "/recover", legacyId: true, hasError: false });
    // A Next RSC refresh may preserve the harmless switch=1 query while
    // unmounting the client form; the durable oracle is the new cookie and
    // the genuinely usable legacy proof screen.
    await expect(real.page.getByLabel("Código de verificação", { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(real.page.getByRole("button", { name: "Continuar com este link" })).toHaveCount(0);
    const switched = await real.context.cookies(portalUrl);
    expect(switched.find(cookie => cookie.name === names[0])?.value).toBe(legacyKey);
    expect(switched.find(cookie => cookie.name === names[1])?.value ?? "").toBe("");
    expect(switched.find(cookie => cookie.name === names[2])?.value ?? "").toBe("");
  } finally {
    const closed = await Promise.allSettled(contexts.map(context => context.close()));
    try {
      for (const id of [modernUserId, legacyUserId]) {
        if (id) {
          await database.accountRecoveryRequest.deleteMany({ where: { userId: id } });
          await database.totpFactor.deleteMany({ where: { userId: id } });
        }
      }
      await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: { in: [modernEmail, legacyEmail] } } });
      if (modernUserId) await database.user.deleteMany({ where: { id: modernUserId, email: modernEmail } });
      if (legacyUserId) await database.user.deleteMany({ where: { id: legacyUserId, email: legacyEmail } });
    } finally {
      await database.$disconnect();
    }
    expect(closed.every(result => result.status === "fulfilled")).toBe(true);
  }
});

test("USER TOTP+EMAIL: real/synthetic parity, independent HTTP proofs, one-time reset and scoped cookies", async ({ browser }) => {
  test.setTimeout(120_000);
  const { database } = await requireFixture();
  const contexts: BrowserContext[] = [];
  const ownedEmail = `${randomUUID()}.multimethod@e2e.invalid`;
  let ownedUserId: string | undefined;
  try {
    const totpSecret = createTotpSecret();
    // The global E2E fixture is reused by other serial suites. Create a
    // unique owner-labelled account instead, so an earlier recovery request's
    // cooldown cannot silently turn the supposedly real case synthetic.
    const ownedUser = await database.user.create({ data: {
      email: ownedEmail, emailNormalized: ownedEmail, displayName: "Owned multi-method E2E fixture",
      passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
      secondFactorMethod: "TOTP",
      totpFactor: { create: {
        secretCiphertext: encryptTotpSecret(totpSecret), keyVersion: 1,
        status: "ACTIVE", confirmedAt: new Date()
      } }
    }, select: { id: true } });
    ownedUserId = ownedUser.id;
    const totalBefore = await database.accountRecoveryRequest.count();
    const real = await openRecovery(browser, "portal");
    contexts.push(real.context);
    const knownId = await startSelectedTotpEmail(real.page, ownedEmail);
    await assertBoundCookies(real.context, real.base, knownId);
    const realPreProof = (await real.page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim();
    const realVisiblePage = (await real.page.locator("main").innerText()).trim();

    const synthetic = await openRecovery(browser, "portal");
    contexts.push(synthetic.context);
    const absentEmail = `absent-${randomUUID()}@e2e.invalid`;
    const syntheticId = await startSelectedTotpEmail(synthetic.page, absentEmail);
    await assertBoundCookies(synthetic.context, synthetic.base, syntheticId);
    const syntheticPreProof = (await synthetic.page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim();
    expect(syntheticPreProof,
      "known and unknown account requests must show the same pre-proof state and text").toBe(realPreProof);
    expect((await synthetic.page.locator("main").innerText()).trim(),
      "the complete visible pre-proof page must not enumerate the selected account").toBe(realVisiblePage);
    expect(syntheticId).not.toBe(knownId);
    expect((await database.accountRecoveryRequest.count({ where: { userId: ownedUserId } }))).toBe(1);
    expect(await database.accountRecoveryRequest.count(),
      "the nonexistent account must not cause an additional database recovery request").toBe(totalBefore + 1);
    const otherContext = await browser.newContext();
    contexts.push(otherContext);
    const stolenPage = await otherContext.newPage();
    await stolenPage.goto(`${portalUrl}/recover?requestId=${encodeURIComponent(knownId)}`);
    await expect(stolenPage.locator('[aria-label="E-mail cadastrado"] input[name="code"]'),
      "an unbound browser must not see or claim another browser's recovery ceremony").toHaveCount(0);

    const message = await database.emailOutboxMessage.findFirst({
      where: { recipientEmail: ownedEmail, kind: "ACCOUNT_RECOVERY" },
      orderBy: { createdAt: "desc" }, select: { payload: true }
    });
    const emailCode = message ? decryptEmailPayload(message.payload).code : undefined;
    expect(emailCode).toMatch(/^\d{6}$/u);
    const emailStage = real.page.locator('[aria-label="E-mail cadastrado"]');
    await emailStage.locator('input[name="code"]').fill(emailCode!);
    await emailStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(real.page.locator('[aria-label="E-mail cadastrado"]')).toContainText("Confirmado.");

    const totpStage = real.page.locator('[aria-label="Aplicativo autenticador"]');
    await totpStage.locator('input[name="code"]').fill(totpAt(totpSecret));
    await totpStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(real.page.getByText("Defina uma nova senha para finalizar a recuperação.", { exact: false })).toBeVisible();
    // Preserve an already-rendered second completion form and the original
    // cookies, then replay its actual Server Action POST after first consume.
    const stalePage = await real.context.newPage();
    await stalePage.goto(real.page.url());
    const staleResetCandidate = `stale-e2e-${randomUUID()}-password`;
    await stalePage.getByLabel("Nova senha", { exact: true }).fill(staleResetCandidate);
    const priorRecoveryCookies = (await real.context.cookies(portalUrl))
      .filter((cookie) => cookie.name.includes("recovery"))
      .map((cookie) => ({
        // Playwright's `domain` field describes a cookie; supplying it when
        // restoring __Host- cookies could mint an invalid Domain attribute.
        // Use the exact original HTTPS origin to restore a host-only cookie.
        url: `${portalUrl}/`, name: cookie.name, value: cookie.value,
        httpOnly: cookie.httpOnly, secure: cookie.secure,
        sameSite: cookie.sameSite, expires: cookie.expires
      }));
    const resetCandidate = `multimethod-e2e-${randomUUID()}-password`;
    await real.page.getByLabel("Nova senha", { exact: true }).fill(resetCandidate);
    await real.page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(real.page).toHaveURL(`${portalUrl}/account/security?recovered=password`);
    const recovered = await database.user.findUniqueOrThrow({ where: { id: ownedUserId } });
    expect(await verifyPassword(recovered.passwordHash ?? "", resetCandidate)).toBe(true);
    expect(recovered.secondFactorMethod).toBe("EMAIL");
    expect((await database.totpFactor.findUniqueOrThrow({ where: { userId: ownedUserId } })).status).toBe("REVOKED");
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: knownId } })).status).toBe("CONSUMED");
    expect(await database.session.count({ where: { userId: ownedUserId, revokedAt: null, expiresAt: { gt: new Date() } } })).toBe(1);
    const finalCookies = await real.context.cookies(portalUrl);
    expect(finalCookies.some((cookie) => cookie.name === getSessionCookieName({ NODE_ENV: productionMode ? "production" : "development" }) && Boolean(cookie.value))).toBe(true);
    expect(finalCookies.some((cookie) => cookie.name.includes("recovery") && Boolean(cookie.value))).toBe(false);
    // Reinject the original browser capability as a host-only cookie. Using
    // the Cookie object's explicit domain with a __Host- prefix would break
    // Chromium's host-only prefix restrictions in production-mode rehearsals.
    await real.context.addCookies(priorRecoveryCookies.map((cookie) => ({
      name: cookie.name, value: cookie.value, url: `${portalUrl}/`,
      expires: cookie.expires, httpOnly: cookie.httpOnly,
      secure: cookie.secure, sameSite: cookie.sameSite
    })));
    const restored = await real.context.cookies(portalUrl);
    for (const cookie of priorRecoveryCookies) {
      expect(restored.find((candidate) => candidate.name === cookie.name)?.value).toBe(cookie.value);
    }
    const rejectedReplay = stalePage.waitForResponse((response) => response.request().method() === "POST" &&
      new URL(response.url()).origin === portalUrl && new URL(response.url()).pathname === "/recover" &&
      Boolean(response.request().headers()["next-action"]));
    await stalePage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    const replayResponse = await rejectedReplay;
    expect(replayResponse.request().postDataBuffer()?.byteLength ?? 0,
      "the stale password must be submitted through an actual Next Server Action POST").toBeGreaterThan(0);
    await expect(stalePage).toHaveURL(portalUrl + "/recover?requestId=" + knownId + "&error=1",
      { timeout: 15_000 });
    const afterReplay = await database.user.findUniqueOrThrow({ where: { id: ownedUserId } });
    expect(await verifyPassword(afterReplay.passwordHash ?? "", resetCandidate)).toBe(true);
    expect(await verifyPassword(afterReplay.passwordHash ?? "", staleResetCandidate)).toBe(false);
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: knownId } })).status).toBe("CONSUMED");
    expect(await database.session.count({ where: { userId: ownedUserId, revokedAt: null, expiresAt: { gt: new Date() } } }),
      "replaying the same browser capability must not issue a second bootstrap session").toBe(1);
    await real.page.goto(`${portalUrl}/recover?requestId=${encodeURIComponent(knownId)}`);
    await expect(real.page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toHaveCount(0);
  } finally {
    // One browser's close failure cannot skip isolated DB cleanup/disconnect.
    const contextResults = await Promise.allSettled(contexts.map((context) => context.close()));
    try {
      if (ownedUserId) {
        await database.session.deleteMany({ where: { userId: ownedUserId } });
        await database.accountRecoveryRequest.deleteMany({ where: { userId: ownedUserId } });
        await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: ownedEmail } });
        await database.totpFactor.deleteMany({ where: { userId: ownedUserId } });
        await database.user.deleteMany({ where: { id: ownedUserId, email: ownedEmail } });
      }
    } finally {
      await database.$disconnect();
    }
    expect(contextResults.every((result) => result.status === "fulfilled"),
      "every isolated browser context must close successfully").toBe(true);
  }
});

test("recovery form rejects a tampered CSRF token without minting capability cookies or mutating requests", async ({ browser }) => {
  const { fixture, database } = await requireFixture();
  const { context, page, base } = await openRecovery(browser, "portal");
  try {
    const before = await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } });
    await page.getByLabel("E-mail da conta", { exact: true }).fill(fixture.user.email);
    await page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await page.locator('form input[name="csrfToken"]').first().evaluate((input) => {
      (input as HTMLInputElement).value = "invalid-tampered-csrf";
    });
    const denied = page.waitForResponse((response) => response.request().method() === "POST" &&
      new URL(response.url()).origin === base && new URL(response.url()).pathname === "/recover");
    await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    expect((await denied).status()).toBe(403);
    expect(await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } })).toBe(before);
    const cookies = await context.cookies(base);
    expect(cookies.some((cookie) => cookie.name.includes("recovery") && Boolean(cookie.value))).toBe(false);
  } finally {
    await context.close();
    await database.$disconnect();
  }
});

test("Hub ADMIN recovery requires synthetic Access and never exposes a Portal ADMIN method", async ({ browser }) => {
  const { database } = await requireFixture();
  const contexts: BrowserContext[] = [];
  try {
    const blocked = await browser.newContext();
    contexts.push(blocked);
    const noAccess = await blocked.newPage();
    const blockedResponse = await noAccess.goto(`${hubUrl}/recover`);
    expect(blockedResponse?.status()).toBe(403);

    const portal = await openRecovery(browser, "portal");
    contexts.push(portal.context);
    await expect(portal.page.getByRole("heading", { level: 1, name: "Recuperar conta" })).toBeVisible();
    await expect(portal.page.getByRole("heading", { name: "Recuperar acesso administrativo" })).toHaveCount(0);
    for (const method of ["TOTP_EMAIL", "EMAIL_ADMIN", "TOTP_ADMIN"] as const) {
      await expect(portal.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(1);
    }
    for (const method of ["PASSKEY_EMAIL", "PASSKEY_TOTP", "PASSKEY_ADMIN"] as const) {
      await expect(portal.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(
        process.env.VIRKI_E2E_PASSKEYS === "true" ? 1 : 0);
    }

    const hub = await openRecovery(browser, "hub");
    contexts.push(hub.context);
    await expect(hub.page.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo" })).toBeVisible();
    for (const method of ["TOTP_EMAIL", "EMAIL_ADMIN", "TOTP_ADMIN"] as const) {
      await expect(hub.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(1);
    }
    for (const method of ["PASSKEY_EMAIL", "PASSKEY_TOTP", "PASSKEY_ADMIN"] as const) {
      await expect(hub.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(
        process.env.VIRKI_E2E_ADMIN_PASSKEYS === "true" ? 1 : 0);
    }
    expect((await hub.context.cookies(hubUrl)).filter((cookie) => cookie.name.includes("recovery") && cookie.value.length > 0),
      "merely viewing the ADMIN recovery form must not issue an authorizing recovery capability").toHaveLength(0);
    // Hub-native/Access-gated ADMIN and public USER recovery must obey the
    // same explicit-restart contract, including an unknown/synthetic account.
    const syntheticAdminId = await startSelectedTotpEmail(hub.page, randomUUID() + "@e2e.invalid");
    const hubOriginalCookies = (await hub.context.cookies(hubUrl)).filter((cookie) =>
      cookie.name.includes("recovery") && Boolean(cookie.value));
    expect(hubOriginalCookies).toHaveLength(3);
    expect((await hub.context.cookies(portalUrl)).filter((cookie) => cookie.name.includes("recovery")))
      .toHaveLength(0);
    await hub.page.goto(hubUrl + "/recover");
    await hub.page.getByLabel("E-mail da conta", { exact: true }).fill(randomUUID() + "@e2e.invalid");
    await hub.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await hub.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    await expect(hub.page).toHaveURL(hubUrl + "/recover?restart=1");
    for (const prior of hubOriginalCookies) {
      expect((await hub.context.cookies(hubUrl)).find((cookie) => cookie.name === prior.name)?.value)
        .toBe(prior.value);
    }
    await hub.page.getByLabel("E-mail da conta", { exact: true }).fill(randomUUID() + "@e2e.invalid");
    await hub.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await hub.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u }).check();
    await hub.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    await expect(hub.page).toHaveURL(/\/recover\?requestId=/u);
    expect(new URL(hub.page.url()).searchParams.get("requestId")).not.toBe(syntheticAdminId);
    for (const prior of hubOriginalCookies.filter((cookie) => !cookie.name.includes("intent"))) {
      expect((await hub.context.cookies(hubUrl)).find((cookie) => cookie.name === prior.name)?.value)
        .not.toBe(prior.value);
    }
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
    await database.$disconnect();
  }
});
