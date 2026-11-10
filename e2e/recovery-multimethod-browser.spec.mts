import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { PrismaClient } from "@virki/database";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { createTotpSecret, encryptTotpSecret, hashRecoveryRequestKey } from "@virki/auth/security";
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

async function startSelectedRecovery(page: Page, email: string, method: "TOTP_EMAIL" | "PASSKEY_EMAIL" | "PASSKEY_TOTP"): Promise<string> {
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
  } else {
    await expect(page.locator('[aria-label="Aplicativo autenticador"] input[name="code"]')).toBeVisible();
  }
  return publicRequestId;
}

async function startSelectedTotpEmail(page: Page, email: string): Promise<string> {
  return startSelectedRecovery(page, email, "TOTP_EMAIL");
}

async function assertBoundCookies(context: BrowserContext, base: string, requestId: string,
  method: "TOTP_EMAIL" | "PASSKEY_EMAIL" | "PASSKEY_TOTP" = "TOTP_EMAIL"): Promise<void> {
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
          expect(rejectedPost.request().headers().origin).toBe(portalUrl);
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
          await expect(page.locator('section[aria-label="Verificação do novo e-mail"] input[name="code"]')).toBeVisible();
          const wrongCode = code === "000000" ? "000001" : "000000";
          await page.locator('section[aria-label="Verificação do novo e-mail"] input[name="code"]').fill(wrongCode);
          await page.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
          await expect(page.locator('section[aria-label="Verificação do novo e-mail"] [role="alert"]'))
            .toContainText("Código inválido ou expirado");
          expect((await database.accountRecoveryRequest.findUniqueOrThrow({
            where: { id: requestId }, select: { recoveryNewEmailVerifiedAt: true }
          })).recoveryNewEmailVerifiedAt).toBeNull();
          await page.locator('section[aria-label="Verificação do novo e-mail"] input[name="code"]').fill(code!);
          await page.getByRole("button", { name: "Confirmar novo e-mail", exact: true }).click();
        }
        await expect(page.getByLabel("Nova senha", { exact: true })).toBeVisible({ timeout: 20_000 });

        // Keep the already-rendered second completion form in its own cookie
        // jar. The winning reset clears recovery cookies and installs a session
        // in `context`; sharing that jar can replace the stale /recover view
        // before its second Server Action POST is actually submitted.
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
        const staleDocument = await stale.goto(page.url());
        expect(staleDocument?.status(), "stale form must come from a real recovery document").toBe(200);
        await expect(stale.getByLabel("Nova senha", { exact: true })).toBeVisible();
        await expect(stale.locator('form input[name="requestId"]')).toHaveValue(requestId);
        const rejectedPassword = "replay-" + randomUUID() + "-password";
        await stale.getByLabel("Nova senha", { exact: true }).fill(rejectedPassword);
        const winningPassword = "signed-" + randomUUID() + "-password";
        await page.getByLabel("Nova senha", { exact: true }).fill(winningPassword);
        await page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
        await expect(page).toHaveURL(portalUrl + "/account/security?recovered=password", { timeout: 25_000 });
        const recovered = await database.user.findUniqueOrThrow({ where: { id: owner.id } });
        expect(await verifyPassword(recovered.passwordHash ?? "", winningPassword)).toBe(true);
        expect(recovered.emailNormalized).toBe(replacementEmail ?? ownerEmail);
        const consumed = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
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
        const protectedUrl = portalUrl + "/account/security";
        const protectedDocument = await page.goto(protectedUrl);
        expect(protectedDocument?.status(), "fresh protected document GET must return HTTP 200").toBe(200);
        await expect(page).toHaveURL(protectedUrl);
        await expect(page.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
        await expect(page.locator("header.page-header")).toContainText(ownerEmail);
        expect((await context.cookies(portalUrl)).filter((cookie) => cookie.name.includes("recovery"))).toHaveLength(0);

        // The winner's session must stay separate from the original capability
        // used by the rejected POST. Verify the stale jar still has that exact
        // capability before clicking its previously rendered, filled form.
        const replayCookies = await staleContext.cookies(portalUrl);
        for (const original of oldCookies) {
          expect(replayCookies.find((cookie) => cookie.name === original.name)?.value).toBe(original.value);
        }
        await expect(stale.getByRole("button", { name: "Concluir recuperação", exact: true })).toBeVisible();
        const replay = stale.waitForResponse((response) =>
          response.request().method() === "POST" && new URL(response.url()).origin === portalUrl &&
          new URL(response.url()).pathname === "/recover" &&
          Boolean(response.request().headers()["next-action"]));
        await stale.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
        const replayResponse = await replay;
        expect(replayResponse.status(), "Next may return 200 or redirect 303 for a rejected Server Action")
          .toBeGreaterThanOrEqual(200);
        expect(replayResponse.status(), "a 403/500 response is not proof of one-time consumption")
          .toBeLessThan(400);
        expect(replayResponse.request().postDataBuffer()?.byteLength ?? 0).toBeGreaterThan(0);
        await expect(stale).toHaveURL(new RegExp("/recover\\?requestId=" + requestId + "&error=1"), { timeout: 15_000 });
        const unchanged = await database.user.findUniqueOrThrow({ where: { id: owner.id } });
        expect(await verifyPassword(unchanged.passwordHash ?? "", winningPassword)).toBe(true);
        expect(await verifyPassword(unchanged.passwordHash ?? "", rejectedPassword)).toBe(false);
        const replayedRequest = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
        expect(replayedRequest.status).toBe("CONSUMED");
        expect(replayedRequest.bootstrapSessionId).toBe(consumed.bootstrapSessionId);
        expect(await database.session.count({ where: {
          userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() }
        } })).toBe(1);
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
    await expect(stalePage).toHaveURL(new RegExp(`/recover\\?requestId=${knownId}&error=1`),
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
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
    await database.$disconnect();
  }
});
