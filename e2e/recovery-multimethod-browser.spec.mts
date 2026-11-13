import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, request as playwrightRequest, test, type APIRequestContext, type Browser, type BrowserContext, type Page, type Response, type Route } from "@playwright/test";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { PrismaClient } from "@virki/database";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { hashAuditIdentifier } from "@virki/auth/audit";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { createTotpSecret, encryptTotpSecret, hashEmailAddress, hashRecoveryRequestKey, hashSecurityCode, DEVICE_COOKIE_NAME } from "@virki/auth/security";
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

async function resumeProvenBrowserAfterLostUrl(page: Page, base: string, id: string): Promise<void> {
  const target = `${base}/recover?requestId=${id}`;
  if (page.url() !== target) {
    // A GET may already have restored the public requestId. Otherwise use
    // the read-only resume action; NEVER start a second recovery request.
    await expect(page).toHaveURL(base + "/recover");
    await page.getByRole("button", { name: "Retomar recuperação anterior" }).click();
  }
  await expect(page).toHaveURL(target);
}

// This must exercise the actual start Server Action, not the UI's read-only
// resume action. The browser explicitly opens the restart form to generate a
// genuine start POST, but the request is adversarially stripped of consent on
// the wire before it reaches the same-origin/CSRF-protected server action.
async function submitUnconsentedRecoveryStartWire(page: Page, email: string, expectedId: string | null, comment?: string): Promise<void> {
  await page.goto(portalUrl + "/recover");
  await page.getByLabel("E-mail da conta", { exact: true }).fill(email);
  await page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
  await page.getByRole("checkbox", { name: /Confirmo que quero substituir/u }).check();
  if (comment) await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).evaluate((button, value) => {
    const form = button.closest("form");
    if (!form) throw new Error("Recovery form missing.");
    const injected = document.createElement("input");
    injected.type = "hidden";
    injected.name = "comment";
    injected.value = value;
    form.appendChild(injected);
  }, comment);
  let authenticStart = false;
  let removedAllConsent = false;
  let includedEmail = false;
  let includedComment = false;
  let intercepted = 0;
  const handler = async (route: Route) => {
    if (route.request().method() !== "POST") return route.continue();
    intercepted += 1;
    const originalBody = route.request().postData() ?? "";
    authenticStart = Boolean(route.request().headers()["next-action"]) &&
      /name="(?:_\d+_)?method"\r?\n\r?\nTOTP_EMAIL:confirm-restart(?:\r?\n|$)/u.test(originalBody);
    includedEmail = originalBody.includes(email);
    includedComment = comment === undefined || originalBody.includes(comment);
    const noSuffix = originalBody.replace("TOTP_EMAIL:confirm-restart", "TOTP_EMAIL");
    const tampered = noSuffix.replace(/(name="(?:_\d+_)?confirmRecoveryRestart"\r?\n\r?\n)yes(?=\r?\n)/gu, "$1no");
    removedAllConsent = !tampered.includes("TOTP_EMAIL:confirm-restart") &&
      !/name="(?:_\d+_)?confirmRecoveryRestart"\r?\n\r?\nyes(?:\r?\n|$)/u.test(tampered);
    await route.continue({ postData: tampered });
  };
  await page.route(/\/recover(?:\?.*)?$/u, handler);
  try {
    const responsePromise = page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/recover");
    await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    const response = await responsePromise;
    expect(response.status(), "the real tampered start must not be denied by unrelated ingress gates").toBeLessThan(400);
    // A deliberately rewritten Server Action request is an ingress/security
    // probe, not a legitimate React UI navigation. Inspect the server's own
    // redirect instead of assuming the client router will apply tampered RSC.
    const redirect = response.headers()["x-action-redirect"] ?? response.headers()["location"] ?? "";
    expect(decodeURIComponent(redirect.split(";")[0] ?? ""),
      expectedId
        ? "the server must retain the original proven request, not initiate another"
        : "an unproven browser pair must not be replaced without consent by the real start action")
      .toBe(expectedId ? `/recover?requestId=${expectedId}` : "/recover?restart=1");
    // Playwright exposes Expires but not Max-Age on stored cookies. Require
    // that the server does not issue a replacement Set-Cookie for either bearer;
    // even a same-value rewrite could silently renew the capability lifetime.
    const setCookies = (await response.headersArray())
      .filter(header => header.name.toLowerCase() === "set-cookie").map(header => header.value);
    const bearerNames = productionMode
      ? ["__Host-virki_recovery", "__Host-virki_recovery_browser"]
      : ["virki_recovery_v2", "virki_recovery_browser"];
    for (const name of bearerNames) {
      expect(setCookies.some(header => header.startsWith(`${name}=`)),
        `no-consent start must not reissue ${name} or reset its Max-Age`).toBe(false);
    }
  } finally {
    await page.unroute(/\/recover(?:\?.*)?$/u, handler);
  }
  expect(intercepted, "the genuine start POST must reach the browser network boundary").toBe(1);
  expect(authenticStart, "not a resume-action POST: real start method with consent suffix").toBe(true);
  expect(removedAllConsent, "strip both possible wire-level consent encodings").toBe(true);
  expect(includedEmail, "the selected mailbox must actually be on the start POST wire").toBe(true);
  expect(includedComment, "the malformed comment must actually be on the start POST wire").toBe(true);
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
    const loginPost = page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).origin === origin && new URL(response.url()).pathname === "/api/login");
    // Observe the FIRST GET in Chromium's actual POST -> 303 -> GET chain.
    // Register before the click so a fast native redirect cannot be missed.
    const nativeVerifyGet = page.waitForResponse(response => {
      const request = response.request();
      const predecessor = request.redirectedFrom();
      const target = new URL(response.url());
      return request.method() === "GET" && target.origin === origin && target.pathname === "/login/verify" &&
        predecessor?.method() === "POST" && new URL(predecessor.url()).pathname === "/api/login";
    }, { timeout: 10_000 }).catch(() => null);
    await page.getByRole("button", { name: "Entrar", exact: true }).click({ noWaitAfter: true });
    const post = await loginPost;
    expect(post.status(), "real password login must start an MFA challenge").toBe(303);
    const location = new URL(post.headers()["location"] ?? "/", origin);
    expect(location.origin).toBe(origin);
    expect(location.pathname).toBe("/login/verify");
    expect(location.searchParams.get("factor")).toBe("email");
    expect(location.searchParams.get("ceremony")).toBeTruthy();
    const issued = (await post.headersArray()).some(header => header.name.toLowerCase() === "set-cookie" &&
      header.value.startsWith(DEVICE_COOKIE_NAME + "="));
    expect(issued, "the real password login must issue the bound device cookie").toBe(true);
    const firstGet = await nativeVerifyGet;
    expect(firstGet, `Chromium must complete the original 303 GET without reloading /login (currently ${new URL(page.url()).pathname})`).not.toBeNull();
    expect(firstGet!.request().redirectedFrom(), "MFA GET must be the browser's original POST redirect").toBe(post.request());
    expect(firstGet!.url(), "MFA GET must follow the server's exact redirect URL").toBe(location.href);
    expect(firstGet!.status(), "the native MFA page must load successfully").toBe(200);
    await expect(page).toHaveURL(location.href);
    await expect(page.getByLabel("Código", { exact: true })).toBeVisible();
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

  let primaryFailure: unknown;
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

    // Next development mode compiles routes lazily and may reload an open login
    // page while compiling /login/verify, canceling Chromium's real 303 GET.
    // Prime compilation with a separate anonymous context, then discard it;
    // the reviewer must still begin with no device cookie or login session.
    const warmContext = await browser.newContext();
    try {
      const warmPage = await warmContext.newPage();
      await addCloudflareAccessHeader(warmPage, { hubOnlyBrowserRedirects: true });
      const warmVerify = warmPage.waitForResponse(response =>
        new URL(response.url()).origin === hubUrl && new URL(response.url()).pathname === "/login/verify");
      const warmLogin = await warmPage.goto(hubUrl + "/login/verify");
      expect((await warmVerify).status(), "anonymous MFA route must compile and reject absent ceremony").toBe(307);
      expect(warmLogin?.status()).toBe(200);
      expect((await warmContext.cookies(hubUrl)).some(cookie => cookie.name === DEVICE_COOKIE_NAME)).toBe(false);
    } finally {
      await warmContext.close();
    }

    const reviewerContext = await newContext();
    expect(await reviewerContext.cookies(hubUrl), "reviewer must start in a genuinely new browser context").toEqual([]);
    const reviewerPage = await reviewerContext.newPage();
    await addCloudflareAccessHeader(reviewerPage, { hubOnlyBrowserRedirects: true });
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
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    if (cdp && authenticatorId) await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => undefined);
    await cdp?.detach().catch(() => undefined);
    const closed = await Promise.allSettled(contexts.map((context) => context.close()));
    // Recovery and elevation write immutable audit references to the owned USER;
    // the disposable runner owns database teardown, so do not delete those rows.
    await database.$disconnect();
    const failedCloses = closed.filter(result => result.status !== "fulfilled").length;
    if (primaryFailure || test.info().status === "timedOut") {
      if (failedCloses) console.warn("E2E_CONTEXT_CLEANUP_FAILURE_COUNT", failedCloses);
    } else {
      expect(failedCloses, "every isolated browser context must close").toBe(0);
    }
  }
});

test("USER fresh/fresh: two initial browser submissions serialize before any capability exists", async ({ browser }) => {
  test.setTimeout(120_000);
  const { database } = await requireFixture();
  const ownerEmail = `${randomUUID()}.fresh-race@e2e.invalid`;
  const secret = createTotpSecret();
  let ownerId: string | undefined;
  let context: BrowserContext | undefined;
  let releaseFirst = () => {};
  let releaseSecond = () => {};
  try {
    const owner = await database.user.create({ data: {
      email: ownerEmail, emailNormalized: ownerEmail, displayName: "Fresh two-tab E2E fixture",
      passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
      secondFactorMethod: "TOTP", totpFactor: { create: {
        secretCiphertext: encryptTotpSecret(secret), keyVersion: 1, status: "ACTIVE", confirmedAt: new Date()
      } }
    }, select: { id: true } });
    ownerId = owner.id;
    const first = await openRecovery(browser, "portal");
    context = first.context;
    const second = await context.newPage();
    await second.goto(portalUrl + "/recover");
    const names = productionMode
      ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
      : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
    expect((await context.cookies(portalUrl)).filter(cookie => names.includes(cookie.name))).toHaveLength(0);
    const firstHold = new Promise<void>(resolve => { releaseFirst = resolve; });
    const secondHold = new Promise<void>(resolve => { releaseSecond = resolve; });
    let firstFetched = false;
    let secondFetched = false;
    await first.page.route(/\/recover(?:\?.*)?$/u, async route => {
      if (route.request().method() !== "POST") return route.continue();
      const response = await route.fetch({ maxRedirects: 0 });
      firstFetched = true;
      await firstHold;
      await route.fulfill({ response });
    });
    await second.route(/\/recover(?:\?.*)?$/u, async route => {
      if (route.request().method() !== "POST") return route.continue();
      const response = await route.fetch({ maxRedirects: 0 });
      secondFetched = true;
      await secondHold;
      await route.fulfill({ response });
    });
    for (const page of [first.page, second]) {
      await page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
      await page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    }
    const firstClick = first.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    try {
      await expect.poll(() => firstFetched, { timeout: 20_000 }).toBe(true);
      // route.fetch writes cookies into the Playwright context before fulfill.
      // Remove only this test-harness side effect; both initial POSTs on the
      // actual wire must arrive WITHOUT a browser-bound recovery pair.
      for (const name of names) await context.clearCookies({ name });
      const secondClick = second.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
      try {
        // The second tab has actually tried to submit, but its request must
        // be queued by the per-origin browser lock until the first response
        // and its HttpOnly cookies have been received.
        await expect.poll(() => second.evaluate(async () =>
          (await navigator.locks.query()).pending?.some(lock => lock.name === "virki-recovery-start-v1") ?? false
        ), { timeout: 20_000 }).toBe(true);
        expect(secondFetched, "the queued fresh POST must not reach the server yet").toBe(false);
        releaseFirst();
        await firstClick;
        await expect(first.page).toHaveURL(/\/recover\?requestId=/u);
        const original = (await context.cookies(portalUrl)).filter(cookie => names.includes(cookie.name));
        expect(original).toHaveLength(3);
        await expect.poll(() => secondFetched, { timeout: 20_000 }).toBe(true);
        // The delayed second POST now carries the first request's cookies
        // and is denied implicit replacement, without changing the pair.
        for (const prior of original) {
          const current = (await context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
          expect(current?.value === prior.value).toBe(true);
        }
        const stage = first.page.locator('[aria-label="Aplicativo autenticador"]');
        await stage.locator('input[name="code"]').fill(totpAt(secret));
        await stage.getByRole("button", { name: "Confirmar", exact: true }).click();
        await expect(stage).toContainText("Confirmado.");
        const originalId = new URL(first.page.url()).searchParams.get("requestId");
        const proven = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: originalId! } });
        expect(proven.recoveryTotpVerifiedAt).not.toBeNull();
        releaseSecond();
        await secondClick;
        await expect(second).toHaveURL(portalUrl + "/recover?restart=1");
        for (const prior of original) {
          const current = (await context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
          expect(current?.value === prior.value,
            "late second fresh POST must not overwrite the verified bearer pair").toBe(true);
        }
      } finally { releaseSecond(); }
    } finally { releaseFirst(); }
  } finally {
    await context?.close();
    if (ownerId) {
      await database.accountRecoveryRequest.deleteMany({ where: { userId: ownerId } });
      await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: ownerEmail } });
      await database.totpFactor.deleteMany({ where: { userId: ownerId } });
      await database.user.deleteMany({ where: { id: ownerId, email: ownerEmail } });
    }
    await database.$disconnect();
  }
});

test("USER TOTP proven: losing the URL requestId still resumes without minting or replacing bearer cookies", async ({ browser }) => {
  test.setTimeout(90_000);
  const { database } = await requireFixture();
  const email = `${randomUUID()}.no-url-resume@e2e.invalid`;
  let userId: string | undefined;
  let context: BrowserContext | undefined;
  try {
    const secret = createTotpSecret();
    const user = await database.user.create({ data: {
      email, emailNormalized: email, displayName: "Missing URL resume test",
      passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
      secondFactorMethod: "TOTP", totpFactor: { create: {
        secretCiphertext: encryptTotpSecret(secret), keyVersion: 1, status: "ACTIVE", confirmedAt: new Date()
      } }
    }, select: { id: true } });
    userId = user.id;
    const session = await openRecovery(browser, "portal");
    context = session.context;
    const id = await startSelectedTotpEmail(session.page, email);
    const stage = session.page.locator('[aria-label="Aplicativo autenticador"]');
    await stage.locator('input[name="code"]').fill(totpAt(secret));
    await stage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(stage).toContainText("Confirmado.");
    const verified = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id } });
    expect(verified.recoveryTotpVerifiedAt).not.toBeNull();
    const primaryNames = productionMode
      ? ["__Host-virki_recovery", "__Host-virki_recovery_browser"]
      : ["virki_recovery_v2", "virki_recovery_browser"];
    const before = (await context.cookies(portalUrl)).filter(c => primaryNames.includes(c.name));
    expect(before).toHaveLength(2);
    await context.clearCookies({
      name: productionMode ? "__Host-virki_recovery_intent" : "virki_recovery_intent"
    });
    await session.page.goto(portalUrl + "/recover");
    await resumeProvenBrowserAfterLostUrl(session.page, portalUrl, id);
    await expect(session.page.locator('[aria-label="Aplicativo autenticador"]')).toContainText("Confirmado.");
    await expect(session.page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toBeVisible();
    for (const prior of before) {
      const current = (await context.cookies(portalUrl)).find(c => c.name === prior.name);
      expect(current?.value === prior.value, "resume must preserve the original bearer value").toBe(true);
      expect(current?.expires).toBe(prior.expires);
    }
    const after = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id } });
    expect(after.recoveryTotpVerifiedAt?.getTime()).toBe(verified.recoveryTotpVerifiedAt?.getTime());
  } finally {
    await context?.close();
    if (userId) {
      await database.accountRecoveryRequest.deleteMany({ where: { userId } });
      await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: email } });
      await database.totpFactor.deleteMany({ where: { userId } });
      await database.user.deleteMany({ where: { id: userId, email } });
    }
    await database.$disconnect();
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
    // A second tab MUST NOT make a new recovery request without deliberate
    // abandonment. It may perform a read-only resume lookup, which cannot
    // race a newly committed TOTP proof by setting another bearer cookie.
    const competingTab = await real.context.newPage();
    await competingTab.goto(portalUrl + "/recover");
    await competingTab.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
    await competingTab.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await competingTab.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    await expect(competingTab).toHaveURL(portalUrl + "/recover?restart=1");
    const totpStage = real.page.locator('[aria-label="Aplicativo autenticador"]');
    for (const original of originalCookies) {
      expect((await real.context.cookies(portalUrl)).find(cookie => cookie.name === original.name)?.value)
        .toBe(original.value);
    }
    await totpStage.locator('input[name="code"]').fill(totpAt(secret));
    await totpStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(totpStage).toContainText("Confirmado.");
    for (const prior of originalCookies) {
      const current = (await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
      expect(current?.value, "read-only resume must not replace a proven TOTP capability").toBe(prior.value);
      expect(current?.expires, "no silent expiry extension across raced POSTs").toBe(prior.expires);
    }
    await competingTab.close();
    const partial = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: originalId } });
    expect(partial.status).toBe("PENDING");
    expect(partial.recoveryTotpVerifiedAt).not.toBeNull();
    expect(partial.emailVerifiedAt).toBeNull();
    // Resume must work even after the address bar loses requestId and a
    // separate tab has already completed the independently enrolled TOTP.
    // A non-authorizing intent cookie cannot be required for this operation.
    await real.context.clearCookies({ name: names[2] });
    await real.page.goto(portalUrl + "/recover");
    await resumeProvenBrowserAfterLostUrl(real.page, portalUrl, originalId);
    await expect(real.page.locator('[aria-label="Aplicativo autenticador"]')).toContainText("Confirmado.");
    await expect(real.page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toBeVisible();
    const resumed = (await real.context.cookies(portalUrl)).filter(cookie => names.includes(cookie.name));
    for (const before of originalCookies.filter(cookie => cookie.name !== names[2])) {
      const current = resumed.find(cookie => cookie.name === before.name);
      expect(current?.value, "a resumed proof cannot rotate an existing bearer").toBe(before.value);
      expect(current?.expires, "resume cannot extend the bearer lifetime").toBe(before.expires);
    }
    const stillProven = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: originalId } });
    expect(stillProven.recoveryTotpVerifiedAt?.getTime()).toBe(partial.recoveryTotpVerifiedAt?.getTime());
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
    // A genuine Server Action start receives an adversarial no-consent POST,
    // including an invalid comment. The read-only resume action cannot count.
    await submitUnconsentedRecoveryStartWire(real.page, ownerEmail, originalId, "disallowed-for-TOTP_EMAIL");
    await real.page.goto(`${portalUrl}/recover?requestId=${originalId}`);
    await expect(real.page).toHaveURL(`${portalUrl}/recover?requestId=${originalId}`);
    for (const prior of originalCookies) {
      expect((await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name)?.value).toBe(prior.value);
    }
    // Nor may a second genuine start for an alternate mailbox replace it.
    const foreignEmail = `absent-${randomUUID()}@e2e.invalid`;
    await submitUnconsentedRecoveryStartWire(real.page, foreignEmail, originalId);
    await real.page.goto(`${portalUrl}/recover?requestId=${originalId}`);
    await expect(real.page).toHaveURL(`${portalUrl}/recover?requestId=${originalId}`);
    for (const prior of originalCookies) {
      expect((await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name)?.value).toBe(prior.value);
    }
    await submitUnconsentedRecoveryStartWire(real.page, ownerEmail, originalId);
    await real.page.goto(`${portalUrl}/recover?requestId=${originalId}`);
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
      await submitUnconsentedRecoveryStartWire(real.page, ownerEmail, originalId);
      await real.page.goto(`${portalUrl}/recover?requestId=${originalId}`);
      for (const prior of originalCookies.filter(cookie => cookie.name !== names[2])) {
        const current = (await real.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
        expect(current?.value, `${intentDamage} non-authoritative intent must not erase ${prior.name}`).toBe(prior.value);
        expect(current?.expires).toBe(prior.expires);
      }
      // The server may rehydrate the NON-authorizing hint only after genuine
      // key+browser proof and live TOTP binding. The hint may also remain
      // missing or malformed: it is never authorization or a requirement
      // for restoring the original proof stage.
      await expect(real.page).toHaveURL(`${portalUrl}/recover?requestId=${originalId}`);
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
    // Discriminating server check: this SYNTHETIC pair has NO verified factor.
    // An unmodified consent-bearing start would rotate it. Strip consent from
    // the actual Next Server Action POST and require /restart=1, not a new ID.
    // This exercises the explicit no-consent guard, unlike proven TOTP cases
    // that are retained even when abandonment consent was supplied.
    const originalRowBefore = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: originalId } });
    expect(originalRowBefore.requestKeyHash).toBe(hashRecoveryRequestKey(originalCookies.find(c => c.name === names[0])!.value));
    expect(originalRowBefore.recoveryBrowserHash).not.toBeNull();
    const originalBearersBefore = (await real.context.cookies(portalUrl))
      .filter(cookie => names.slice(0, 2).includes(cookie.name));
    const outboxBefore = await database.emailOutboxMessage.count({
      where: { recipientEmail: ownerEmail, kind: "ACCOUNT_RECOVERY" }
    });
    await submitUnconsentedRecoveryStartWire(independent.page, ownerEmail, null);
    for (const prior of syntheticPair) {
      const current = (await independent.context.cookies(portalUrl)).find(cookie => cookie.name === prior.name);
      expect(current, "unconsented real start must preserve the unproven bearer and all cookie attributes").toEqual(prior);
    }
    expect(await database.accountRecoveryRequest.count({ where: { userId: ownerId } }),
      "the unconsented start must not create an owner recovery row").toBe(1);
    expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: originalId } }),
      "the refused POST must not change the original proof, capability binding or database expiry")
      .toEqual(originalRowBefore);
    expect((await real.context.cookies(portalUrl)).filter(cookie => names.slice(0, 2).includes(cookie.name)),
      "another tab's refused POST must not rewrite the original browser's bearers").toEqual(originalBearersBefore);
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: ownerEmail, kind: "ACCOUNT_RECOVERY" }
    }), "the refused POST must not issue an additional recovery message").toBe(outboxBefore);
    // A legitimate typo correction remains possible after an affirmative
    // browser-visible acknowledgement, without teaching the browser whether
    // the previous attempt was synthetic or a real unproven request.
    await independent.page.goto(`${portalUrl}/recover?restart=1`);
    await independent.page.getByLabel("E-mail da conta", { exact: true }).fill(ownerEmail);
    await independent.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await independent.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u }).check();
    const retryPhases: string[] = [];
    const retryPostPaths: string[] = [];
    independent.page.on("console", message => {
      if (message.text().startsWith("RESTART_UI_PHASE")) retryPhases.push(message.text());
    });
    independent.page.on("request", request => {
      if (request.method() === "POST") retryPostPaths.push(new URL(request.url()).pathname);
    });
    const syntheticRetry = independent.page.waitForResponse(response => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/recover", { timeout: 12_000 });
    await independent.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    const retryResponse = await syntheticRetry.catch(() => {
      throw new Error("Synthetic retry transport: " + JSON.stringify({ retryPhases, retryPostPaths }));
    });
    expect(retryResponse.status()).toBeLessThan(400);
    expect(/name="(?:_\d+_)?method"\r?\n\r?\nTOTP_EMAIL:confirm-restart(?:\r?\n|$)/u.test(
      retryResponse.request().postDataBuffer()?.toString("utf8") ?? ""),
    "real positive restart POST must include the explicit consent suffix").toBe(true);
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

test("USER legacy GET delayed across modern TOTP proof must never replace the browser-bound pair", async ({ browser }) => {
  test.setTimeout(120_000);
  const { database } = await requireFixture();
  const modernEmail = `${randomUUID()}.legacy-race-modern@e2e.invalid`;
  const legacyEmail = `${randomUUID()}.legacy-race-old@e2e.invalid`;
  const contexts: BrowserContext[] = [];
  let modernUserId: string | undefined;
  let legacyUserId: string | undefined;
  let releaseLegacy = () => {};
  try {
    const secret = createTotpSecret();
    const [modern, legacyUser] = await Promise.all([
      database.user.create({ data: {
        email: modernEmail, emailNormalized: modernEmail, displayName: "Late legacy GET modern test",
        passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
        role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
        secondFactorMethod: "TOTP", totpFactor: { create: {
          secretCiphertext: encryptTotpSecret(secret), keyVersion: 1, status: "ACTIVE", confirmedAt: new Date()
        } }
      }, select: { id: true } }),
      database.user.create({ data: {
        email: legacyEmail, emailNormalized: legacyEmail, displayName: "Late legacy GET old test",
        passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
        role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date()
      }, select: { id: true } })
    ]);
    modernUserId = modern.id;
    legacyUserId = legacyUser.id;
    const legacyKey = randomBytes(24).toString("base64url");
    const legacy = await database.accountRecoveryRequest.create({ data: {
      userId: legacyUser.id, requestKeyHash: hashRecoveryRequestKey(legacyKey),
      emailAddressHash: hashEmailAddress(legacyEmail), emailChallengeHash: hashSecurityCode("123456"),
      purpose: "RECOVERY", expiresAt: new Date(Date.now() + 30 * 60_000)
    }, select: { id: true } });

    const oldTab = await openRecovery(browser, "portal");
    contexts.push(oldTab.context);
    const currentTab = await oldTab.context.newPage();
    await currentTab.goto(portalUrl + "/recover");
    const names = productionMode
      ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
      : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
    expect((await oldTab.context.cookies(portalUrl)).filter(c => names.includes(c.name))).toHaveLength(0);
    const heldLegacy = new Promise<void>(resolve => { releaseLegacy = resolve; });
    let legacyFetched = false;
    await oldTab.page.route(/\/recover\/open(?:\?.*)?$/u, async route => {
      const response = await route.fetch({ maxRedirects: 0 });
      legacyFetched = true;
      await heldLegacy;
      await route.fulfill({ response });
    });
    const oldNavigation = oldTab.page.goto(`${portalUrl}/recover/open?request=${encodeURIComponent(legacyKey)}`);
    try {
      await expect.poll(() => legacyFetched, { timeout: 15_000 }).toBe(true);
      // Playwright's route.fetch may apply held Set-Cookie prematurely.
      // Restore the browser to the authentic pre-response, empty state.
      for (const name of names) await oldTab.context.clearCookies({ name });
      const modernId = await startSelectedTotpEmail(currentTab, modernEmail);
      const stage = currentTab.locator('[aria-label="Aplicativo autenticador"]');
      await stage.locator('input[name="code"]').fill(totpAt(secret));
      await stage.getByRole("button", { name: "Confirmar", exact: true }).click();
      await expect(stage).toContainText("Confirmado.");
      const row = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: modernId } });
      expect(row.recoveryTotpVerifiedAt).not.toBeNull();
      const before = (await oldTab.context.cookies(portalUrl)).filter(c => names.includes(c.name));
      expect(before).toHaveLength(3);
      releaseLegacy();
      await oldNavigation;
      await expect(oldTab.page).toHaveURL(new RegExp(`/recover\\?requestId=${legacy.id}(?:&switch=1)?$`));
      const after = await oldTab.context.cookies(portalUrl);
      for (const cookie of before) {
        expect(after.find(c => c.name === cookie.name)?.value === cookie.value,
          "late legacy GET response must not overwrite the proven modern bearer pair").toBe(true);
        expect(after.find(c => c.name === cookie.name)?.expires).toBe(cookie.expires);
      }
    } finally { releaseLegacy(); }
  } finally {
    const closed = await Promise.allSettled(contexts.map(c => c.close()));
    for (const id of [modernUserId, legacyUserId]) {
      if (id) {
        await database.accountRecoveryRequest.deleteMany({ where: { userId: id } });
        await database.totpFactor.deleteMany({ where: { userId: id } });
      }
    }
    await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: { in: [modernEmail, legacyEmail] } } });
    if (modernUserId) await database.user.deleteMany({ where: { id: modernUserId, email: modernEmail } });
    if (legacyUserId) await database.user.deleteMany({ where: { id: legacyUserId, email: legacyEmail } });
    await database.$disconnect();
    expect(closed.every(r => r.status === "fulfilled")).toBe(true);
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
    await expect(fresh.page).toHaveURL(`${portalUrl}/recover?requestId=${legacy.id}&switch=1`);
    await expect(fresh.page.getByRole("button", { name: "Continuar com este link" })).toBeVisible();
    expect((await fresh.context.cookies(portalUrl)).find(cookie => cookie.name === names[0])?.value ?? "").toBe("");
    await fresh.page.getByRole("button", { name: "Continuar com este link" }).click();
    await expect.poll(async () => (await fresh.context.cookies(portalUrl)).find(cookie => cookie.name === names[0])?.value)
      .toBe(legacyKey);
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

for (const role of ["USER", "ADMIN"] as const) {
  test(`${role} two-tab delayed modern start cannot overwrite explicitly adopted legacy recovery`, async ({ browser }) => {
    test.setTimeout(150_000);
    const { fixture, database } = await requireFixture();
    const base = role === "USER" ? portalUrl : hubUrl;
    const modernEmail = `${randomUUID()}.lock-modern@e2e.invalid`;
    const legacyEmail = `${randomUUID()}.lock-legacy@e2e.invalid`;
    const legacyKey = randomBytes(24).toString("base64url");
    const primary = productionMode ? "__Host-virki_recovery" : "virki_recovery_v2";
    const candidateName = productionMode ? "__Host-virki_recovery_candidate" : "virki_recovery_candidate";
    let context: BrowserContext | undefined;
    let isolatedTransport: APIRequestContext | undefined;
    let modernUserId: string | undefined;
    let legacyUserId: string | undefined;
    let releaseStart = () => {};
    const heldStart = new Promise<void>(resolve => { releaseStart = resolve; });
    try {
      const [modern, legacyUser] = await Promise.all([
        database.user.create({ data: {
          email: modernEmail, emailNormalized: modernEmail, displayName: "Concurrent modern recovery fixture",
          passwordHash: await hashPassword(randomBytes(24).toString("base64url")), role,
          isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(), secondFactorMethod: "TOTP",
          totpFactor: { create: { secretCiphertext: encryptTotpSecret(createTotpSecret()), keyVersion: 1,
            status: "ACTIVE", confirmedAt: new Date() } }
        }, select: { id: true } }),
        database.user.create({ data: {
          email: legacyEmail, emailNormalized: legacyEmail, displayName: "Concurrent approved legacy fixture",
          passwordHash: await hashPassword(randomBytes(24).toString("base64url")), role,
          isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date()
        }, select: { id: true } })
      ]);
      modernUserId = modern.id;
      legacyUserId = legacyUser.id;
      const legacy = await database.accountRecoveryRequest.create({ data: {
        userId: legacyUserId, purpose: "RECOVERY", status: "APPROVED",
        requestKeyHash: hashRecoveryRequestKey(legacyKey), emailAddressHash: hashEmailAddress(legacyEmail),
        emailChallengeHash: hashSecurityCode("123456"), emailVerifiedAt: new Date(),
        approvedAt: new Date(), reviewedByUserId: fixture.recoveryReviewer.id,
        expiresAt: new Date(Date.now() + 25 * 60_000)
      }, select: { id: true, expiresAt: true, emailVerifiedAt: true, approvedAt: true } });

      // Per-page signed and independently validated Access assertions are
      // present before CDP captures the original browser POST. In particular,
      // this does not rely on a context.route handler that route.continue()
      // could bypass while testing the Hub.
      context = await browser.newContext();
      const startTab = await context.newPage();
      if (role === "ADMIN") await addCloudflareAccessHeader(startTab, { hubOnlyBrowserRedirects: true });
      await startTab.goto(`${base}/recover`);
      const switchTab = await context.newPage();
      if (role === "ADMIN") await addCloudflareAccessHeader(switchTab, { hubOnlyBrowserRedirects: true });
      await switchTab.goto(`${base}/recover/open?request=${encodeURIComponent(legacyKey)}`);
      await expect(switchTab).toHaveURL(`${base}/recover?requestId=${legacy.id}&switch=1`);
      await expect(switchTab.getByRole("button", { name: "Continuar com este link" })).toBeVisible();
      const before = await context.cookies(base);
      const candidate = before.find(cookie => cookie.name === candidateName);
      expect(candidate?.value).toBe(legacyKey);
      expect(before.some(cookie => cookie.name === primary && Boolean(cookie.value))).toBe(false);

      // A separate Playwright APIRequestContext holds server response bytes
      // without installing Set-Cookie in the shared two-tab browser context.
      // The browser itself still verifies TLS on every normal page navigation.
      isolatedTransport = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
      const cdp = await context.newCDPSession(startTab);
      let startInterceptions = 0;
      let backendStartReady = false;
      let pausedStatus = -1;
      let pausedRedirect = "none";
      let upstreamIssuedCookie = false;
      let upstreamModernKey = "";
      let interceptionFailure: string | undefined;
      await cdp.send("Fetch.enable", { patterns: [{ urlPattern: `${base}/recover*`, requestStage: "Request" }] });
      cdp.on("Fetch.requestPaused", async ({ requestId, request }) => {
        const actionHeader = Object.entries(request.headers).some(([name]) => name.toLowerCase() === "next-action");
        if (request.method !== "POST" || new URL(request.url).pathname !== "/recover" || !actionHeader) {
          await cdp.send("Fetch.continueRequest", { requestId });
          return;
        }
        startInterceptions += 1;
        try {
          const upstreamUrl = new URL(request.url);
          const host = upstreamUrl.host;
          upstreamUrl.hostname = "127.0.0.1";
          if (!request.postData) throw new Error("Chromium did not supply the multipart Server Action body at the request boundary");
          const originalAccess = Object.entries(request.headers)
            .find(([name]) => name.toLowerCase() === "cf-access-jwt-assertion")?.[1];
          if (role === "ADMIN" && (!originalAccess || originalAccess.split(".").length !== 3)) {
            throw new Error("The original Chromium ADMIN Server Action did not carry its signed Access assertion");
          }
          const response = await isolatedTransport!.post(upstreamUrl.href, {
            data: Buffer.from(request.postData, "utf8"),
            headers: { ...request.headers, host },
            maxRedirects: 0
          });
          pausedStatus = response.status();
          const responseHeaders = await response.headersArray();
          const issuedKey = responseHeaders.find(header => header.name.toLowerCase() === "set-cookie" &&
            header.value.startsWith(primary + "="));
          upstreamIssuedCookie = Boolean(issuedKey);
          upstreamModernKey = issuedKey?.value.slice(primary.length + 1).split(";")[0] ?? "";
          const redirect = response.headers()["x-action-redirect"];
          if (redirect) {
            const target = new URL(decodeURIComponent(redirect.split(";")[0] ?? ""), base);
            pausedRedirect = `${target.pathname}?${[...target.searchParams.keys()].join(",")}`;
          }
          const body = (await response.body()).toString("base64");
          backendStartReady = true;
          await heldStart;
          await cdp.send("Fetch.fulfillRequest", {
            requestId,
            responseCode: response.status(),
            responseHeaders: responseHeaders.filter(header => !["content-length", "content-encoding", "transfer-encoding", "connection"].includes(header.name.toLowerCase())),
            body
          });
        } catch (error) {
          interceptionFailure = error instanceof Error ? error.message : "unknown transport error";
          backendStartReady = true;
          await cdp.send("Fetch.failRequest", { requestId, errorReason: "Failed" }).catch(() => {});
        }
      });
      await startTab.getByLabel("E-mail da conta", { exact: true }).fill(modernEmail);
      await startTab.locator('input[name="method"][value="TOTP_EMAIL"]').check();
      const modernPost = startTab.waitForResponse(response => response.request().method() === "POST" &&
        new URL(response.url()).pathname === "/recover" && Boolean(response.request().headers()["next-action"]),
      { timeout: 25_000 });
      await startTab.getByRole("button", { name: "Solicitar recuperação", exact: true }).click({ noWaitAfter: true });
      await expect.poll(() => backendStartReady, { timeout: 20_000 }).toBe(true);
      expect(interceptionFailure, "real upstream transport must complete without a request/body or TLS error").toBeUndefined();
      expect(startInterceptions, "the genuine modern Server Action must be delayed exactly once").toBe(1);
      const createdModern = await database.accountRecoveryRequest.count({ where: { userId: modernUserId } });
      expect({ status: pausedStatus, redirect: pausedRedirect, persisted: createdModern },
        "backend must have completed a real modern start while Chromium response remains paused")
        .toEqual({ status: 200, redirect: "/recover?requestId", persisted: 1 });
      const issuedModern = await database.accountRecoveryRequest.findFirstOrThrow({
        where: { userId: modernUserId },
        select: { requestKeyHash: true, recoveryRole: true }
      });
      expect(issuedModern.recoveryRole, "upstream must persist the recovery under the actual Hub/Portal role").toBe(role);
      expect(issuedModern.requestKeyHash, "upstream Set-Cookie must match the genuine committed request")
        .toBe(hashRecoveryRequestKey(upstreamModernKey));
      const duringHold = await context.cookies(base);
      expect(duringHold.find(cookie => cookie.name === primary)?.value ?? "",
        "separate upstream transport must not install cookies in Chromium before fulfillment").toBe("");
      expect(duringHold.find(cookie => cookie.name === candidateName)?.value).toBe(legacyKey);

      let dispatchHadModernCookie = false;
      let dispatchHadModernBrowser = false;
      let dispatchHadModernIntent = false;
      await switchTab.route(/\/recover(?:\?.*)?$/u, async route => {
        if (route.request().method() === "POST" && route.request().headers()["next-action"]) {
          const atDispatch = await context!.cookies(base);
          const currentKey = atDispatch.find(cookie => cookie.name === primary)?.value;
          dispatchHadModernCookie = Boolean(currentKey && currentKey !== legacyKey);
          dispatchHadModernBrowser = atDispatch.some(cookie =>
            cookie.name === (productionMode ? "__Host-virki_recovery_browser" : "virki_recovery_browser") && Boolean(cookie.value));
          dispatchHadModernIntent = atDispatch.some(cookie =>
            cookie.name === (productionMode ? "__Host-virki_recovery_intent" : "virki_recovery_intent") && Boolean(cookie.value));
        }
        // A matching context route, if later introduced by the test harness,
        // must still get to install Access. route.continue() would skip it.
        await route.fallback();
      });
      const switchPost = switchTab.waitForResponse(response => response.request().method() === "POST" &&
        new URL(response.url()).pathname === "/recover" && Boolean(response.request().headers()["next-action"]),
      { timeout: 25_000 });
      let prematureSwitchPosts = 0;
      const observeSwitchPost = (request: import("@playwright/test").Request) => {
        if (request.method() === "POST" && new URL(request.url()).pathname === "/recover" &&
          Boolean(request.headers()["next-action"])) prematureSwitchPosts += 1;
      };
      switchTab.on("request", observeSwitchPost);
      await switchTab.getByRole("button", { name: "Continuar com este link" }).click({ noWaitAfter: true });
      let switchWasQueued = false;
      try {
        await expect.poll(() => switchTab.evaluate(async () =>
          (await navigator.locks.query()).pending?.filter(lock => lock.name === "virki-recovery-start-v1").length ?? 0),
        { timeout: 3_000 }).toBe(1);
        switchWasQueued = true;
      } catch {
        // The unpatched ancestor executes the switch immediately. Observe the
        // final cookie too so the RED demonstrates the real overwrite race.
      }
      const premature = prematureSwitchPosts;
      switchTab.off("request", observeSwitchPost);
      releaseStart();
      const [modernResponse, adoptedResponse] = await Promise.all([modernPost, switchPost]);
      expect(modernResponse.status()).toBeLessThan(400);
      expect(adoptedResponse.status()).toBeLessThan(400);
      expect(upstreamIssuedCookie, "the held real server response must issue a modern bearer").toBe(true);
      const finalCookies = await context.cookies(base);
      const adopted = finalCookies.find(cookie => cookie.name === primary);
      const lastCookieKind = adopted?.value === legacyKey ? "legacy" :
        adopted?.value && adopted.value === upstreamModernKey ? "late-modern-overwrite" :
        adopted?.value ? "unexpected-key" : "missing";
      expect(lastCookieKind,
        "the last Set-Cookie must be the explicitly adopted legacy key even after the modern response arrives")
        .toBe("legacy");
      expect({ primary: dispatchHadModernCookie, browser: dispatchHadModernBrowser, intent: dispatchHadModernIntent },
        "the modern bearer pair and intent must reach Chromium before the queued legacy switch POST")
        .toEqual({ primary: true, browser: true, intent: true });
      await expect.poll(async () => {
        const current = await context!.cookies(base);
        return current.find(cookie => cookie.name === primary)?.value === legacyKey;
      }, { timeout: 15_000 }).toBe(true);
      expect(switchWasQueued, "explicit switch must wait behind the in-flight modern start Web Lock").toBe(true);
      expect(premature, "no switch Server Action may run while the modern response is withheld").toBe(0);
      expect(adopted?.value).toBe(legacyKey);
      // The candidate is intentionally short-lived (at most ten minutes).
      // Explicit adoption restores the original approved DB expiry, never
      // extends it and never truncates it to the candidate's preview TTL.
      expect(Math.abs((adopted?.expires ?? 0) - legacy.expiresAt.getTime() / 1000),
        "adopted legacy bearer must retain the approved request's original expiry").toBeLessThan(2);
      expect(adopted!.expires).toBeGreaterThan(candidate!.expires);
      expect(finalCookies.find(cookie => cookie.name === candidateName)?.value ?? "").toBe("");
      const preserved = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: legacy.id } });
      expect(preserved.status).toBe("APPROVED");
      expect(preserved.emailVerifiedAt?.getTime()).toBe(legacy.emailVerifiedAt?.getTime());
      expect(preserved.approvedAt?.getTime()).toBe(legacy.approvedAt?.getTime());
      expect(preserved.expiresAt.getTime()).toBe(legacy.expiresAt.getTime());
      expect(await database.accountRecoveryRequest.count({ where: { userId: modernUserId } })).toBe(1);
      await expect(switchTab.getByLabel("Nova senha", { exact: true }),
        "the adopted APPROVED legacy key must still show the authentic password-reset step").toBeVisible();
    } finally {
      releaseStart();
      if (context) await context.close();
      if (isolatedTransport) await isolatedTransport.dispose();
      for (const id of [modernUserId, legacyUserId]) {
        if (id) {
          await database.accountRecoveryRequest.deleteMany({ where: { userId: id } });
          await database.totpFactor.deleteMany({ where: { userId: id } });
        }
      }
      await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: { in: [modernEmail, legacyEmail] } } });
      if (modernUserId) await database.user.deleteMany({ where: { id: modernUserId, email: modernEmail } });
      if (legacyUserId) await database.user.deleteMany({ where: { id: legacyUserId, email: legacyEmail } });
      await database.$disconnect();
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
  test.setTimeout(70_000);
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
    // Synthetic capabilities have no independent proven factor. With the
    // requestId URL lost, read-only resume MUST NOT manufacture a valid ID,
    // alter bearer cookies, or switch to the public USER surface.
    await hub.page.goto(hubUrl + "/recover");
    await hub.page.getByRole("button", { name: "Retomar recuperação anterior", exact: true }).click();
    await expect(hub.page).toHaveURL(hubUrl + "/recover?restart=1");
    await expect(hub.page.getByRole("heading", { name: "Recuperar acesso administrativo" })).toBeVisible();
    for (const prior of hubOriginalCookies) {
      expect((await hub.context.cookies(hubUrl)).find(cookie => cookie.name === prior.name)?.value)
        .toBe(prior.value);
    }
    await hub.page.goto(hubUrl + "/recover");
    await hub.page.getByLabel("E-mail da conta", { exact: true }).fill(randomUUID() + "@e2e.invalid");
    await hub.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await hub.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    await expect(hub.page).toHaveURL(hubUrl + "/recover?restart=1");
    await expect(hub.page.getByRole("heading", { name: "Recuperar acesso administrativo" }))
      .toBeVisible();
    expect(await hub.page.evaluate(async () => {
      const api = navigator.locks;
      if (!api?.request) return { supported: false, held: -1, pending: -1 };
      const active = await api.query();
      return {
        supported: true,
        held: active.held?.filter(lock => lock.name === "virki-recovery-start-v1").length ?? 0,
        pending: active.pending?.filter(lock => lock.name === "virki-recovery-start-v1").length ?? 0
      };
    }), "after full Hub document navigation the prior form lock must be released")
      .toEqual({ supported: true, held: 0, pending: 0 });
    for (const prior of hubOriginalCookies) {
      expect((await hub.context.cookies(hubUrl)).find((cookie) => cookie.name === prior.name)?.value)
        .toBe(prior.value);
    }
    await hub.page.getByLabel("E-mail da conta", { exact: true }).fill(randomUUID() + "@e2e.invalid");
    await hub.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await hub.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u }).check();
    expect(await hub.page.evaluate(() => {
      const input = document.querySelector<HTMLInputElement>('input[name="confirmRecoveryRestart"]');
      return {
        checked: input?.checked === true,
        actualFormDataYes: input?.form ? new FormData(input.form).get("confirmRecoveryRestart") === "yes" : false
      };
    })).toEqual({ checked: true, actualFormDataYes: true });
    // The literal method suffix must authorize the acknowledged restart by
    // itself: React can omit the separate checkbox field in an Action payload.
    // Strip affirmative multipart consent while preserving method, CSRF and
    // the real Hub/Access request, then prove the server rotates both bearers.
    let interceptedConsent = 0;
    let suffixOnWire = false;
    let originalAffirmativeField = false;
    let noConfirmationFieldOnWire = false;
    const consentHandler = async (route: Route) => {
      // Let the existing context handler attach the independently signed
      // Cloudflare Access header after our wire mutation.
      if (route.request().method() !== "POST") return route.fallback();
      interceptedConsent += 1;
      const original = route.request().postData() ?? "";
      suffixOnWire = /name="(?:_\d+_)?method"\r?\n\r?\nTOTP_EMAIL:confirm-restart(?:\r?\n|$)/u.test(original);
      originalAffirmativeField = /name="(?:_\d+_)?confirmRecoveryRestart"\r?\n\r?\nyes(?:\r?\n|$)/u.test(original);
      const stripped = original.replace(/name="(?:_\d+_)?confirmRecoveryRestart"(?=\r?\n)/gu,
        'name="ignoredConsentProbe"');
      noConfirmationFieldOnWire = !/name="(?:_\d+_)?confirmRecoveryRestart"(?=\r?\n)/u.test(stripped);
      await route.fallback({ postData: stripped });
    };
    await hub.page.route(/\/recover(?:\?.*)?$/u, consentHandler);
    let submitted: Response;
    try {
      const consentPost = hub.page.waitForResponse((response) => response.request().method() === "POST" &&
        new URL(response.url()).pathname === "/recover", { timeout: 15_000 });
      await hub.page.getByRole("button", { name: "Solicitar recuperação", exact: true })
        .click({ noWaitAfter: true });
      submitted = await consentPost;
    } finally {
      await hub.page.unroute(/\/recover(?:\?.*)?$/u, consentHandler);
    }
    expect(interceptedConsent, "the real ADMIN start POST must be intercepted exactly once").toBe(1);
    expect(suffixOnWire, "the selected method carries affirmative restart consent").toBe(true);
    expect(originalAffirmativeField, "the original multipart POST includes the checkbox acknowledgement").toBe(true);
    expect(noConfirmationFieldOnWire, "the server sees no multipart checkbox field, even by presence").toBe(true);
    expect(submitted.status(), "same-surface ADMIN restart must not be rejected by host/CSRF/Access")
      .toBeLessThan(400);
    const postedBody = submitted.request().postDataBuffer()?.toString("utf8") ?? "";
    expect(/name="(?:_\d+_)?method"\r?\n\r?\nTOTP_EMAIL:confirm-restart(?:\r?\n|$)/u.test(postedBody),
      "real ADMIN Server Action must receive the explicit method consent suffix").toBe(true);
    const redirectHeader = submitted.headers()["x-action-redirect"] ?? submitted.headers()["location"] ?? "";
    const redirectTarget = new URL(decodeURIComponent(redirectHeader.split(";")[0] ?? ""), hubUrl);
    expect({ path: redirectTarget.pathname, queryKeys: [...redirectTarget.searchParams.keys()] },
      "ADMIN restart must reach the real positive Server Action redirect").toEqual({ path: "/recover", queryKeys: ["requestId"] });
    const afterConsent = await hub.context.cookies(hubUrl);
    const changedByAction = hubOriginalCookies.filter(cookie => !cookie.name.includes("intent"))
      .every(cookie => {
        const current = afterConsent.find(next => next.name === cookie.name);
        return Boolean(current?.value && current.value !== cookie.value);
      });
    expect(changedByAction,
      "consent action must replace both opaque cookies before testing its navigation").toBe(true);
    // Report only query PARAMETER NAMES on failure; never leak IDs, cookies, CSRF
    // or recovery capabilities into runner output or CI failure logs.
    await expect.poll(() => [...new URL(hub.page.url()).searchParams.keys()].sort().join(","),
      { timeout: 10_000 }).toBe("requestId");
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

for (const role of ["USER", "ADMIN"] as const) {
  test(`${role} approved legacy key-only remains usable after unconsented modern POST`, async ({ browser }) => {
    test.setTimeout(120_000);
    const { fixture, database } = await requireFixture();
    const email = `legacy-keyonly-${role.toLowerCase()}-${randomUUID()}@e2e.invalid`;
    const origin = role === "ADMIN" ? hubUrl : portalUrl;
    const key = randomBytes(24).toString("base64url");
    const cookieName = productionMode ? "__Host-virki_recovery" : "virki_recovery_v2";
    const newPassword = `recovered-legacy-${randomUUID()}-secure-password`;
    let userId: string | undefined;
    let context: BrowserContext | undefined;
    try {
      const owner = await database.user.create({ data: {
        email, emailNormalized: email, displayName: "Legacy key-only browser fixture",
        role, passwordHash: await hashPassword(randomBytes(32).toString("base64url")),
        isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
        secondFactorMethod: "EMAIL"
      }, select: { id: true } });
      userId = owner.id;
      const approved = await database.accountRecoveryRequest.create({ data: {
        userId, status: "APPROVED", purpose: "RECOVERY",
        requestKeyHash: hashRecoveryRequestKey(key), emailAddressHash: hashEmailAddress(email),
        emailChallengeHash: hashSecurityCode("123456"), emailVerifiedAt: new Date(),
        approvedAt: new Date(), reviewedByUserId: fixture.recoveryReviewer.id,
        expiresAt: new Date(Date.now() + 25 * 60_000)
      }, select: { id: true, status: true, requestKeyHash: true, expiresAt: true } });
      const active = await openRecovery(browser, role === "ADMIN" ? "hub" : "portal");
      context = active.context;
      await active.page.goto(`${origin}/recover/open?request=${encodeURIComponent(key)}`);
      await active.page.getByRole("button", { name: "Continuar com este link" }).click();
      await expect.poll(async () => (await context!.cookies(origin))
        .find(cookie => cookie.name === cookieName)?.value).toBe(key);
      const before = (await context.cookies(origin)).find(cookie => cookie.name === cookieName)!;
      expect((await context.cookies(origin)).find(cookie => cookie.name.includes("recovery_browser"))?.value ?? "").toBe("");
      await active.page.goto(`${origin}/recover`);
      await expect(active.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u })).toBeVisible();
      await active.page.getByRole("button", { name: "Retomar recuperação anterior" }).click();
      await expect(active.page).toHaveURL(`${origin}/recover?requestId=${approved.id}`);
      expect((await context.cookies(origin)).find(cookie => cookie.name === cookieName)?.value === before.value).toBe(true);
      await active.page.goto(`${origin}/recover`);
      await active.page.getByLabel("E-mail da conta", { exact: true }).fill(email);
      await active.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
      if (role === "ADMIN") await addCloudflareAccessHeader(active.page, { hubOnlyBrowserRedirects: true });
      // The fixed UI requires an explicit checkbox, but this test deliberately
      // sends an actual Next Server Action POST with consent removed on the wire.
      const checkbox = active.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u });
      if (await checkbox.count()) await checkbox.check();
      let posts = 0;
      let genuineNextAction = false;
      let noConsentOnWire = false;
      let redirectPath = "";
      const intercepted = async (route: Route) => {
        if (route.request().method() !== "POST") return route.continue();
        posts += 1;
        const originalBody = route.request().postData() ?? "";
        genuineNextAction = Boolean(route.request().headers()["next-action"]) &&
          originalBody.includes("TOTP_EMAIL");
        const withoutSuffix = originalBody.replace("TOTP_EMAIL:confirm-restart", "TOTP_EMAIL");
        const stripped = withoutSuffix.replace(/(name="(?:_\d+_)?confirmRecoveryRestart"\r?\n\r?\n)yes(?=\r?\n)/gu, "$1no");
        noConsentOnWire = !stripped.includes("TOTP_EMAIL:confirm-restart") &&
          !/name="(?:_\d+_)?confirmRecoveryRestart"\r?\n\r?\nyes(?:\r?\n|$)/u.test(stripped);
        await route.continue({ postData: stripped });
      };
      await active.page.route(/\/recover(?:\?.*)?$/u, intercepted);
      try {
        const pendingPost = active.page.waitForResponse(response =>
          response.request().method() === "POST" && new URL(response.url()).pathname === "/recover");
        await active.page.getByRole("button", { name: "Solicitar recuperação" }).click({ noWaitAfter: true });
        const response = await pendingPost;
        expect(response.status()).toBeLessThan(400);
        redirectPath = decodeURIComponent((response.headers()["x-action-redirect"] ??
          response.headers().location ?? "").split(";")[0] ?? "");
      } finally {
        await active.page.unroute(/\/recover(?:\?.*)?$/u, intercepted);
      }
      expect(posts, "must reach real selected Next start action").toBe(1);
      expect(genuineNextAction, "must not accidentally test a resume action").toBe(true);
      expect(noConsentOnWire, "both method suffix and multipart checkbox must be absent").toBe(true);
      const after = (await context.cookies(origin)).find(cookie => cookie.name === cookieName);
      expect(after?.value === before.value, "an unconsented start must not replace adopted legacy key").toBe(true);
      expect(after?.expires, "unconsented start must not extend legacy TTL").toBe(before.expires);
      expect(["/recover?restart=1", `/recover?requestId=${approved.id}`]).toContain(redirectPath);
      expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: approved.id },
        select: { id: true, status: true, requestKeyHash: true, expiresAt: true } })).toEqual(approved);
      expect(await database.accountRecoveryRequest.count({ where: { userId } })).toBe(1);
      await active.page.goto(`${origin}/recover?requestId=${encodeURIComponent(approved.id)}`);
      await expect(active.page.getByLabel("Nova senha", { exact: true })).toBeVisible();
      await active.page.getByLabel("Nova senha", { exact: true }).fill(newPassword);
      await active.page.getByRole("button", { name: "Concluir recuperação" }).click();
      await expect(active.page).toHaveURL(`${origin}/login?recovered=1`);
      expect((await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: approved.id } })).status).toBe("CONSUMED");
      expect(await verifyPassword((await database.user.findUniqueOrThrow({ where: { id: userId } })).passwordHash ?? "",
        newPassword)).toBe(true);
    } finally {
      await context?.close();
      if (userId) {
        await database.session.deleteMany({ where: { userId } });
        await database.accountRecoveryRequest.deleteMany({ where: { userId } });
        await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: email } });
        await database.user.deleteMany({ where: { id: userId, email } });
      }
      await database.$disconnect();
    }
  });
}

for (const role of ["USER", "ADMIN"] as const) {
  test(`${role} expired legacy key-only rotates to a real enrolled recovery with explicit consent`, async ({ browser }) => {
    test.setTimeout(120_000);
    const { database } = await requireFixture();
    const email = `legacy-expired-${role.toLowerCase()}-${randomUUID()}@e2e.invalid`;
    const origin = role === "ADMIN" ? hubUrl : portalUrl;
    const cookieName = productionMode ? "__Host-virki_recovery" : "virki_recovery_v2";
    const staleKey = randomBytes(24).toString("base64url");
    let userId: string | undefined;
    let context: BrowserContext | undefined;
    try {
      const secret = createTotpSecret();
      const owner = await database.user.create({ data: {
        email, emailNormalized: email, displayName: "Expired legacy positive rotation E2E",
        role, passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
        isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
        secondFactorMethod: "TOTP",
        totpFactor: { create: {
          secretCiphertext: encryptTotpSecret(secret), keyVersion: 1,
          status: "ACTIVE", confirmedAt: new Date()
        } }
      }, select: { id: true } });
      userId = owner.id;
      const expired = await database.accountRecoveryRequest.create({ data: {
        userId, purpose: "RECOVERY", status: "EXPIRED",
        requestKeyHash: hashRecoveryRequestKey(staleKey),
        emailAddressHash: hashEmailAddress(email), emailChallengeHash: hashSecurityCode("123456"),
        createdAt: new Date(Date.now() - 120_000), expiresAt: new Date(Date.now() - 60_000)
      }, select: { id: true, status: true, requestKeyHash: true, expiresAt: true } });
      const active = await openRecovery(browser, role === "ADMIN" ? "hub" : "portal");
      context = active.context;
      await context.addCookies([{ name: cookieName, value: staleKey, url: `${origin}/`,
        httpOnly: true, secure: productionMode, sameSite: "Lax",
        expires: Math.floor(Date.now() / 1000) + 600 }]);
      await active.page.goto(`${origin}/recover`);
      await expect(active.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u })).toBeVisible();
      await active.page.getByLabel("E-mail da conta", { exact: true }).fill(email);
      await active.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
      await active.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u }).check();
      const sent = active.page.waitForResponse(response =>
        response.request().method() === "POST" && new URL(response.url()).pathname === "/recover");
      await active.page.getByRole("button", { name: "Solicitar recuperação" }).click();
      const post = await sent;
      expect(post.status()).toBeLessThan(400);
      expect(post.request().headers()["next-action"]).toBeTruthy();
      expect((post.request().postData() ?? "").includes("TOTP_EMAIL:confirm-restart"),
        "the actual start POST must carry explicit user consent").toBe(true);
      await expect(active.page).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]+$/u);
      const newRequestId = new URL(active.page.url()).searchParams.get("requestId")!;
      expect(newRequestId).not.toBe(expired.id);
      const current = (await context.cookies(origin)).find(cookie => cookie.name === cookieName);
      expect(Boolean(current?.value && current.value !== staleKey),
        "affirmative abandonment of an expired key must mint a fresh bearer").toBe(true);
      expect((await context.cookies(origin)).find(cookie => cookie.name.includes("recovery_browser"))?.value).toBeTruthy();
      const created = await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: newRequestId } });
      expect(created.userId).toBe(userId);
      expect(created.recoveryRole).toBe(role);
      expect(created.status).toBe("PENDING");
      expect(created.recoveryProofs).toEqual(["EMAIL", "TOTP"]);
      expect(created.requestKeyHash).toBe(hashRecoveryRequestKey(current!.value));
      expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: expired.id },
        select: { id: true, status: true, requestKeyHash: true, expiresAt: true } })).toEqual(expired);
    } finally {
      await context?.close();
      if (userId) {
        await database.session.deleteMany({ where: { userId } });
        await database.accountRecoveryRequest.deleteMany({ where: { userId } });
        await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: email } });
        await database.totpFactor.deleteMany({ where: { userId } });
        await database.user.deleteMany({ where: { id: userId, email } });
      }
      await database.$disconnect();
    }
  });
}

// Explicit restart consent must not discard a legacy link whose email proof
// or independent approval is already complete. Unlike a no-consent test, this
// enters the retainedLegacyId branch; deleting that guard MUST make it RED.
for (const role of ["USER", "ADMIN"] as const) {
  for (const legacyStatus of ["APPROVED", "PENDING"] as const) {
    test(`${role} ${legacyStatus} verified legacy key-only survives explicit modern restart consent`, async ({ browser }) => {
      test.setTimeout(120_000);
      const { fixture, database } = await requireFixture();
      const email = `legacy-consent-${role.toLowerCase()}-${randomUUID()}@e2e.invalid`;
      const origin = role === "ADMIN" ? hubUrl : portalUrl;
      const cookieName = productionMode ? "__Host-virki_recovery" : "virki_recovery_v2";
      const key = randomBytes(24).toString("base64url");
      let userId: string | undefined;
      let context: BrowserContext | undefined;
      try {
        const totp = createTotpSecret();
        const owner = await database.user.create({ data: {
          email, emailNormalized: email, displayName: "Verified legacy consent retention fixture",
          role, passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
          isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
          secondFactorMethod: "TOTP",
          totpFactor: { create: {
            secretCiphertext: encryptTotpSecret(totp), keyVersion: 1,
            status: "ACTIVE", confirmedAt: new Date()
          } }
        }, select: { id: true } });
        userId = owner.id;
        const original = await database.accountRecoveryRequest.create({ data: {
          userId, status: legacyStatus, purpose: "RECOVERY",
          requestKeyHash: hashRecoveryRequestKey(key), emailAddressHash: hashEmailAddress(email),
          emailChallengeHash: hashSecurityCode("123456"), emailVerifiedAt: new Date(),
          ...(legacyStatus === "APPROVED" ? {
            approvedAt: new Date(), reviewedByUserId: fixture.recoveryReviewer.id
          } : {}),
          expiresAt: new Date(Date.now() + 25 * 60_000)
        }, select: { id: true, status: true, requestKeyHash: true, expiresAt: true, emailVerifiedAt: true } });
        const active = await openRecovery(browser, role === "ADMIN" ? "hub" : "portal");
        context = active.context;
        await active.page.goto(`${origin}/recover/open?request=${encodeURIComponent(key)}`);
        await active.page.getByRole("button", { name: "Continuar com este link" }).click();
        await expect.poll(async () => (await context!.cookies(origin))
          .find(cookie => cookie.name === cookieName)?.value === key).toBe(true);
        const before = (await context.cookies(origin)).find(cookie => cookie.name === cookieName)!;
        expect((await context.cookies(origin)).some(cookie => cookie.name.includes("recovery_browser"))).toBe(false);
        await active.page.goto(`${origin}/recover`);
        await expect(active.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u })).toBeVisible();
        await active.page.getByLabel("E-mail da conta", { exact: true }).fill(email);
        await active.page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
        await active.page.getByRole("checkbox", { name: /Confirmo que quero substituir/u }).check();
        if (role === "ADMIN") await addCloudflareAccessHeader(active.page, { hubOnlyBrowserRedirects: true });

        const postPromise = active.page.waitForResponse(response =>
          response.request().method() === "POST" && new URL(response.url()).pathname === "/recover");
        await active.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click({ noWaitAfter: true });
        const response = await postPromise;
        const postedBody = response.request().postData() ?? "";
        expect(response.status(), "real Next action passed CSRF/role/Access").toBeLessThan(400);
        expect(Boolean(response.request().headers()["next-action"]), "must be a genuine Next action").toBe(true);
        expect(/name="(?:_\d+_)?method"\r?\n\r?\nTOTP_EMAIL:confirm-restart(?:\r?\n|$)/u.test(postedBody),
          "the real start action must receive explicit method-suffix consent").toBe(true);
        const redirected = decodeURIComponent((response.headers()["x-action-redirect"] ??
          response.headers().location ?? "").split(";")[0] ?? "");
        expect(redirected === `/recover?requestId=${original.id}`,
          "affirmative consent must redirect to the verified legacy request").toBe(true);
        const issued = (await response.headersArray()).filter(header =>
          header.name.toLowerCase() === "set-cookie" &&
          /^(?:__Host-virki_recovery(?:_browser|_intent)?|virki_recovery_(?:v2|browser|intent))=/u.test(header.value));
        expect(issued, "retention must not rewrite primary/browser/intent cookies").toHaveLength(0);
        await expect.poll(() => active.page.url() === `${origin}/recover?requestId=${original.id}`).toBe(true);
        const after = (await context.cookies(origin)).find(cookie => cookie.name === cookieName);
        expect(after?.value === before.value, "retention must preserve the original legacy bearer").toBe(true);
        expect(after?.expires, "retention must preserve the original cookie expiry").toBe(before.expires);
        expect((await context.cookies(origin)).some(cookie => cookie.name.includes("recovery_browser")),
          "retention must not mint a modern browser bearer").toBe(false);
        expect(await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: original.id },
          select: { id: true, status: true, requestKeyHash: true, expiresAt: true, emailVerifiedAt: true } })).toEqual(original);
        expect(await database.accountRecoveryRequest.count({ where: { userId } }),
          "verified legacy recovery must not create another owner request").toBe(1);
        expect(await database.emailOutboxMessage.count({ where: { recipientEmail: email } }),
          "verified legacy recovery must not enqueue another owner email").toBe(0);
      } finally {
        await context?.close();
        if (userId) {
          await database.session.deleteMany({ where: { userId } });
          await database.accountRecoveryRequest.deleteMany({ where: { userId } });
          await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: email } });
          await database.totpFactor.deleteMany({ where: { userId } });
          await database.user.deleteMany({ where: { id: userId, email } });
        }
        await database.$disconnect();
      }
    });
  }
}
