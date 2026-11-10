import { randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { PrismaClient } from "@virki/database";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

// @ts-expect-error The shared safety guard is intentionally a JavaScript module.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const hub = "https://hub.localhost:3001";
const dbUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixtureFile = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();
const enabled = process.env.VIRKI_E2E_PASSKEYS === "true" &&
  process.env.VIRKI_E2E_ADMIN_PASSKEYS === "true" &&
  process.env.VIRKI_E2E_HUB_MODE !== "production";
// Explicitly enabling privileged passkeys makes this test a mandatory gate:
// absent browser/DB fixtures must FAIL, not silently count as a SKIP. Operators
// can also demand the gate without pre-enabling it through REQUIRE_ADMIN_PASSKEYS.
const mandatory = process.env.VIRKI_E2E_ADMIN_PASSKEYS === "true" ||
  process.env.VIRKI_E2E_REQUIRE_ADMIN_PASSKEYS === "true";

// Running playwright --list must never launch web servers, use an existing DB,
// install browser trust, or mutate Cloudflare/SMTP. The normal harness owns its
// per-run TLS trust and private DB only when physical execution is authorized.
test.skip(!mandatory && (!enabled || !dbUrl || !fixtureFile || !existsSync(fixtureFile)),
  "ADMIN passkey browser E2E is opt-in; an explicit ADMIN passkey/required gate may never SKIP.");

type Reviewer = { id: string; email: string; password: string; administrativePassword: string };
type Owner = { id: string; email: string; password: string; administrativePassword: string };
type OwnedSession = { id: string; token: string };

async function requireHarness(): Promise<{ db: PrismaClient; reviewer: Reviewer }> {
  if (!enabled || !dbUrl || !fixtureFile || process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("Explicit ADMIN passkey flags and disposable E2E database are mandatory.");
  }
  if (process.env.NODE_ENV === "production" || process.env.VIRKI_E2E_HUB_MODE === "production") {
    throw new Error("ADMIN passkey E2E cannot run against production-mode Hub.");
  }
  assertDisposableCoreTestDatabase(dbUrl, process.env);
  const target = new URL(dbUrl);
  if (target.pathname !== "/virki_e2e_test" || !["127.0.0.1", "localhost", "postgres", "core-test-postgres"].includes(target.hostname)) {
    throw new Error("ADMIN passkey E2E requires the exact disposable harness database.");
  }
  const value: unknown = JSON.parse(await readFile(fixtureFile, "utf8"));
  if (!value || typeof value !== "object") throw new Error("Missing authenticated E2E fixture.");
  const reviewer = (value as { recoveryReviewer?: Reviewer }).recoveryReviewer;
  if (!reviewer || typeof reviewer.id !== "string" || typeof reviewer.email !== "string" ||
      typeof reviewer.password !== "string" || typeof reviewer.administrativePassword !== "string") {
    throw new Error("A distinct real ADMIN reviewer fixture is mandatory.");
  }
  return { db: new PrismaClient({ datasources: { db: { url: dbUrl } } }), reviewer };
}

async function createOwner(db: PrismaClient): Promise<Owner> {
  const password = randomBytes(32).toString("base64url");
  const administrativePassword = randomBytes(32).toString("base64url");
  const email = `owned-admin-passkey-${randomUUID()}@e2e.invalid`;
  const owner = await db.user.create({ data: {
    email, emailNormalized: email, displayName: "Owned browser passkey recovery ADMIN", role: "ADMIN",
    accountStatus: "ACTIVE", isActive: true, emailVerifiedAt: new Date(),
    passwordHash: await hashPassword(password), secondFactorMethod: "EMAIL",
    administrativeCredential: { create: { status: "ACTIVE", passwordHash: await hashPassword(administrativePassword) } }
  }, select: { id: true } });
  return { id: owner.id, email, password, administrativePassword };
}

async function attachSession(context: BrowserContext, db: PrismaClient, actorId: string): Promise<OwnedSession> {
  const token = randomBytes(32).toString("base64url");
  const session = await db.session.create({ data: {
    userId: actorId, tokenHash: hashSessionToken(token),
    expiresAt: new Date(Date.now() + 30 * 60_000), authenticationMethods: ["pwd", "otp", "mfa"]
  } });
  await context.addCookies([{ name: getSessionCookieName({ NODE_ENV: "development" }), value: token,
    url: hub, httpOnly: true, secure: true, sameSite: "Lax" }]);
  return { id: session.id, token };
}

async function latestCode(db: PrismaClient, email: string, kind: string, key?: string): Promise<string> {
  const message = await db.emailOutboxMessage.findFirst({
    where: { recipientEmail: email, kind: kind as "ADMIN_EMAIL_VERIFICATION", ...(key ? { idempotencyKey: `admin-elevation:${key}` } : {}) },
    orderBy: { createdAt: "desc" }, select: { payload: true }
  });
  const code = message && decryptEmailPayload(message.payload).code;
  expect(code, `test-only outbox must contain a ${kind} code`).toMatch(/^\d{6}$/u);
  return code!;
}

async function elevateWithUi(page: Page, db: PrismaClient, actor: Reviewer | Owner, scope: "ADMIN_CREDENTIAL_CHANGE" | "ACCOUNT_STATE_CHANGE") {
  const section = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Elevação temporária", exact: true }) });
  const start = section.locator("form").first();
  await start.locator('select[name="scope"]').selectOption(scope);
  await start.getByLabel("Senha normal atual", { exact: true }).fill(actor.password);
  await start.getByLabel("Senha administrativa", { exact: true }).fill(actor.administrativePassword);
  await start.getByRole("button", { name: "Solicitar elevação", exact: true }).click();
  const verify = section.locator("form").nth(1);
  await expect(verify.getByLabel("Código", { exact: true })).toBeVisible();
  const requestKey = await verify.locator('input[name="requestKey"]').inputValue();
  await verify.getByLabel("Código", { exact: true }).fill(await latestCode(db, actor.email, "ADMIN_EMAIL_VERIFICATION", requestKey));
  await verify.getByRole("button", { name: "Ativar elevação", exact: true }).click();
  await expect(page).toHaveURL(`${hub}/admin/security?status=elevation#admin-content`);
  await expect(page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Elevação temporária", exact: true }) })
    .locator("article.list-row").filter({ hasText: scope === "ADMIN_CREDENTIAL_CHANGE" ? "Alterar credencial administrativa" : "Alterar contas" })).toBeVisible();
}

async function newHubContext(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await addCloudflareAccessHeader(page); // Signed JWKS test principal, no real Cloudflare traffic.
    return { context, page };
  } catch (error) { await context.close(); throw error; }
}

async function installVirtualAuthenticator(context: BrowserContext, page: Page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true
  } });
  return async () => {
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => undefined);
    await cdp.detach().catch(() => undefined);
  };
}

async function registerOwnedHubPasskey(page: Page, db: PrismaClient, owner: Owner) {
  await page.goto(`${hub}/admin/security`);
  await expect(page.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
  const manager = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: /^Passkeys/ }) });
  await expect(manager).toBeVisible();
  const optionsResponse = () => page.waitForResponse(response =>
    new URL(response.url()).pathname === "/api/passkeys" &&
    response.request().method() === "POST" &&
    response.request().postDataJSON()?.action === "admin-register-options",
  { timeout: 10_000 });
  const add = manager.getByRole("button", { name: "Adicionar passkey", exact: true });
  await expect(add).toBeDisabled();
  // This disposable ADMIN deliberately uses EMAIL, so the Hub must not render
  // a TOTP field. TOTP-backed owners must supply their real current code.
  expect(await db.user.findUniqueOrThrow({ where: { id: owner.id }, select: { secondFactorMethod: true } }))
    .toMatchObject({ secondFactorMethod: "EMAIL" });
  await expect(manager.getByLabel("Código atual do aplicativo autenticador")).toHaveCount(0);
  // Password alone is not enough without a recently activated, separately
  // confirmed administrative elevation. The browser calls the actual API.
  await fillEnabledEnrollmentForm(manager, owner.password);
  const deniedOptions = optionsResponse();
  await add.click({ timeout: 6_000 });
  expect((await deniedOptions).status(), "an ADMIN without a fresh elevation must be rejected by the API").toBe(403);
  await expect(manager.getByRole("alert")).toContainText("Não foi possível confirmar a alteração");
  expect(await db.passkeyCredential.count({ where: { userId: owner.id } })).toBe(0);

  await elevateWithUi(page, db, owner, "ADMIN_CREDENTIAL_CHANGE");
  // The elevation action navigates back to this page. A full document reload
  // mounts a fresh controlled form after the rejected registration attempt;
  // otherwise App Router can preserve stale client state across the action.
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
  const renewed = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: /^Passkeys/ }) });
  const renewedAdd = renewed.getByRole("button", { name: "Adicionar passkey", exact: true });
  await expect(renewed).toBeVisible();
  await expect(renewedAdd).toBeDisabled();
  await expect(renewed.getByLabel("Código atual do aplicativo autenticador")).toHaveCount(0);
  await fillEnabledEnrollmentForm(renewed, owner.password);
  const acceptedOptions = optionsResponse();
  await renewedAdd.click({ timeout: 6_000 });
  expect((await acceptedOptions).status(), "enrollment must reach the real server and start WebAuthn").toBe(200);
  await expect(page.getByText("Owned Chromium ADMIN factor", { exact: true })).toBeVisible({ timeout: 30_000 });
  const rows = await db.passkeyCredential.findMany({ where: { userId: owner.id, revokedAt: null } });
  expect(rows).toHaveLength(1);
  expect(rows[0]!.rpID).toBe("hub.localhost");
  expect(rows[0]!.credentialId.length).toBeGreaterThan(16);
  return rows[0]!;
}

async function fillEnabledEnrollmentForm(manager: ReturnType<Page["locator"]>, password: string) {
  const passwordInput = manager.getByLabel("Senha atual para autorizar alterações");
  const nameInput = manager.getByLabel("Nome da passkey");
  const add = manager.getByRole("button", { name: "Adicionar passkey", exact: true });
  // After the elevation Server Action, the HTML may arrive before React
  // hydrates. Filling that pre-hydration DOM does not update controlled state.
  // Retry real form input until React enables its own button, with a short gate.
  await expect.poll(async () => {
    await passwordInput.fill(password, { timeout: 3_000 });
    await nameInput.fill("Owned Chromium ADMIN factor", { timeout: 3_000 });
    return (await passwordInput.inputValue()) === password &&
      (await nameInput.inputValue()) === "Owned Chromium ADMIN factor" &&
      await add.isEnabled();
  }, { message: "React-controlled ADMIN enrollment fields must enable the real button", timeout: 6_000,
    intervals: [100, 250, 500] }).toBe(true);
}

async function startPasskeyAdminRecovery(page: Page, email: string) {
  await page.goto(`${hub}/recover`);
  await expect(page.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo" })).toBeVisible();
  await expect(page.locator('input[name="method"][value="PASSKEY_ADMIN"]')).toBeVisible();
  await page.getByLabel("E-mail da conta", { exact: true }).fill(email);
  await page.locator('input[name="method"][value="PASSKEY_ADMIN"]').check();
  const post = page.waitForResponse(response => new URL(response.url()).pathname === "/recover" &&
    response.request().method() === "POST" && Boolean(response.request().headers()["next-action"]));
  await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
  const headers = await (await post).headersArray();
  for (const name of ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"]) {
    const header = headers.find(item => item.name.toLowerCase() === "set-cookie" && item.value.startsWith(`${name}=`));
    expect(header, `the Next action must mint the ${name} capability`).toBeDefined();
    expect(/(?:^|;)\s*Domain=/iu.test(header!.value), "Hub recovery cookies must be host-only").toBe(false);
  }
  await expect(page).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]{43}$/u);
  const requestId = new URL(page.url()).searchParams.get("requestId") ?? "";
  expect(requestId).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  return requestId;
}

// Compare user-visible content and controls only. The known and synthetic
// ceremonies intentionally have different opaque request IDs and CSRF tokens.
async function publicRecoveryView(page: Page) {
  const main = page.locator("main.auth-page");
  await expect(main).toBeVisible();
  return {
    text: (await main.innerText()).replace(/\s+/gu, " ").trim(),
    buttons: (await main.locator("button:visible").allTextContents()).map(value => value.trim()),
    links: (await main.locator("a:visible").allTextContents()).map(value => value.trim()),
    inputs: await main.locator('input:not([type="hidden"]):visible').evaluateAll(inputs =>
      inputs.map(input => ({
        name: (input as HTMLInputElement).name,
        type: (input as HTMLInputElement).type,
        label: input.closest("label")?.textContent?.trim() ?? ""
      })))
  };
}

function assertRecoveryCookies(cookies: Awaited<ReturnType<BrowserContext["cookies"]>>, id: string) {
  for (const name of ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"]) {
    const cookie = cookies.find(item => item.name === name);
    expect(cookie, `${name} must be scoped to its issuing Hub`).toBeDefined();
    expect(cookie!.domain).toBe("hub.localhost");
    expect(cookie!.path).toBe("/");
    expect(cookie!.httpOnly).toBe(true);
    expect(cookie!.sameSite).toBe("Lax");
    expect(cookie!.secure).toBe(false); // Dev mode only; production uses __Host- and Secure.
  }
  expect(cookies.find(item => item.name === "virki_recovery_intent")?.value).toBe(`${id}.PASSKEY_ADMIN`);
}

test("Chromium ADMIN: actual Hub RP passkey enrollment and PASSKEY_ADMIN recovery need separate reviewer and verified new mailbox", async ({ browser }) => {
  test.setTimeout(180_000);
  const { db, reviewer } = await requireHarness();
  const contexts: BrowserContext[] = [];
  let ownerSession: OwnedSession | undefined;
  let reviewerSession: OwnedSession | undefined;
  let removeAuthenticator: (() => Promise<void>) | undefined;
  try {
    const reviewerState = await db.user.findUniqueOrThrow({ where: { id: reviewer.id }, select: { role: true, isActive: true, accountStatus: true } });
    expect(reviewerState).toMatchObject({ role: "ADMIN", isActive: true, accountStatus: "ACTIVE" });
    const owner = await createOwner(db); // Unique account in the confirmed disposable DB only.
    expect(owner.id).not.toBe(reviewer.id);
    const target = await newHubContext(browser);
    contexts.push(target.context);
    ownerSession = await attachSession(target.context, db, owner.id);
    removeAuthenticator = await installVirtualAuthenticator(target.context, target.page);
    const enrolled = await registerOwnedHubPasskey(target.page, db, owner);

    // A key registered on the Hub cannot be invoked as a portal credential.
    const badRp = await target.page.evaluate(async () => {
      try {
        await navigator.credentials.get({ publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: "portal.localhost", timeout: 1500, userVerification: "required"
        } });
        return "unexpected-success";
      } catch (error) { return error instanceof DOMException ? error.name : "rejected"; }
    });
    expect(badRp).toBe("SecurityError");

    await target.context.clearCookies(); // Recovery is unauthenticated but Hub Access still required.
    await target.page.goto(`${hub}/recover`);
    await target.page.getByLabel("E-mail da conta", { exact: true }).fill(owner.email);
    await target.page.locator('input[name="method"][value="PASSKEY_ADMIN"]').check();
    await target.page.locator('form input[name="csrfToken"]').first().evaluate(input => {
      (input as HTMLInputElement).value = "invalid-test-only-csrf";
    });
    const csrfDenial = target.page.waitForResponse(response => new URL(response.url()).pathname === "/recover" &&
      response.request().method() === "POST" && Boolean(response.request().headers()["next-action"]));
    await target.page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    expect((await csrfDenial).status(), "tampered CSRF must be rejected at the Next action boundary").toBe(403);
    expect(await db.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(0);
    expect((await target.context.cookies(hub)).some(cookie => cookie.name.includes("recovery") && Boolean(cookie.value))).toBe(false);
    const requestId = await startPasskeyAdminRecovery(target.page, owner.email);
    const issuedRecoveryCookies = await target.context.cookies(hub);
    assertRecoveryCookies(issuedRecoveryCookies, requestId);
    const pending = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
    expect(pending).toMatchObject({ userId: owner.id, recoveryRole: "ADMIN", recoveryProofs: ["PASSKEY"], recoveryAdminReview: true, status: "PENDING" });

    // The public request ID and matching method choice carry no authority in a
    // second Chromium profile, and an unknown ADMIN receives the same UI.
    const stolen = await newHubContext(browser);
    contexts.push(stolen.context);
    const foreignUrl = `${hub}/recover?requestId=${requestId}`;
    const foreignDocument = await stolen.page.goto(foreignUrl);
    expect(foreignDocument?.status(), "foreign browser must get a real HTTP 200 document, not a forbidden or failed page").toBe(200);
    await expect(stolen.page).toHaveURL(foreignUrl);
    await expect(stolen.page.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo", exact: true })).toBeVisible();
    await expect(stolen.page.locator('p.form-error[role="alert"]')).toContainText("Este link de recuperação não é mais válido");
    await expect(stolen.page.locator('[aria-label="Chave de acesso"] button')).toHaveCount(0);
    await expect(stolen.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const synthetic = await newHubContext(browser);
    contexts.push(synthetic.context);
    const unknownId = await startPasskeyAdminRecovery(synthetic.page, `absent-${randomUUID()}@e2e.invalid`);
    expect(unknownId).not.toBe(requestId);
    expect(await db.accountRecoveryRequest.count({ where: { id: unknownId } })).toBe(0);
    // The Next Server Action can update the address bar to the redirect URL
    // before the App Router commits the new page. URL-only synchronization is
    // not proof that the synthetic pre-proof UI rendered. Compare two *real*
    // canonical document GETs instead, failing on Access/404/500 rather than
    // treating an error document as synthetic parity.
    const knownUrl = `${hub}/recover?requestId=${requestId}`;
    const syntheticUrl = `${hub}/recover?requestId=${unknownId}`;
    const knownDocument = await target.page.goto(knownUrl);
    expect(knownDocument?.status(), "known recovery must render a real Hub HTTP 200 document").toBe(200);
    await expect(target.page).toHaveURL(knownUrl);
    const syntheticDocument = await synthetic.page.goto(syntheticUrl);
    expect(syntheticDocument?.status(), "unknown recovery must render a real Hub HTTP 200 document").toBe(200);
    await expect(synthetic.page).toHaveURL(syntheticUrl);
    assertRecoveryCookies(await target.context.cookies(hub), requestId);
    assertRecoveryCookies(await synthetic.context.cookies(hub), unknownId);
    await expect(synthetic.page.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo", exact: true })).toBeVisible();
    await expect(synthetic.page.locator('[aria-label="Chave de acesso"]').getByRole("button", { name: "Confirmar com passkey" })).toBeVisible();
    await expect(target.page.locator('[aria-label="Chave de acesso"]').getByRole("button", { name: "Confirmar com passkey" })).toBeVisible();
    expect(await publicRecoveryView(synthetic.page),
      "unknown ADMIN and enrolled ADMIN must have the same visible recovery page and actionable controls before proof")
      .toEqual(await publicRecoveryView(target.page));
    await expect(synthetic.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);

    const independent = await newHubContext(browser);
    contexts.push(independent.context);
    reviewerSession = await attachSession(independent.context, db, reviewer.id);
    await independent.page.goto(`${hub}/admin/security`);
    await expect(independent.page.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
    const reviewRow = independent.page.locator("article.list-row").filter({ hasText: owner.email });
    await expect(reviewRow,
      "an unverified PASSKEY_ADMIN request must not reach the independent reviewer's approvable queue").toHaveCount(0);

    const factor = target.page.locator('[aria-label="Chave de acesso"]');
    await factor.getByRole("button", { name: "Confirmar com passkey" }).click();
    await expect(factor.getByRole("status")).toContainText("Confirmada.");
    expect((await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).recoveryPasskeyVerifiedAt).not.toBeNull();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);

    await independent.page.reload();
    await expect(reviewRow).toBeVisible();
    await expect(reviewRow.getByRole("button", { name: "Aprovar recuperação", exact: true })).toBeVisible();
    const beforeDeniedApproval = await db.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, reviewedByUserId: true, approvedAt: true, recoveryPasskeyVerifiedAt: true,
        requestKeyHash: true, expiresAt: true }
    });
    expect(beforeDeniedApproval.status).toBe("PENDING");
    expect(beforeDeniedApproval.reviewedByUserId).toBeNull();
    expect(beforeDeniedApproval.approvedAt).toBeNull();
    expect(beforeDeniedApproval.recoveryPasskeyVerifiedAt).not.toBeNull();
    const successfulApprovalAuditBefore = await db.auditLog.count({
      where: { actorUserId: reviewer.id, eventType: "ACCOUNT_RECOVERY_APPROVED" }
    });
    // Server Component forms can submit as native POST before hydration;
    // identifying the owned request body is safer than requiring next-action.
    const deniedApprovalPost = independent.page.waitForResponse(response =>
      new URL(response.url()).origin === hub && new URL(response.url()).pathname === "/admin/security" &&
      response.request().method() === "POST" && Boolean(response.request().postData()?.includes(requestId)),
    { timeout: 10_000 });
    await reviewRow.getByRole("button", { name: "Aprovar recuperação", exact: true }).click({ timeout: 6_000 });
    const deniedApproval = await deniedApprovalPost;
    expect(deniedApproval.status(), "the request must reach the authorization action, not fail at Access/CSRF/HTTP500")
      .toBeGreaterThanOrEqual(200);
    expect(deniedApproval.status()).toBeLessThan(400);
    expect(deniedApproval.request().headers().origin).toBe(hub);
    expect(deniedApproval.request().postData(), "the reviewer must POST the owned request ID to the Server Action")
      .toContain(requestId);
    await expect(independent.page).toHaveURL(`${hub}/admin/security?error=recovery#admin-content`);
    expect(await db.accountRecoveryRequest.findUniqueOrThrow({
      where: { id: requestId },
      select: { status: true, reviewedByUserId: true, approvedAt: true, recoveryPasskeyVerifiedAt: true,
        requestKeyHash: true, expiresAt: true }
    }), "a reviewer without ACCOUNT_STATE_CHANGE must leave the request PENDING with original factor proof")
      .toEqual(beforeDeniedApproval);
    expect(await db.auditLog.count({ where: { actorUserId: reviewer.id, eventType: "ACCOUNT_RECOVERY_APPROVED" } }),
      "denied approval must not write a successful account recovery approval audit")
      .toBe(successfulApprovalAuditBefore);
    await elevateWithUi(independent.page, db, reviewer, "ACCOUNT_STATE_CHANGE");
    const elevatedRow = independent.page.locator("article.list-row").filter({ hasText: owner.email });
    await expect(elevatedRow.getByRole("button", { name: "Aprovar recuperação", exact: true })).toBeVisible();
    const approvedActionPost = independent.page.waitForResponse(response =>
      new URL(response.url()).origin === hub && new URL(response.url()).pathname === "/admin/security" &&
      response.request().method() === "POST" && Boolean(response.request().postData()?.includes(requestId)),
    { timeout: 10_000 });
    await elevatedRow.getByRole("button", { name: "Aprovar recuperação", exact: true }).click({ timeout: 6_000 });
    const approvedActionResponse = await approvedActionPost;
    expect(approvedActionResponse.status(), "elevated approval must reach a successful real Server Action")
      .toBeGreaterThanOrEqual(200);
    expect(approvedActionResponse.status()).toBeLessThan(400);
    expect(approvedActionResponse.request().postData()).toContain(requestId);
    await expect(independent.page).toHaveURL(`${hub}/admin/security?status=recovery#admin-content`);
    expect(await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } }))
      .toMatchObject({ status: "APPROVED", reviewedByUserId: reviewer.id });
    expect(await db.auditLog.count({ where: { actorUserId: reviewer.id, eventType: "ACCOUNT_RECOVERY_APPROVED" } }))
      .toBe(successfulApprovalAuditBefore + 1);

    await target.page.reload();
    await expect(target.page.getByRole("heading", { name: "Confirme um novo e-mail antes de trocar a senha" })).toBeVisible();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const replacement = `owned-new-mail-${randomUUID()}@e2e.invalid`;
    await target.page.getByLabel("Novo endereço de e-mail").fill(replacement);
    await target.page.getByRole("button", { name: "Enviar código ao novo e-mail" }).click();
    await expect(target.page.getByLabel("Código recebido no novo e-mail")).toBeVisible();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const code = await latestCode(db, replacement, "RECOVERY_EMAIL_REBIND");

    // Exercise the actual Next completion Server Action BEFORE mailbox proof,
    // not merely a hidden input. The isolated owned request is temporarily
    // marked verified only to render a genuine React completion form; clear
    // that fixture-only marker BEFORE submitting. This mimics a stale rendered
    // completion form after factor state changes, without authorizing a reset.
    // Render the stale form in a second page of the original browser context
    // to leave the actively verifying new-mail form untouched.
    const beforeDenied = await db.user.findUniqueOrThrow({ where: { id: owner.id },
      select: { email: true, emailNormalized: true, emailVerifiedAt: true, passwordHash: true, secondFactorMethod: true } });
    const newMailBeforeDenied = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId },
      select: { status: true, recoveryNewEmailVerifiedAt: true, bootstrapSessionId: true } });
    expect(newMailBeforeDenied).toMatchObject({ status: "APPROVED", recoveryNewEmailVerifiedAt: null, bootstrapSessionId: null });
    const prematurePage = await target.context.newPage();
    await addCloudflareAccessHeader(prematurePage);
    await db.accountRecoveryRequest.update({ where: { id: requestId }, data: { recoveryNewEmailVerifiedAt: new Date() } });
    try {
      const preparedDocument = await prematurePage.goto(`${hub}/recover?requestId=${requestId}`);
      expect(preparedDocument?.status()).toBe(200);
      await expect(prematurePage.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo" })).toBeVisible();
      await expect(prematurePage.getByLabel("Nova senha", { exact: true })).toBeVisible();
      await expect(prematurePage.locator('form input[name="requestId"]')).toHaveValue(requestId);
      await expect(prematurePage.locator('form input[name="csrfToken"]')).not.toHaveValue("");
    } finally {
      // Never leave an artificial verified marker behind if rendering fails.
      await db.accountRecoveryRequest.update({ where: { id: requestId }, data: { recoveryNewEmailVerifiedAt: null } });
    }
    expect((await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).recoveryNewEmailVerifiedAt).toBeNull();
    const unchangedCapabilities = await target.context.cookies(hub);
    assertRecoveryCookies(unchangedCapabilities, requestId);
    for (const name of ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"]) {
      expect(unchangedCapabilities.find(cookie => cookie.name === name)?.value,
        `premature completion must still carry the original bound ${name} capability`)
        .toBe(issuedRecoveryCookies.find(cookie => cookie.name === name)?.value);
    }
    await expect(prematurePage.locator('form input[name="requestId"]')).toHaveValue(requestId);
    const prematurePassword = `premature-admin-${randomUUID()}-password`;
    await prematurePage.getByLabel("Nova senha", { exact: true }).fill(prematurePassword);
    const deniedAction = prematurePage.waitForResponse(response => new URL(response.url()).origin === hub &&
      new URL(response.url()).pathname === "/recover" && response.request().method() === "POST" &&
      Boolean(response.request().headers()["next-action"]));
    await prematurePage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    const deniedResponse = await deniedAction;
    expect(deniedResponse.status(), "a denied mailbox proof must be handled by the real action (not Access/CSRF/HTTP500)")
      .toBeGreaterThanOrEqual(200);
    expect(deniedResponse.status()).toBeLessThan(400);
    expect(deniedResponse.request().headers().origin).toBe(hub);
    expect(deniedResponse.request().postDataBuffer()?.byteLength ?? 0,
      "the premature password must reach the real Server Action POST").toBeGreaterThan(0);
    expect(deniedResponse.request().postData()).toContain(requestId);
    await expect(prematurePage).toHaveURL(`${hub}/recover?requestId=${requestId}&error=1`);
    const afterDenied = await db.user.findUniqueOrThrow({ where: { id: owner.id },
      select: { email: true, emailNormalized: true, emailVerifiedAt: true, passwordHash: true, secondFactorMethod: true } });
    expect(afterDenied, "denied Server Action must not change the normal password, email or MFA").toEqual(beforeDenied);
    expect(await verifyPassword(afterDenied.passwordHash ?? "", prematurePassword)).toBe(false);
    const rejectedRecovery = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId },
      select: { status: true, recoveryNewEmailVerifiedAt: true, bootstrapSessionId: true } });
    expect(rejectedRecovery).toEqual(newMailBeforeDenied);
    await expect(target.page).toHaveURL(`${hub}/recover?requestId=${requestId}`);
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    await expect(target.page.getByLabel("Código recebido no novo e-mail")).toBeVisible();

    await target.page.getByLabel("Código recebido no novo e-mail").fill(code);
    await target.page.getByRole("button", { name: "Confirmar novo e-mail" }).click();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toBeVisible();
    expect((await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).recoveryNewEmailVerifiedAt).not.toBeNull();

    // Preserve a fully rendered, authorized completion form and its original
    // browser capabilities in a separate cookie jar BEFORE the winning reset.
    // The winner will clear its own recovery cookies and receive a session;
    // a second tab in that same context would no longer exercise the old proof.
    const originalCookies = (await target.context.cookies(hub))
      .filter(cookie => ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"].includes(cookie.name));
    expect(originalCookies, "replay requires all three original ADMIN recovery capabilities").toHaveLength(3);
    assertRecoveryCookies(originalCookies, requestId);
    const stale = await newHubContext(browser);
    contexts.push(stale.context);
    await stale.context.addCookies(originalCookies.map(cookie => ({
      url: `${hub}/`, name: cookie.name, value: cookie.value,
      httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite, expires: cookie.expires
    })));
    const staleUrl = `${hub}/recover?requestId=${requestId}`;
    const staleDocument = await stale.page.goto(staleUrl);
    expect(staleDocument?.status(), "the second completion form must come from a real Hub document").toBe(200);
    await expect(stale.page).toHaveURL(staleUrl);
    await expect(stale.page.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo" })).toBeVisible();
    await expect(stale.page.getByLabel("Nova senha", { exact: true })).toBeVisible();
    await expect(stale.page.locator('form input[name="requestId"]')).toHaveValue(requestId);
    const replayPassword = `replayed-normal-admin-${randomUUID()}-password`;
    await stale.page.getByLabel("Nova senha", { exact: true }).fill(replayPassword);

    const changedPassword = `new-normal-admin-${randomUUID()}-password`;
    await target.page.getByLabel("Nova senha", { exact: true }).fill(changedPassword);
    // A successful Server Action alone is insufficient: require a *new*
    // protected document GET, not a stale RSC update or a generic heading.
    const bootstrapDocument = target.page.waitForResponse(response => new URL(response.url()).origin === hub &&
      new URL(response.url()).pathname === "/admin/accounts" && response.request().method() === "GET" &&
      response.request().resourceType() === "document");
    await target.page.getByRole("button", { name: "Concluir recuperação" }).click();
    await expect(target.page).toHaveURL(`${hub}/admin/accounts`);
    expect((await bootstrapDocument).status(), "bootstrap must load the actual protected Hub document over HTTP 200").toBe(200);
    await expect(target.page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    const consumed = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId },
      select: { status: true, bootstrapSessionId: true } });
    expect(consumed.status).toBe("CONSUMED");
    expect(consumed.bootstrapSessionId, "recovery must persist its precise bootstrap session identity").toBeTruthy();
    const bootstrapSession = await db.session.findUniqueOrThrow({ where: { id: consumed.bootstrapSessionId! },
      select: { userId: true, tokenHash: true, revokedAt: true, expiresAt: true } });
    expect(bootstrapSession.userId).toBe(owner.id);
    expect(bootstrapSession.revokedAt).toBeNull();
    expect(bootstrapSession.expiresAt.getTime()).toBeGreaterThan(Date.now());
    const sessionCookie = (await target.context.cookies(hub)).find(cookie => cookie.name === getSessionCookieName({ NODE_ENV: "development" }));
    expect(sessionCookie, "the browser must receive a protected host-only bootstrap session cookie").toBeDefined();
    expect(sessionCookie!.domain).toBe("hub.localhost");
    expect(sessionCookie!.path).toBe("/");
    expect(sessionCookie!.httpOnly).toBe(true);
    expect(sessionCookie!.sameSite).toBe("Lax");
    expect(hashSessionToken(sessionCookie!.value),
      "the active browser session must match bootstrapSessionId, not a leftover unrelated session").toBe(bootstrapSession.tokenHash);
    const updated = await db.user.findUniqueOrThrow({ where: { id: owner.id } });
    expect(await verifyPassword(updated.passwordHash ?? "", changedPassword)).toBe(true);
    expect(await verifyPassword(updated.passwordHash ?? "", owner.password)).toBe(false);
    expect(updated.emailNormalized).toBe(replacement);
    expect(updated.secondFactorMethod).toBe("EMAIL");
    const administrative = await db.administrativeCredential.findUniqueOrThrow({ where: { userId: owner.id } });
    expect(await verifyPassword(administrative.passwordHash, owner.administrativePassword)).toBe(true);
    expect(administrative.status).toBe("ACTIVE");
    expect((await db.passkeyCredential.findUniqueOrThrow({ where: { id: enrolled.id } })).revokedAt).not.toBeNull();
    expect((await db.session.findUniqueOrThrow({ where: { id: ownerSession.id } })).revokedAt).not.toBeNull();
    expect(await db.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "RECOVERY_EMAIL_REBIND_NOTICE" } })).toBe(1);

    // Recovery invalidates the authenticator, and replay cannot resurrect it.
    expect(await db.passkeyCredential.count({ where: { userId: owner.id, revokedAt: null } })).toBe(0);

    // The stale browser must retain the exact old proof, submit a SECOND real
    // Next Server Action and be denied without changing either credential or
    // issuing another bootstrap session. HTTP 403/500 cannot count as a pass.
    const sessionRowsBeforeReplay = await db.session.count({ where: { userId: owner.id } });
    const staleCookies = await stale.context.cookies(hub);
    for (const original of originalCookies) {
      expect(staleCookies.find(cookie => cookie.name === original.name)?.value).toBe(original.value);
    }
    expect(staleCookies.some(cookie => cookie.name === getSessionCookieName({ NODE_ENV: "development" }))).toBe(false);
    const replay = stale.page.waitForResponse(response => new URL(response.url()).origin === hub &&
      new URL(response.url()).pathname === "/recover" && response.request().method() === "POST" &&
      Boolean(response.request().headers()["next-action"]));
    await stale.page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    const replayResponse = await replay;
    expect(replayResponse.status(), "rejected ADMIN replay must finish as a handled Next action").toBeGreaterThanOrEqual(200);
    expect(replayResponse.status(), "403/500 is not a valid proof of one-time denial").toBeLessThan(400);
    expect(replayResponse.request().postDataBuffer()?.byteLength ?? 0,
      "the stale browser must submit the actual password completion form").toBeGreaterThan(0);
    await expect(stale.page).toHaveURL(`${hub}/recover?requestId=${requestId}&error=1`);
    const afterReplay = await db.user.findUniqueOrThrow({ where: { id: owner.id } });
    expect(afterReplay.email).toBe(updated.email);
    expect(afterReplay.emailNormalized).toBe(updated.emailNormalized);
    expect(afterReplay.emailVerifiedAt).toEqual(updated.emailVerifiedAt);
    expect(afterReplay.passwordHash).toBe(updated.passwordHash);
    expect(afterReplay.secondFactorMethod).toBe(updated.secondFactorMethod);
    expect(afterReplay.accountStatus).toBe(updated.accountStatus);
    expect(afterReplay.isActive).toBe(updated.isActive);
    expect(await verifyPassword(afterReplay.passwordHash ?? "", changedPassword)).toBe(true);
    expect(await verifyPassword(afterReplay.passwordHash ?? "", replayPassword)).toBe(false);
    const replayedRequest = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
    expect(replayedRequest.status).toBe("CONSUMED");
    expect(replayedRequest.bootstrapSessionId).toBe(consumed.bootstrapSessionId);
    expect(replayedRequest.reviewedByUserId).toBe(reviewer.id);
    expect(await db.session.count({ where: {
      userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() }
    } }), "replay must not mint a second active bootstrap session").toBe(1);
    expect(await db.session.count({ where: { userId: owner.id } }),
      "replay must not mint any additional session, even a revoked one").toBe(sessionRowsBeforeReplay);
    const bootstrapAfterReplay = await db.session.findUniqueOrThrow({ where: { id: consumed.bootstrapSessionId! } });
    expect(bootstrapAfterReplay.revokedAt).toBeNull();
    expect(bootstrapAfterReplay.tokenHash).toBe(bootstrapSession.tokenHash);
    expect((await db.passkeyCredential.findUniqueOrThrow({ where: { id: enrolled.id } })).revokedAt).not.toBeNull();
  } finally {
    await removeAuthenticator?.().catch(() => undefined);
    await Promise.allSettled(contexts.map(context => context.close()));
    if (reviewerSession) await db.session.updateMany({ where: { id: reviewerSession.id, revokedAt: null }, data: { revokedAt: new Date() } }).catch(() => undefined);
    // AuditLog is immutable and can reference the owned account. Never DELETE
    // that account or protected audit evidence; the disposable DB is destroyed
    // by the dedicated E2E harness, not this test.
    await db.$disconnect();
  }
});

test("Chromium ADMIN: a revoked Hub passkey cannot prove an already-bound PASSKEY_ADMIN recovery", async ({ browser }) => {
  test.setTimeout(90_000);
  const { db } = await requireHarness();
  let removeAuthenticator: (() => Promise<void>) | undefined;
  let context: BrowserContext | undefined;
  try {
    const owner = await createOwner(db);
    const current = await newHubContext(browser);
    context = current.context;
    await attachSession(current.context, db, owner.id);
    removeAuthenticator = await installVirtualAuthenticator(current.context, current.page);
    const enrolled = await registerOwnedHubPasskey(current.page, db, owner);

    // Establish a REAL browser-bound PENDING request while the Hub credential
    // is live. If we revoke before requesting, the backend returns a synthetic
    // request without a DB row; its failure would never test revoked proof.
    expect(await db.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(0);
    await current.context.clearCookies();
    const requestId = await startPasskeyAdminRecovery(current.page, owner.email);
    assertRecoveryCookies(await current.context.cookies(hub), requestId);
    expect(await db.accountRecoveryRequest.count({ where: { userId: owner.id } }),
      "the bound request must be persisted before revocation").toBe(1);
    const bound = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
    expect(bound).toMatchObject({ userId: owner.id, recoveryRole: "ADMIN", recoveryProofs: ["PASSKEY"],
      recoveryAdminReview: true, status: "PENDING", recoveryPasskeyVerifiedAt: null,
      reviewedByUserId: null, bootstrapSessionId: null });
    // Let Chromium sign with the still-active resident credential. Intercept
    // the genuine Next assertion-finish POST only AFTER the browser has signed,
    // revoke the matching persisted credential, then forward that original
    // signed request to the server. This tests the finish-time revocation gate,
    // not a synthetic request or an authenticator with no usable credential.
    let signedFinishIntercepted = false;
    let revokedBeforeFinish = false;
    let interceptionFailure: string | undefined;
    await current.page.route("**/recover**", async route => {
      const request = route.request();
      const signedAssertion = request.method() === "POST" && Boolean(request.headers()["next-action"]) &&
        (request.postData() ?? "").includes("clientDataJSON") &&
        (request.postData() ?? "").includes("authenticatorData");
      if (!signedAssertion) { await route.continue(); return; }
      signedFinishIntercepted = true;
      try {
        const claimed = await db.passkeyCredential.updateMany({
          where: { id: enrolled.id, userId: owner.id, revokedAt: null }, data: { revokedAt: new Date() }
        });
        if (claimed.count !== 1) throw new Error("signed WebAuthn credential must be live until its finish POST");
        revokedBeforeFinish = true;
        await route.continue();
      } catch (error) {
        interceptionFailure = error instanceof Error ? error.message : "interception failed";
        await route.abort().catch(() => undefined);
      }
    });
    const actionCalls: Array<{ status: number; bytes: number }> = [];
    current.page.on("response", response => {
      if (new URL(response.url()).origin === hub && new URL(response.url()).pathname === "/recover" &&
          response.request().method() === "POST" && response.request().headers()["next-action"]) {
        actionCalls.push({ status: response.status(), bytes: response.request().postDataBuffer()?.byteLength ?? 0 });
      }
    });
    await current.page.locator('[aria-label="Chave de acesso"]').getByRole("button", { name: "Confirmar com passkey" }).click();
    await expect(current.page.locator('[aria-label="Chave de acesso"] [role="alert"]'))
      .toContainText("Não foi possível confirmar a passkey");
    expect(interceptionFailure).toBeUndefined();
    expect(signedFinishIntercepted, "the virtual authenticator must produce an actual signed WebAuthn assertion").toBe(true);
    expect(revokedBeforeFinish, "the credential must be revoked BEFORE its signed assertion reaches the server").toBe(true);
    expect((await db.passkeyCredential.findUniqueOrThrow({ where: { id: enrolled.id } })).revokedAt).not.toBeNull();
    expect(actionCalls.length, "WebAuthn must run both the real START and assertion-finish actions").toBeGreaterThanOrEqual(2);
    for (const action of actionCalls) {
      expect(action.status, "failed WebAuthn proof must be handled by the real Server Action").toBeGreaterThanOrEqual(200);
      expect(action.status, "a 403/500 boundary failure is not an assertion denial").toBeLessThan(400);
      expect(action.bytes, "the WebAuthn Server Action must receive a nonempty submission").toBeGreaterThan(0);
    }
    const challenges = await db.passkeyChallenge.findMany({ where: { userId: owner.id, ceremony: "RECOVERY" } });
    expect(challenges.length, "START must persist a real recovery WebAuthn challenge").toBeGreaterThan(0);
    expect(challenges.every(challenge => challenge.consumedAt === null)).toBe(true);
    expect(await db.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(1);
    const rejected = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
    expect(rejected).toMatchObject({ userId: owner.id, status: "PENDING", recoveryPasskeyVerifiedAt: null,
      reviewedByUserId: null, bootstrapSessionId: null });
    await expect(current.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
  } finally {
    await removeAuthenticator?.().catch(() => undefined);
    await context?.close().catch(() => undefined);
    // Deliberately retain the owned AuditLog-linked ADMIN until its disposable
    // database is destroyed; never mutate the audit ledger for test teardown.
    await db.$disconnect();
  }
});
