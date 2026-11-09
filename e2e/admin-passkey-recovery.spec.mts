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

// Running playwright --list must never launch web servers, use an existing DB,
// install browser trust, or mutate Cloudflare/SMTP. The normal harness owns its
// per-run TLS trust and private DB only when physical execution is authorized.
test.skip(!enabled || !dbUrl || !fixtureFile || !existsSync(fixtureFile),
  "ADMIN passkey E2E requires both explicit flags and an isolated E2E fixture.");

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
  // Password alone is not enough without a recently activated, separately
  // confirmed administrative elevation. The browser calls the actual API.
  await manager.getByLabel("Senha atual para autorizar alterações").fill(owner.password);
  await manager.getByLabel("Nome da passkey").fill("Owned Chromium ADMIN factor");
  await manager.getByRole("button", { name: "Adicionar passkey" }).click();
  await expect(manager.getByRole("alert")).toContainText("Não foi possível confirmar a alteração");
  expect(await db.passkeyCredential.count({ where: { userId: owner.id } })).toBe(0);

  await elevateWithUi(page, db, owner, "ADMIN_CREDENTIAL_CHANGE");
  const renewed = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: /^Passkeys/ }) });
  await renewed.getByLabel("Senha atual para autorizar alterações").fill(owner.password);
  await renewed.getByLabel("Nome da passkey").fill("Owned Chromium ADMIN factor");
  await renewed.getByRole("button", { name: "Adicionar passkey" }).click();
  await expect(page.getByText("Owned Chromium ADMIN factor", { exact: true })).toBeVisible({ timeout: 30_000 });
  const rows = await db.passkeyCredential.findMany({ where: { userId: owner.id, revokedAt: null } });
  expect(rows).toHaveLength(1);
  expect(rows[0]!.rpID).toBe("hub.localhost");
  expect(rows[0]!.credentialId.length).toBeGreaterThan(16);
  return rows[0]!;
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
    assertRecoveryCookies(await target.context.cookies(hub), requestId);
    const pending = await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } });
    expect(pending).toMatchObject({ userId: owner.id, recoveryRole: "ADMIN", recoveryProofs: ["PASSKEY"], recoveryAdminReview: true, status: "PENDING" });

    // The public request ID and matching method choice carry no authority in a
    // second Chromium profile, and an unknown ADMIN receives the same UI.
    const stolen = await newHubContext(browser);
    contexts.push(stolen.context);
    await stolen.page.goto(`${hub}/recover?requestId=${requestId}`);
    await expect(stolen.page.locator('[aria-label="Chave de acesso"] button')).toHaveCount(0);
    const synthetic = await newHubContext(browser);
    contexts.push(synthetic.context);
    const unknownId = await startPasskeyAdminRecovery(synthetic.page, `absent-${randomUUID()}@e2e.invalid`);
    expect(unknownId).not.toBe(requestId);
    expect(await db.accountRecoveryRequest.count({ where: { id: unknownId } })).toBe(0);
    expect((await synthetic.page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim())
      .toBe((await target.page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim());

    const factor = target.page.locator('[aria-label="Chave de acesso"]');
    await factor.getByRole("button", { name: "Confirmar com passkey" }).click();
    await expect(factor.getByRole("status")).toContainText("Confirmada.");
    expect((await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).recoveryPasskeyVerifiedAt).not.toBeNull();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);

    const independent = await newHubContext(browser);
    contexts.push(independent.context);
    reviewerSession = await attachSession(independent.context, db, reviewer.id);
    await independent.page.goto(`${hub}/admin/security`);
    await expect(independent.page.getByRole("heading", { level: 1, name: "Segurança" })).toBeVisible();
    const reviewRow = independent.page.locator("article.list-row").filter({ hasText: owner.email });
    await expect(reviewRow).toBeVisible();
    await expect(reviewRow.getByRole("button", { name: "Aprovar recuperação" })).toBeVisible();
    await elevateWithUi(independent.page, db, reviewer, "ACCOUNT_STATE_CHANGE");
    const elevatedRow = independent.page.locator("article.list-row").filter({ hasText: owner.email });
    await elevatedRow.getByRole("button", { name: "Aprovar recuperação" }).click();
    await expect(independent.page).toHaveURL(`${hub}/admin/security?status=recovery#admin-content`);
    expect(await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } }))
      .toMatchObject({ status: "APPROVED", reviewedByUserId: reviewer.id });

    await target.page.reload();
    await expect(target.page.getByRole("heading", { name: "Confirme um novo e-mail antes de trocar a senha" })).toBeVisible();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const replacement = `owned-new-mail-${randomUUID()}@e2e.invalid`;
    await target.page.getByLabel("Novo endereço de e-mail").fill(replacement);
    await target.page.getByRole("button", { name: "Enviar código ao novo e-mail" }).click();
    await expect(target.page.getByLabel("Código recebido no novo e-mail")).toBeVisible();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const code = await latestCode(db, replacement, "RECOVERY_EMAIL_REBIND");
    await target.page.getByLabel("Código recebido no novo e-mail").fill(code);
    await target.page.getByRole("button", { name: "Confirmar novo e-mail" }).click();
    await expect(target.page.getByLabel("Nova senha", { exact: true })).toBeVisible();
    expect((await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).recoveryNewEmailVerifiedAt).not.toBeNull();

    const changedPassword = `new-normal-admin-${randomUUID()}-password`;
    await target.page.getByLabel("Nova senha", { exact: true }).fill(changedPassword);
    await target.page.getByRole("button", { name: "Concluir recuperação" }).click();
    await expect(target.page).toHaveURL(`${hub}/admin/accounts`);
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
    expect(await db.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).toMatchObject({ status: "CONSUMED" });
    expect(await db.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "RECOVERY_EMAIL_REBIND_NOTICE" } })).toBe(1);

    // Recovery invalidates the authenticator, and replay cannot resurrect it.
    expect(await db.passkeyCredential.count({ where: { userId: owner.id, revokedAt: null } })).toBe(0);
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

test("Chromium ADMIN: a revoked Hub passkey cannot authorize a fresh PASSKEY_ADMIN ceremony", async ({ browser }) => {
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

    // Model a credential revoked by the security subsystem; no recovery
    // cooldown exists for this new ADMIN, so the denial is due to revocation.
    await db.passkeyCredential.update({ where: { id: enrolled.id }, data: { revokedAt: new Date() } });
    expect(await db.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(0);
    await current.context.clearCookies();
    const requestId = await startPasskeyAdminRecovery(current.page, owner.email);
    expect(await db.accountRecoveryRequest.count({ where: { userId: owner.id } }),
      "a revoked RP credential must result in a synthetic, non-authorizing recovery").toBe(0);
    expect(await db.accountRecoveryRequest.count({ where: { id: requestId } })).toBe(0);

    await current.page.locator('[aria-label="Chave de acesso"]').getByRole("button", { name: "Confirmar com passkey" }).click();
    await expect(current.page.locator('[aria-label="Chave de acesso"] [role="alert"]'))
      .toContainText("Não foi possível confirmar a passkey");
    expect(await db.accountRecoveryRequest.count({ where: { userId: owner.id } })).toBe(0);
    await expect(current.page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
  } finally {
    await removeAuthenticator?.().catch(() => undefined);
    await context?.close().catch(() => undefined);
    // Deliberately retain the owned AuditLog-linked ADMIN until its disposable
    // database is destroyed; never mutate the audit ledger for test teardown.
    await db.$disconnect();
  }
});
