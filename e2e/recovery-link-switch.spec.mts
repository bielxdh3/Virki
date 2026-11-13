import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const hubUrl = process.env.VIRKI_E2E_HUB_MODE === "production" ? "https://hub.localhost" : "https://hub.localhost:3001";
const productionHubMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const recoveryCookieName = productionHubMode ? "__Host-virki_recovery" : "virki_recovery_v2";
const recoveryCandidateCookieName = productionHubMode ? "__Host-virki_recovery_candidate" : "virki_recovery_candidate";
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE;
test.skip(!e2eDatabaseUrl || !fixturePath, "Recovery switch E2E requires the explicit disposable database and global-setup fixture.");

type FixtureAccount = { id: string; email: string };
type AuthFixture = { admin: FixtureAccount };
let fixture: AuthFixture;

test.beforeAll(async () => {
  if (!fixturePath || !e2eDatabaseUrl) throw new Error("Recovery switch E2E fixture is unavailable.");
  const { assertDisposableCoreTestDatabase } = await import("../scripts/core-test-database-safety.mjs");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  const value: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!isFixture(value)) throw new Error("Recovery switch E2E fixture is invalid.");
  fixture = value;
});

test("approved ADMIN recovery link switch activates only the confirmed candidate", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery switch E2E database is unavailable.");
  process.env.DATABASE_URL = e2eDatabaseUrl;
  process.env.VIRKI_HUB_URL = hubUrl;
  process.env.VIRKI_HUB_HOSTNAME = "hub.localhost";

  const [{ prisma }, { getAccountRecoveryState, hashRecoveryRequestKey, requestAdministrativeAccountRecovery }, { decryptEmailPayload }] = await Promise.all([
    import("@virki/database"),
    import("@virki/auth/security"),
    import("@virki/auth/email")
  ]);
  const context = await browser.newContext();
  const createdAccountIds: string[] = [];
  const createdEmails: string[] = [];
  try {
    const createAdmin = async (label: string): Promise<FixtureAccount> => {
      const email = `${randomUUID()}.${label}@e2e.invalid`;
      const account = await prisma.user.create({ data: {
        email,
        emailNormalized: email,
        displayName: `E2E ${label}`,
        role: "ADMIN",
        isActive: true,
        accountStatus: "ACTIVE",
        emailVerifiedAt: new Date()
      }, select: { id: true, email: true } });
      createdAccountIds.push(account.id);
      createdEmails.push(account.email);
      return account;
    };
    const firstAccount = await createAdmin("recovery-first");
    const candidateAccount = await createAdmin("recovery-candidate");
    const requestLink = async (account: FixtureAccount) => {
      await requestAdministrativeAccountRecovery(account.email, "pt-BR");
      const message = await prisma.emailOutboxMessage.findFirst({
        where: { recipientEmail: account.email, kind: "ACCOUNT_RECOVERY" },
        orderBy: { createdAt: "desc" },
        select: { id: true, payload: true }
      });
      if (!message) throw new Error("Recovery switch E2E message is unavailable.");
      const actionUrl = decryptEmailPayload(message.payload).actionUrl;
      if (!actionUrl || new URL(actionUrl).origin !== hubUrl) throw new Error("Recovery switch E2E link is invalid.");
      const requestKey = new URL(actionUrl).searchParams.get("request");
      if (!requestKey || !/^[A-Za-z0-9_-]{32,100}$/u.test(requestKey)) throw new Error("Recovery switch E2E key is invalid.");
      const recovery = await prisma.accountRecoveryRequest.findFirst({
        where: { userId: account.id, requestKeyHash: hashRecoveryRequestKey(requestKey) },
        select: { id: true }
      });
      if (!recovery) throw new Error("Recovery switch E2E record is unavailable.");
      return { actionUrl, requestKey, requestId: recovery.id };
    };

    const first = await requestLink(firstAccount);
    const candidate = await requestLink(candidateAccount);
    const reviewedAt = new Date();
    await prisma.accountRecoveryRequest.update({
      where: { id: candidate.requestId },
      data: { status: "APPROVED", emailVerifiedAt: reviewedAt, reviewedByUserId: fixture.admin.id, approvedAt: reviewedAt }
    });

    const page = await context.newPage();
    await addCloudflareAccessHeader(page);
    await page.goto(first.actionUrl);
    await expect(page.getByRole("button", { name: "Continuar com este link", exact: true })).toBeVisible();
    expect((await context.cookies(hubUrl)).find(cookie => cookie.name === recoveryCookieName)?.value ?? "").toBe("");
    expect((await context.cookies(hubUrl)).find(cookie => cookie.name === recoveryCandidateCookieName)?.value)
      .toBe(first.requestKey);
    await page.getByRole("button", { name: "Continuar com este link", exact: true }).click();
    await expect(page.getByLabel("Código de verificação", { exact: true })).toBeVisible();
    const firstActive = (await context.cookies(hubUrl)).find((cookie) => cookie.name === recoveryCookieName);
    expect(firstActive?.value).toBe(first.requestKey);

    await page.goto(candidate.actionUrl);
    await expect(page.getByRole("status")).toContainText("Outro link está aberto nesta sessão.");
    await expect(page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const beforeConfirmation = await context.cookies(hubUrl);
    expect(beforeConfirmation.find((cookie) => cookie.name === recoveryCookieName)?.value).toBe(first.requestKey);
    expect(beforeConfirmation.find((cookie) => cookie.name === recoveryCandidateCookieName)?.value).toBe(candidate.requestKey);

    await page.locator('input[name="requestId"]').evaluate((input, value) => { (input as HTMLInputElement).value = value; }, first.requestId);
    await page.getByRole("button", { name: "Continuar com este link", exact: true }).click();
    await expect(page.locator('p[role="alert"]')).toContainText("Não foi possível usar este link.");
    const afterRejectedSwitch = await context.cookies(hubUrl);
    expect(afterRejectedSwitch.find((cookie) => cookie.name === recoveryCookieName)?.value).toBe(first.requestKey);
    expect(afterRejectedSwitch.find((cookie) => cookie.name === recoveryCandidateCookieName)?.value).toBe(candidate.requestKey);

    await page.locator('input[name="requestId"]').evaluate((input, value) => { (input as HTMLInputElement).value = value; }, candidate.requestId);
    const switchResponses: string[] = [];
    page.on("response", (response) => {
      const request = response.request();
      const url = new URL(response.url());
      if (request.method() !== "POST" || url.origin !== hubUrl) return;
      const redirectHeader = response.headers()["x-action-redirect"]?.split(";")[0];
      let redirectSummary = "none";
      if (redirectHeader) {
        try {
          const redirect = new URL(redirectHeader, hubUrl);
          redirectSummary = `${redirect.pathname}?${[...redirect.searchParams.keys()].join(",")}`;
        } catch { redirectSummary = "unparseable"; }
      }
      switchResponses.push(`${url.pathname}:${response.status()}:redirect=${redirectSummary}`);
    });
    await page.getByRole("button", { name: "Continuar com este link", exact: true }).click();
    try {
      await expect(page.getByRole("status")).toContainText("Defina uma nova senha para concluir o acesso à sua conta.");
    } catch {
      const currentUrl = new URL(page.url());
      const afterFailure = await context.cookies(hubUrl);
      const activeKey = afterFailure.find((cookie) => cookie.name === recoveryCookieName)?.value;
      const candidateStillPresent = afterFailure.some((cookie) => cookie.name === recoveryCandidateCookieName && Boolean(cookie.value));
      const [recoveryState, record, alertText] = await Promise.all([
        getAccountRecoveryState(candidate.requestId, candidate.requestKey, new Date(), "ADMIN"),
        prisma.accountRecoveryRequest.findUnique({
          where: { id: candidate.requestId },
          select: { status: true, emailVerifiedAt: true, expiresAt: true, purpose: true, user: { select: { role: true, isActive: true, accountStatus: true } } }
        }),
        page.getByRole("alert").textContent().catch(() => null)
      ]);
      throw new Error(`Recovery link switch did not render the approved request (path=${currentUrl.pathname}; requestIdMatches=${currentUrl.searchParams.get("requestId") === candidate.requestId}; activeMatchesCandidate=${activeKey === candidate.requestKey}; candidateStillPresent=${candidateStillPresent}; lookup=${recoveryState?.status ?? "missing"}; record=${record?.status ?? "missing"}; emailVerified=${Boolean(record?.emailVerifiedAt)}; unexpired=${Boolean(record && record.expiresAt > new Date())}; purpose=${record?.purpose ?? "missing"}; accountEligible=${Boolean(record?.user.isActive && record.user.accountStatus === "ACTIVE" && record.user.role === "ADMIN")}; alert=${alertText ?? "none"}; responses=${switchResponses.join("|") || "none"}).`);
    }
    await expect(page.getByLabel("Nova senha", { exact: true })).toBeVisible();
    const afterConfirmation = await context.cookies(hubUrl);
    expect(afterConfirmation.find((cookie) => cookie.name === recoveryCookieName)?.value).toBe(candidate.requestKey);
    expect(afterConfirmation.some((cookie) => cookie.name === recoveryCandidateCookieName && cookie.value.length > 0)).toBe(false);

    const originalPasswordHash = await prisma.user.findUnique({ where: { id: candidateAccount.id }, select: { passwordHash: true } });
    const invalidPassword = page.getByLabel("Nova senha", { exact: true });
    await invalidPassword.evaluate((input) => { (input as HTMLInputElement).form!.noValidate = true; });
    await invalidPassword.fill("short-password");
    await page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect.poll(() => {
      const currentUrl = new URL(page.url());
      return currentUrl.pathname === "/recover" && currentUrl.searchParams.get("requestId") === candidate.requestId && !currentUrl.searchParams.has("error");
    }).toBe(true);
    try {
      await expect(page.locator('p.form-error[role="alert"]')).toContainText("pelo menos 16 caracteres");
    } catch {
      const [cookiesAfterRejectedPassword, recoveryState, record, alertText] = await Promise.all([
        context.cookies(hubUrl),
        getAccountRecoveryState(candidate.requestId, candidate.requestKey, new Date(), "ADMIN"),
        prisma.accountRecoveryRequest.findUnique({
          where: { id: candidate.requestId },
          select: { status: true, emailVerifiedAt: true, expiresAt: true, purpose: true, requestKeyHash: true, user: { select: { role: true, isActive: true, accountStatus: true } } }
        }),
        page.locator('p.form-error[role="alert"]').textContent().catch(() => null)
      ]);
      const activeRecoveryKey = cookiesAfterRejectedPassword.find((cookie) => cookie.name === recoveryCookieName)?.value;
      throw new Error(`Short ADMIN recovery password error did not retain the approved request (path=${new URL(page.url()).pathname}; requestIdMatches=${new URL(page.url()).searchParams.get("requestId") === candidate.requestId}; activeMatchesCandidate=${activeRecoveryKey === candidate.requestKey}; lookup=${recoveryState?.status ?? "missing"}; record=${record?.status ?? "missing"}; keyMatches=${Boolean(record?.requestKeyHash && record.requestKeyHash === hashRecoveryRequestKey(candidate.requestKey))}; emailVerified=${Boolean(record?.emailVerifiedAt)}; unexpired=${Boolean(record && record.expiresAt > new Date())}; accountEligible=${Boolean(record?.user.isActive && record.user.accountStatus === "ACTIVE" && record.user.role === "ADMIN")}; alert=${alertText ?? "none"}).`);
    }
    expect(await prisma.user.findUnique({ where: { id: candidateAccount.id }, select: { passwordHash: true } })).toEqual(originalPasswordHash);
    const afterRejectedPassword = await context.cookies(hubUrl);
    expect(afterRejectedPassword.find((cookie) => cookie.name === recoveryCookieName)?.value).toBe(candidate.requestKey);
    expect(afterRejectedPassword.some((cookie) => cookie.name === recoveryCandidateCookieName && Boolean(cookie.value))).toBe(false);
  } finally {
    await context.close();
    if (createdAccountIds.length > 0) {
      await prisma.accountRecoveryRequest.deleteMany({ where: { userId: { in: createdAccountIds } } });
      await prisma.emailOutboxMessage.deleteMany({ where: { recipientEmail: { in: createdEmails } } });
      await prisma.user.deleteMany({ where: { id: { in: createdAccountIds } } });
    }
    await prisma.$disconnect();
  }
});

function isFixture(value: unknown): value is AuthFixture {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return isAccount(candidate.admin);
}

function isAccount(value: unknown): value is FixtureAccount {
  if (!value || typeof value !== "object") return false;
  const account = value as Record<string, unknown>;
  return typeof account.id === "string" && typeof account.email === "string";
}
