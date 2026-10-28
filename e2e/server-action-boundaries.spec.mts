import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { hashAuditSessionReference, hashSessionToken } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { PrismaClient } from "@virki/database";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const productionHubMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const hubUrl = productionHubMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const sessionCookieName = getSessionCookieName({ NODE_ENV: productionHubMode ? "production" : process.env.NODE_ENV });
const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();

test.skip(!databaseUrl || !fixturePath, "Server Action boundary E2E requires an explicit disposable database fixture.");

type ActorFixture = { id: string; email: string };
type AuthFixture = { admin: ActorFixture; user: ActorFixture };
type MutationCounts = {
  users: number;
  sessions: number;
  recoveryRequests: number;
  outboxMessages: number;
  deliveryAttempts: number;
  auditLogs: number;
};

function createDatabase(): PrismaClient {
  if (!databaseUrl) throw new Error("The explicit disposable E2E database URL is unavailable.");
  return new PrismaClient({ datasources: { db: { url: databaseUrl } } });
}

async function readFixture(): Promise<AuthFixture> {
  if (!fixturePath) throw new Error("The authenticated E2E fixture path is unavailable.");
  const value: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!isAuthFixture(value)) throw new Error("The authenticated E2E fixture is invalid.");
  return value;
}

function isAuthFixture(value: unknown): value is AuthFixture {
  if (!value || typeof value !== "object") return false;
  const fixture = value as Record<string, unknown>;
  return isActorFixture(fixture.admin) && isActorFixture(fixture.user);
}

function isActorFixture(value: unknown): value is ActorFixture {
  if (!value || typeof value !== "object") return false;
  const actor = value as Record<string, unknown>;
  return typeof actor.id === "string" && typeof actor.email === "string";
}

async function createSession(database: PrismaClient, userId: string, token: string, authenticationMethods: string[]) {
  return database.session.create({
    data: {
      userId,
      tokenHash: hashSessionToken(token),
      expiresAt: new Date(Date.now() + 10 * 60_000),
      authenticationMethods
    }
  });
}

async function readMutationCounts(database: PrismaClient): Promise<MutationCounts> {
  const [users, sessions, recoveryRequests, outboxMessages, deliveryAttempts, auditLogs] = await Promise.all([
    database.user.count(),
    database.session.count(),
    database.accountRecoveryRequest.count(),
    database.emailOutboxMessage.count(),
    database.emailDeliveryAttempt.count(),
    database.auditLog.count()
  ]);
  return { users, sessions, recoveryRequests, outboxMessages, deliveryAttempts, auditLogs };
}

function isHubServerActionResponse(response: import("@playwright/test").Response): boolean {
  const request = response.request();
  return new URL(response.url()).origin === hubUrl &&
    new URL(response.url()).pathname === "/admin/accounts" &&
    request.method() === "POST" &&
    Boolean(request.headers()["next-action"]);
}

test("Hub Server Action returns HTTP 403 and attributes a role denial to the authenticated user", async ({ browser }) => {
  test.setTimeout(90_000);
  const fixture = await readFixture();
  const database = createDatabase();
  const adminToken = randomBytes(32).toString("base64url");
  let adminSessionId: string | undefined;
  let adminRoleChanged = false;
  const context = await browser.newContext();

  try {
    const adminSession = await createSession(database, fixture.admin.id, adminToken, ["pwd", "otp", "mfa"]);
    adminSessionId = adminSession.id;
    await context.addCookies([{ name: sessionCookieName, value: adminToken, url: hubUrl, httpOnly: true, secure: true, sameSite: "Lax" }]);

    const page = await context.newPage();
    await addCloudflareAccessHeader(page);
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    const form = page.locator("form").filter({ has: page.getByRole("button", { name: "Criar conta", exact: true }) });
    const deniedEmail = `denied-${randomBytes(8).toString("hex")}@e2e.invalid`;
    await form.getByLabel("Nome", { exact: true }).fill("Denied runtime probe");
    await form.getByLabel("E-mail", { exact: true }).fill(deniedEmail);

    const countsBefore = await readMutationCounts(database);
    const roleChange = await database.user.updateMany({
      where: { id: fixture.admin.id, role: "ADMIN" },
      data: { role: "USER" }
    });
    expect(roleChange.count).toBe(1);
    adminRoleChanged = true;

    // Keep the page-issued CSRF token and session binding intact while changing
    // the disposable fixture actor's role between render and action execution.
    const actionResponsePromise = page.waitForResponse(isHubServerActionResponse);
    await form.getByRole("button", { name: "Criar conta", exact: true }).click();
    const actionResponse = await actionResponsePromise;
    expect(actionResponse.status()).toBe(403);

    const countsAfter = await readMutationCounts(database);
    expect({ ...countsAfter, auditLogs: countsBefore.auditLogs }).toEqual(countsBefore);
    expect(countsAfter.auditLogs).toBeGreaterThan(countsBefore.auditLogs);

    const denials = await database.auditLog.findMany({
      where: {
        actorUserId: fixture.admin.id,
        actorRole: "USER",
        sessionRef: hashAuditSessionReference(adminSession.id),
        eventType: "AUTHORIZATION_DENIED",
        reason: "role",
        resource: "identity.security"
      },
      orderBy: { createdAt: "desc" },
      select: { actorUserId: true, actorRole: true, sessionRef: true, result: true, reason: true, service: true, route: true, method: true, metadata: true, requestId: true }
    });
    const actionDenials = denials.filter((event) => {
      const metadata = event.metadata;
      return Boolean(metadata && typeof metadata === "object" && !Array.isArray(metadata) && metadata.source === "admin-account-create");
    });
    expect(actionDenials).toHaveLength(1);
    const denial = actionDenials[0];
    expect(denial).not.toBeNull();
    expect(denial).toMatchObject({
      actorUserId: fixture.admin.id,
      actorRole: "USER",
      sessionRef: hashAuditSessionReference(adminSession.id),
      result: "DENIED",
      reason: "role",
      service: "hub",
      route: "/admin/accounts",
      method: "POST"
    });
    expect(denial?.requestId).toMatch(/^[a-f0-9-]{36}$/u);
  } finally {
    if (adminRoleChanged) await database.user.updateMany({ where: { id: fixture.admin.id, role: "USER" }, data: { role: "ADMIN" } });
    if (adminSessionId) await database.session.deleteMany({ where: { id: adminSessionId } });
    await context.close();
    await database.$disconnect();
  }
});

test("Hub rejects an over-1 MiB Server Action body before any account or audit mutation", async ({ browser }) => {
  test.setTimeout(90_000);
  const fixture = await readFixture();
  const database = createDatabase();
  const adminToken = randomBytes(32).toString("base64url");
  let sessionId: string | undefined;
  const context = await browser.newContext();

  try {
    const session = await createSession(database, fixture.admin.id, adminToken, ["pwd", "otp", "mfa"]);
    sessionId = session.id;
    await context.addCookies([{ name: sessionCookieName, value: adminToken, url: hubUrl, httpOnly: true, secure: true, sameSite: "Lax" }]);
    const page = await context.newPage();
    await addCloudflareAccessHeader(page);
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    const form = page.locator("form").filter({ has: page.getByRole("button", { name: "Criar conta", exact: true }) });
    await form.getByLabel("Nome", { exact: true }).fill("Oversized runtime probe");
    await form.getByLabel("E-mail", { exact: true }).fill(`oversized-${randomBytes(8).toString("hex")}@e2e.invalid`);
    await form.evaluate((node) => {
      const oversized = document.createElement("input");
      oversized.type = "hidden";
      oversized.name = "e2eOversizedBodyProbe";
      oversized.value = "x".repeat(1024 * 1024 + 1024);
      node.append(oversized);
    });

    const countsBefore = await readMutationCounts(database);
    const actionResponsePromise = page.waitForResponse(isHubServerActionResponse);
    await form.getByRole("button", { name: "Criar conta", exact: true }).click();
    const actionResponse = await actionResponsePromise;
    const requestSize = actionResponse.request().postDataBuffer()?.byteLength ?? 0;
    expect(requestSize).toBeGreaterThan(1024 * 1024);
    expect(actionResponse.status()).toBeGreaterThanOrEqual(400);

    const countsAfter = await readMutationCounts(database);
    expect(countsAfter).toEqual(countsBefore);
  } finally {
    if (sessionId) await database.session.deleteMany({ where: { id: sessionId } });
    await context.close();
    await database.$disconnect();
  }
});
