import { execFileSync, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { chmod, mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { hashPassword } from "@bielos/auth";
import { encryptOidcClientSecret, hashOidcIdentifier } from "@bielos/auth/oidc-secrets";
import { hashDeviceToken } from "@bielos/auth/security";
import { PrismaClient } from "@bielos/database";

// @ts-expect-error This existing JavaScript safety helper has no declaration file.
import { assertDisposableCoreTestDatabase } from "../core-test-database-safety.mjs";
// @ts-expect-error The isolated E2E service runner is JavaScript without a declaration file.
import { startIsolatedService } from "./isolated-service.mjs";

const E2E_DATABASE_ENV = "BIELOS_E2E_DATABASE_URL";
const FIXTURE_FILE_ENV = "BIELOS_E2E_AUTH_FIXTURE_FILE";
const OIDC_PRIVATE_CONFIG_ENV = "BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE";

type AccountFixture = {
  id: string;
  email: string;
  password: string;
  deviceToken: string;
  administrativePassword?: string;
};

type FixtureState = {
  user: AccountFixture;
  admin: AccountFixture;
  recoveryReviewer: AccountFixture;
  projectName: string;
  projectLaunchUrl: string;
  projectSlug: string;
  projectClientId: string;
  projectConnectionId: string;
  ungrantedProjectName: string;
  ungrantedProjectSlug: string;
  ungrantedProjectClientId: string;
  ungrantedProjectConnectionId: string;
  disabledProjectName: string;
  disabledProjectSlug: string;
  disabledProjectClientId: string;
  disabledProjectConnectionId: string;
  oidc: {
    clientId: string;
    clientSecret: string;
  };
};

if (process.argv[2] === "--validate-database") {
  validateE2eDatabase();
}

export default async function globalSetup(): Promise<(() => Promise<void>) | void> {
  const databaseUrl = process.env[E2E_DATABASE_ENV]?.trim();
  delete process.env[FIXTURE_FILE_ENV];
  if (!databaseUrl) return;
  const oidcPrivateConfigFile = process.env[OIDC_PRIVATE_CONFIG_ENV]?.trim();
  if (!oidcPrivateConfigFile || !isAbsolute(oidcPrivateConfigFile)) {
    throw new Error("E2E OIDC private configuration path is unavailable.");
  }

  validateE2eDatabase(databaseUrl);
  const prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  const runId = randomUUID();
  const projectSlug = `e2e-${runId}`;
  const projectClientId = `e2e-${runId}`;
  const ungrantedProjectSlug = `${projectSlug}-ungranted`;
  const ungrantedProjectClientId = `${projectClientId}-ungranted`;
  const disabledProjectSlug = `${projectSlug}-disabled`;
  const disabledProjectClientId = `${projectClientId}-disabled`;
  const userEmail = `${runId}.user@e2e.invalid`;
  const adminEmail = `${runId}.admin@e2e.invalid`;
  const projectName = `E2E project ${runId.slice(0, 8)}`;
  const ungrantedProjectName = `E2E ungranted project ${runId.slice(0, 8)}`;
  const disabledProjectName = `E2E disabled project ${runId.slice(0, 8)}`;
  const projectLaunchUrl = "https://project.e2e.invalid/launch";
  const user: Omit<AccountFixture, "id"> = {
    email: userEmail,
    password: randomBytes(32).toString("base64url"),
    deviceToken: randomBytes(32).toString("base64url")
  };
  const admin: Omit<AccountFixture, "id"> = {
    email: adminEmail,
    password: randomBytes(32).toString("base64url"),
    deviceToken: randomBytes(32).toString("base64url")
  };
  const reviewerAdministrativePassword = randomBytes(32).toString("base64url");
  const recoveryReviewer: Omit<AccountFixture, "id"> = {
    email: `${runId}.recovery-reviewer@e2e.invalid`,
    password: randomBytes(32).toString("base64url"),
    deviceToken: randomBytes(32).toString("base64url"),
    administrativePassword: reviewerAdministrativePassword
  };

  let temporaryDirectory: string | undefined;
  let fixtureFile: string | undefined;
  let oidcPrivateConfigWritten = false;
  let oidcIssuerProcess: ChildProcess | undefined;
  let seeded: FixtureState | undefined;
  try {
    temporaryDirectory = await mkdtemp(join(tmpdir(), "bielos-e2e-auth-"));
    fixtureFile = join(temporaryDirectory, "fixture.json");
    await restrictTemporaryDirectory(temporaryDirectory);

    const [userPasswordHash, adminPasswordHash, reviewerPasswordHash, reviewerAdministrativePasswordHash] = await Promise.all([
      hashPassword(user.password),
      hashPassword(admin.password),
      hashPassword(recoveryReviewer.password),
      hashPassword(reviewerAdministrativePassword)
    ]);
    const now = new Date();
    const rememberedUntil = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const oidcSecret = randomBytes(48).toString("base64url");
    const oidcEncryptionKey = randomBytes(32).toString("hex");
    const clientSecretCiphertext = encryptOidcClientSecret(oidcSecret, {
      BIELOS_OIDC_ADAPTER_KEY: oidcEncryptionKey
    });
    const signingKey = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
    const signingKeyId = randomUUID();
    const signingJwks = {
      keys: [{ ...signingKey, kid: signingKeyId, use: "sig", alg: "ES256" }]
    };
    const cookieKey = randomBytes(32).toString("base64url");
    await writeFile(oidcPrivateConfigFile, JSON.stringify({
      adapterKey: oidcEncryptionKey,
      cookieKey,
      signingJwks
    }), { encoding: "utf8", flag: "wx", mode: 0o600 });
    oidcPrivateConfigWritten = true;

    const records = await prisma.$transaction(async (transaction) => {
      const userRecord = await transaction.user.create({
        data: {
          email: user.email,
          emailNormalized: user.email,
          displayName: "E2E User",
          passwordHash: userPasswordHash,
          role: "USER",
          isActive: true,
          accountStatus: "ACTIVE",
          emailVerifiedAt: now
        },
        select: { id: true }
      });
      const adminRecord = await transaction.user.create({
        data: {
          email: admin.email,
          emailNormalized: admin.email,
          displayName: "E2E Admin",
          passwordHash: adminPasswordHash,
          role: "ADMIN",
          isActive: true,
          accountStatus: "ACTIVE",
          emailVerifiedAt: now
        },
        select: { id: true }
      });
      const recoveryReviewerRecord = await transaction.user.create({
        data: {
          email: recoveryReviewer.email,
          emailNormalized: recoveryReviewer.email,
          displayName: "E2E Recovery Reviewer",
          passwordHash: reviewerPasswordHash,
          role: "ADMIN",
          isActive: true,
          accountStatus: "ACTIVE",
          emailVerifiedAt: now
        },
        select: { id: true }
      });
      await transaction.administrativeCredential.create({
        data: { userId: recoveryReviewerRecord.id, passwordHash: reviewerAdministrativePasswordHash, status: "ACTIVE" }
      });
      const connection = await transaction.projectConnection.create({
        data: {
          name: projectName,
          slug: projectSlug,
          origin: "https://project.e2e.invalid",
          launchUrl: projectLaunchUrl,
          enabled: true,
          clientId: projectClientId,
          clientSecretCiphertext,
          redirectUris: []
        },
        select: { id: true }
      });
      const ungrantedConnection = await transaction.projectConnection.create({
        data: {
          name: ungrantedProjectName,
          slug: ungrantedProjectSlug,
          origin: "https://ungranted.e2e.invalid",
          launchUrl: "https://ungranted.e2e.invalid/launch",
          enabled: true,
          clientId: ungrantedProjectClientId,
          clientSecretCiphertext,
          redirectUris: []
        },
        select: { id: true }
      });
      const disabledConnection = await transaction.projectConnection.create({
        data: {
          name: disabledProjectName,
          slug: disabledProjectSlug,
          origin: "https://disabled.e2e.invalid",
          launchUrl: "https://disabled.e2e.invalid/launch",
          enabled: false,
          clientId: disabledProjectClientId,
          clientSecretCiphertext,
          redirectUris: []
        },
        select: { id: true }
      });

      await transaction.userProjectGrant.create({
        data: { userId: userRecord.id, connectionId: connection.id }
      });
      await transaction.userProjectGrant.create({
        data: { userId: userRecord.id, connectionId: disabledConnection.id }
      });
      await transaction.trustedDevice.createMany({
        data: [
          { userId: userRecord.id, deviceIdHash: hashDeviceToken(user.deviceToken), rememberedUntil, strongVerifiedAt: now },
          { userId: adminRecord.id, deviceIdHash: hashDeviceToken(admin.deviceToken), rememberedUntil, strongVerifiedAt: now },
          { userId: recoveryReviewerRecord.id, deviceIdHash: hashDeviceToken(recoveryReviewer.deviceToken), rememberedUntil, strongVerifiedAt: now }
        ]
      });

      return {
        userId: userRecord.id,
        adminId: adminRecord.id,
        recoveryReviewerId: recoveryReviewerRecord.id,
        projectConnectionId: connection.id,
        ungrantedProjectConnectionId: ungrantedConnection.id,
        disabledProjectConnectionId: disabledConnection.id
      };
    });

    seeded = {
      user: { ...user, id: records.userId },
      admin: { ...admin, id: records.adminId },
      recoveryReviewer: { ...recoveryReviewer, id: records.recoveryReviewerId },
      projectName,
      projectSlug,
      projectClientId,
      projectConnectionId: records.projectConnectionId,
      projectLaunchUrl,
      ungrantedProjectName,
      ungrantedProjectSlug,
      ungrantedProjectClientId,
      ungrantedProjectConnectionId: records.ungrantedProjectConnectionId,
      disabledProjectName,
      disabledProjectSlug,
      disabledProjectClientId,
      disabledProjectConnectionId: records.disabledProjectConnectionId,
      oidc: {
        clientId: projectClientId,
        clientSecret: oidcSecret
      }
    };
    await writeFile(fixtureFile, JSON.stringify(seeded), { encoding: "utf8", flag: "wx", mode: 0o600 });
    process.env[FIXTURE_FILE_ENV] = fixtureFile;

    const startedOidcIssuer = startIsolatedService("issuer", {
      ...process.env,
      DATABASE_URL: databaseUrl,
      BIELOS_E2E_OIDC_PRIVATE_CONFIG_FILE: oidcPrivateConfigFile,
      BIELOS_OIDC_ISSUER: "https://portal.localhost:3001",
      BIELOS_OIDC_BIND_ADDRESS: "127.0.0.1",
      OIDC_ISSUER_PORT: "3003"
    }, { manageProcessLifecycle: false }) as ChildProcess;
    oidcIssuerProcess = startedOidcIssuer;
    await waitForOidcIssuer(startedOidcIssuer, signingKeyId);
  } catch {
    let cleanupFailed = false;
    await stopIsolatedService(oidcIssuerProcess).catch(() => { cleanupFailed = true; });
    try {
      if (seeded) await removeFixtureRecords(prisma, seeded);
    } catch {
      cleanupFailed = true;
    }
    if (temporaryDirectory) {
      await removeTemporaryFixture(fixtureFile, temporaryDirectory).catch(() => { cleanupFailed = true; });
    }
    if (oidcPrivateConfigWritten) await removeFile(oidcPrivateConfigFile).catch(() => { cleanupFailed = true; });
    await prisma.$disconnect().catch(() => { cleanupFailed = true; });
    throw new Error(cleanupFailed
      ? "E2E fixture setup failed; scoped cleanup also failed in the validated disposable database."
      : "E2E fixture setup failed in the validated disposable database.");
  }

  const cleanupState = seeded;
  const cleanupFile = fixtureFile;
  const cleanupDirectory = temporaryDirectory;
  if (!cleanupState || !cleanupFile || !cleanupDirectory) {
    await stopIsolatedService(oidcIssuerProcess).catch(() => undefined);
    await prisma.$disconnect();
    throw new Error("E2E fixture setup did not produce a complete fixture.");
  }

  return async () => {
    let cleanupFailed = false;
    await stopIsolatedService(oidcIssuerProcess).catch(() => { cleanupFailed = true; });
    try {
      await removeFixtureRecords(prisma, cleanupState);
    } catch {
      cleanupFailed = true;
    }
    await removeTemporaryFixture(cleanupFile, cleanupDirectory).catch(() => { cleanupFailed = true; });
    await removeFile(oidcPrivateConfigFile).catch(() => { cleanupFailed = true; });
    await prisma.$disconnect().catch(() => { cleanupFailed = true; });
    delete process.env[FIXTURE_FILE_ENV];
    if (cleanupFailed) throw new Error("E2E fixture cleanup failed for run-scoped records.");
  };
}

function validateE2eDatabase(databaseUrl = process.env[E2E_DATABASE_ENV]?.trim()): URL {
  if (!databaseUrl) throw new Error(`${E2E_DATABASE_ENV} is required for database validation.`);
  return assertDisposableCoreTestDatabase(databaseUrl, process.env) as URL;
}

async function removeFixtureRecords(prisma: PrismaClient, fixture: FixtureState): Promise<void> {
  const userIds = [fixture.user.id, fixture.admin.id, fixture.recoveryReviewer.id];
  await prisma.$transaction(async (transaction) => {
    await transaction.oidcArtifact.deleteMany({
      where: {
        OR: [
          { clientIdHash: hashOidcIdentifier(fixture.projectClientId) },
          { accountIdHash: hashOidcIdentifier(fixture.user.id) }
        ]
      }
    });
    await transaction.auditLog.deleteMany({ where: { actorUserId: { in: userIds } } });
    await transaction.user.deleteMany({ where: { id: fixture.user.id, email: fixture.user.email, role: "USER" } });
    await transaction.user.deleteMany({ where: { id: fixture.admin.id, email: fixture.admin.email, role: "ADMIN" } });
    await transaction.user.deleteMany({ where: { id: fixture.recoveryReviewer.id, email: fixture.recoveryReviewer.email, role: "ADMIN" } });
    await transaction.projectConnection.deleteMany({
      where: {
        OR: [
          { id: fixture.projectConnectionId, slug: fixture.projectSlug, clientId: fixture.projectClientId },
          {
            id: fixture.ungrantedProjectConnectionId,
            slug: fixture.ungrantedProjectSlug,
            clientId: fixture.ungrantedProjectClientId
          },
          {
            id: fixture.disabledProjectConnectionId,
            slug: fixture.disabledProjectSlug,
            clientId: fixture.disabledProjectClientId
          }
        ]
      }
    });
  });
}

async function waitForOidcIssuer(child: ChildProcess, expectedSigningKeyId: string): Promise<void> {
  const readinessUrl = "http://127.0.0.1:3003/.well-known/openid-configuration";
  const jwksUrl = "http://127.0.0.1:3003/jwks";
  const deadline = Date.now() + 30_000;
  let startupError: Error | undefined;
  const recordStartupError = (error: Error) => { startupError = error; };
  child.once("error", recordStartupError);
  try {
    while (Date.now() < deadline) {
      if (startupError) throw new Error("E2E OIDC issuer could not start.");
      if (child.exitCode !== null || child.signalCode !== null) throw new Error("E2E OIDC issuer exited during startup.");
      try {
        const response = await fetch(readinessUrl, { signal: AbortSignal.timeout(500) });
        if (response.ok) {
          const metadata: unknown = await response.json();
          if (metadata && typeof metadata === "object" && "issuer" in metadata && metadata.issuer === "https://portal.localhost:3001") {
            const keysResponse = await fetch(jwksUrl, { signal: AbortSignal.timeout(500) });
            const keySet: unknown = keysResponse.ok ? await keysResponse.json() : undefined;
            const hasRunKey = keySet && typeof keySet === "object" && "keys" in keySet && Array.isArray(keySet.keys) &&
              keySet.keys.some((key) => key && typeof key === "object" && "kid" in key && key.kid === expectedSigningKeyId);
            if (hasRunKey && child.exitCode === null && child.signalCode === null) return;
          }
        }
      } catch {
        // The loopback issuer is expected to refuse connections until startup completes.
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error("E2E OIDC issuer did not become ready.");
  } finally {
    child.off("error", recordStartupError);
  }
}

async function stopIsolatedService(child: ChildProcess | undefined): Promise<void> {
  if (!child || await waitForChildExit(child, 0)) return;
  child.kill("SIGTERM");
  if (await waitForChildExit(child, 5_000)) return;
  child.kill("SIGKILL");
  if (!await waitForChildExit(child, 5_000)) throw new Error("E2E OIDC issuer process did not stop.");
}

async function waitForChildExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return new Promise((resolve) => {
    const finish = (exited: boolean) => {
      clearTimeout(timer);
      child.off("exit", onExit);
      resolve(exited);
    };
    const onExit = () => finish(true);
    const timer = setTimeout(() => finish(false), timeoutMs);
    child.once("exit", onExit);
  });
}

async function removeFile(file: string): Promise<void> {
  await unlink(file).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
}

async function removeTemporaryFixture(file: string | undefined, directory: string): Promise<void> {
  if (file) {
    await unlink(file).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
  await rmdir(directory).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
}

async function restrictTemporaryDirectory(directory: string): Promise<void> {
  if (process.platform === "win32") {
    const identity = execFileSync("whoami", [], { encoding: "utf8" }).trim();
    if (!identity || /[\r\n]/u.test(identity)) throw new Error("Could not resolve the current Windows identity.");
    execFileSync("icacls", [directory, "/inheritance:r", "/grant:r", `${identity}:(OI)(CI)F`], { stdio: "ignore" });
    return;
  }
  await chmod(directory, 0o700);
}
