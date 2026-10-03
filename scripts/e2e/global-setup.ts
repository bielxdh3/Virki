import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { chmod, mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hashPassword } from "@bielos/auth";
import { encryptOidcClientSecret } from "@bielos/auth/oidc-secrets";
import { hashDeviceToken } from "@bielos/auth/security";
import { PrismaClient } from "@bielos/database";

// @ts-expect-error This existing JavaScript safety helper has no declaration file.
import { assertDisposableCoreTestDatabase } from "../core-test-database-safety.mjs";

const E2E_DATABASE_ENV = "BIELOS_E2E_DATABASE_URL";
const FIXTURE_FILE_ENV = "BIELOS_E2E_AUTH_FIXTURE_FILE";

type AccountFixture = {
  id: string;
  email: string;
  password: string;
  deviceToken: string;
};

type FixtureState = {
  user: AccountFixture;
  admin: AccountFixture;
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
};

if (process.argv[2] === "--validate-database") {
  validateE2eDatabase();
}

export default async function globalSetup(): Promise<(() => Promise<void>) | void> {
  const databaseUrl = process.env[E2E_DATABASE_ENV]?.trim();
  delete process.env[FIXTURE_FILE_ENV];
  if (!databaseUrl) return;

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

  let temporaryDirectory: string | undefined;
  let fixtureFile: string | undefined;
  let seeded: FixtureState | undefined;
  try {
    temporaryDirectory = await mkdtemp(join(tmpdir(), "bielos-e2e-auth-"));
    fixtureFile = join(temporaryDirectory, "fixture.json");
    await restrictTemporaryDirectory(temporaryDirectory);

    const [userPasswordHash, adminPasswordHash] = await Promise.all([
      hashPassword(user.password),
      hashPassword(admin.password)
    ]);
    const now = new Date();
    const rememberedUntil = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const oidcSecret = randomBytes(48).toString("base64url");
    const oidcEncryptionKey = randomBytes(32).toString("hex");
    const clientSecretCiphertext = encryptOidcClientSecret(oidcSecret, {
      BIELOS_OIDC_ADAPTER_KEY: oidcEncryptionKey
    });

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
          { userId: adminRecord.id, deviceIdHash: hashDeviceToken(admin.deviceToken), rememberedUntil, strongVerifiedAt: now }
        ]
      });

      return {
        userId: userRecord.id,
        adminId: adminRecord.id,
        projectConnectionId: connection.id,
        ungrantedProjectConnectionId: ungrantedConnection.id,
        disabledProjectConnectionId: disabledConnection.id
      };
    });

    seeded = {
      user: { ...user, id: records.userId },
      admin: { ...admin, id: records.adminId },
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
      disabledProjectConnectionId: records.disabledProjectConnectionId
    };
    await writeFile(fixtureFile, JSON.stringify(seeded), { encoding: "utf8", flag: "wx", mode: 0o600 });
    process.env[FIXTURE_FILE_ENV] = fixtureFile;
  } catch {
    let cleanupFailed = false;
    try {
      if (seeded) await removeFixtureRecords(prisma, seeded);
    } catch {
      cleanupFailed = true;
    }
    if (temporaryDirectory) {
      await removeTemporaryFixture(fixtureFile, temporaryDirectory).catch(() => { cleanupFailed = true; });
    }
    await prisma.$disconnect().catch(() => { cleanupFailed = true; });
    throw new Error(cleanupFailed
      ? "E2E fixture setup failed; scoped cleanup also failed in the validated disposable database."
      : "E2E fixture setup failed in the validated disposable database.");
  }

  const cleanupState = seeded;
  const cleanupFile = fixtureFile;
  const cleanupDirectory = temporaryDirectory;
  if (!cleanupState || !cleanupFile || !cleanupDirectory) {
    await prisma.$disconnect();
    throw new Error("E2E fixture setup did not produce a complete fixture.");
  }

  return async () => {
    let cleanupFailed = false;
    try {
      await removeFixtureRecords(prisma, cleanupState);
    } catch {
      cleanupFailed = true;
    }
    await removeTemporaryFixture(cleanupFile, cleanupDirectory).catch(() => { cleanupFailed = true; });
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
  const userIds = [fixture.user.id, fixture.admin.id];
  await prisma.$transaction(async (transaction) => {
    await transaction.auditLog.deleteMany({ where: { actorUserId: { in: userIds } } });
    await transaction.user.deleteMany({ where: { id: fixture.user.id, email: fixture.user.email, role: "USER" } });
    await transaction.user.deleteMany({ where: { id: fixture.admin.id, email: fixture.admin.email, role: "ADMIN" } });
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
