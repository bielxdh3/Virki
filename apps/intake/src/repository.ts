import { createHash, randomBytes } from "node:crypto";
import { createRequestKey } from "@bielos/database";
import { hashPassword } from "@bielos/auth";
import { enqueueEmailMessageForClient } from "@bielos/auth/email";
import type { PrismaClient } from "@bielos/database";
import type { IntakeRepository, IntakeSubmission, PublicIntakeModule } from "./handler";

const VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000;

type IntakeCatalogRow = {
  id: string;
  key: string;
  name: string;
  runtimeAvailability: "AVAILABLE" | "UNAVAILABLE" | "INERT";
};

export function createDatabaseIntakeRepository(
  client: PrismaClient,
  publicOrigin: string
): IntakeRepository {
  return {
    async listPublicModules(): Promise<PublicIntakeModule[]> {
      const modules = await listPublicCatalog(client);
      return modules.map((module) => ({ ...module }));
    },
    async submitApplication(input: IntakeSubmission): Promise<void> {
      const now = new Date();
      await client.$transaction(async (transaction) => {
        const lockKey = `intake:${input.abuseIdentifierHash}`;
        await transaction.$queryRaw`
          SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}, 0)) IS NULL AS "locked"
        `;

        const requestedKeys = input.modules.map((module) => module.key);
        const catalog = await listPublicCatalog(transaction);
        const publicModules = catalog.filter((module) => requestedKeys.includes(module.key));
        if (publicModules.length === 0) {
          return;
        }

        const cutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const recent = await transaction.applicationModuleDecision.findMany({
          where: {
            moduleId: { in: publicModules.map((module) => module.id) },
            createdAt: { gte: cutoff },
            application: { emailNormalized: input.emailNormalized }
          },
          select: { moduleId: true }
        });
        const recentModuleIds = new Set(recent.map((module) => module.moduleId));
        const newModules = publicModules.filter((module) => !recentModuleIds.has(module.id));
        if (newModules.length === 0) {
          return;
        }

        const verificationToken = randomBytes(32).toString("base64url");
        const application = await transaction.accountApplication.create({
          data: {
            emailNormalized: input.emailNormalized,
            displayName: input.displayName,
            abuseIdentifierHash: input.abuseIdentifierHash,
            moduleDecisions: {
              create: newModules.map((module) => ({
                dedupeKey: createRequestKey(input.emailNormalized, module.id, now),
                moduleId: module.id,
                reason: input.modules.find((requested) => requested.key === module.key)!.reason
              }))
            }
          },
          select: { id: true }
        });

        await transaction.applicationEmailVerification.create({
          data: {
            applicationId: application.id,
            tokenHash: hashToken(verificationToken),
            expiresAt: new Date(now.getTime() + VERIFICATION_TTL_MS),
            updatedAt: now
          },
          select: { id: true }
        });

        await enqueueEmailMessageForClient(transaction, {
          idempotencyKey: `application-verification:${application.id}`,
          kind: "APPLICATION_EMAIL_VERIFICATION",
          recipientEmail: input.emailNormalized,
          locale: input.locale,
          now,
          payload: {
            publicValues: { displayName: input.displayName ?? "" },
            protectedValues: {
              actionUrl: `${publicOrigin}/apply/verify?token=${verificationToken}`
            }
          }
        });
      });
    },
    async verifyApplicationEmail(token: string): Promise<void> {
      const now = new Date();
      await client.$transaction(async (transaction) => {
        const verification = await transaction.applicationEmailVerification.findFirst({
          where: { tokenHash: hashToken(token), consumedAt: null, expiresAt: { gt: now } },
          select: { id: true, applicationId: true }
        });
        if (!verification) {
          throw new Error("Verification rejected.");
        }
        const updated = await transaction.applicationEmailVerification.updateMany({
          where: { id: verification.id, consumedAt: null },
          data: { consumedAt: now, updatedAt: now }
        });
        if (updated.count !== 1) {
          throw new Error("Verification rejected.");
        }
        await transaction.accountApplication.updateMany({
          where: { id: verification.applicationId, status: "PENDING_EMAIL" },
          data: { status: "EMAIL_VERIFIED", updatedAt: now }
        });
      });
    },
    async activateApplication(token: string, password: string): Promise<void> {
      const now = new Date();
      const passwordHash = await hashPassword(password);
      const userId = randomBytes(16).toString("hex");
      const [result] = await client.$queryRaw<Array<{ activated: boolean }>>`
        SELECT "bielos_intake_activate_application"(
          ${hashToken(token)},
          ${userId},
          ${passwordHash},
          CAST(${now} AS timestamp(3))
        ) AS "activated"
      `;
      if (!result?.activated) {
        throw new Error("Activation rejected.");
      }
    }
  };
}

async function listPublicCatalog(
  client: Pick<PrismaClient, "$queryRaw">
): Promise<IntakeCatalogRow[]> {
  return client.$queryRaw<IntakeCatalogRow[]>`
    SELECT "id", "key", "name", "runtimeAvailability"
    FROM "IntakePublicModuleCatalog"
    ORDER BY "name" ASC
  `;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
