import { createHash, randomBytes } from "node:crypto";
import {
  createRequestKey,
  isPublicRequestableModule,
  type InitialModuleCatalogEntry
} from "@bielos/database";
import { enqueueEmailMessageForClient } from "@bielos/auth/email";
import type { PrismaClient } from "@bielos/database";
import type { IntakeRepository, IntakeSubmission, PublicIntakeModule } from "./handler";

const VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000;

export function createDatabaseIntakeRepository(
  client: PrismaClient,
  publicOrigin: string
): IntakeRepository {
  return {
    async listPublicModules(): Promise<PublicIntakeModule[]> {
      const modules = await client.moduleCatalog.findMany({
        where: { visibility: "PUBLIC", requestable: true },
        select: { key: true, name: true, runtimeAvailability: true },
        orderBy: { name: "asc" }
      });
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
        const catalog = await transaction.moduleCatalog.findMany({
          where: {
            key: { in: requestedKeys },
            visibility: "PUBLIC",
            requestable: true
          },
          select: {
            id: true,
            key: true,
            visibility: true,
            requestable: true
          }
        });
        const publicModules = catalog.filter(isPublicRequestableModule);
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
          }
        });

        await transaction.applicationEmailVerification.create({
          data: {
            applicationId: application.id,
            tokenHash: hashToken(verificationToken),
            expiresAt: new Date(now.getTime() + VERIFICATION_TTL_MS),
            updatedAt: now
          }
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
    }
  };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
