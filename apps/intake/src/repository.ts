import { createHash, randomBytes } from "node:crypto";
import {
  createRequestKey,
  isPublicRequestableModule,
  type InitialModuleCatalogEntry
} from "@bielos/database";
import { hashPassword } from "@bielos/auth";
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
      await client.$transaction(async (transaction) => {
        const activation = await transaction.accountActivation.findFirst({
          where: { tokenHash: hashToken(token), consumedAt: null, expiresAt: { gt: now } },
          select: {
            id: true,
            application: {
              select: {
                id: true,
                emailNormalized: true,
                displayName: true,
                status: true,
                moduleDecisions: {
                  where: { status: "APPROVED" },
                  select: { moduleId: true, accessDurationKind: true, accessExpiresAt: true }
                }
              }
            }
          }
        });
        if (
          !activation ||
          !["APPROVED", "PARTIALLY_APPROVED"].includes(activation.application.status)
        ) {
          throw new Error("Activation rejected.");
        }

        const user = await transaction.user.create({
          data: {
            email: activation.application.emailNormalized,
            emailNormalized: activation.application.emailNormalized,
            displayName: activation.application.displayName,
            passwordHash,
            accountStatus: "ACTIVE",
            emailVerifiedAt: now
          },
          select: { id: true }
        });

        if (activation.application.moduleDecisions.length > 0) {
          await transaction.moduleAccessGrant.createMany({
            data: activation.application.moduleDecisions.map((decision) => ({
              userId: user.id,
              moduleId: decision.moduleId,
              accessDurationKind: decision.accessDurationKind,
              expiresAt: decision.accessExpiresAt
            }))
          });
        }

        await transaction.accountActivation.updateMany({
          where: { id: activation.id, consumedAt: null },
          data: { consumedAt: now, updatedAt: now }
        });
        await transaction.accountApplication.update({
          where: { id: activation.application.id },
          data: { status: "ACTIVATED", activatedUserId: user.id, updatedAt: now }
        });
      });
    }
  };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
