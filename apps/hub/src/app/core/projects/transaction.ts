import { prisma, type Prisma } from "@bielos/database";

const SERIALIZABLE_RETRY_LIMIT = 3;

export async function runCoreProjectSerializableTransaction<T>(
  operation: (transaction: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  for (let attempt = 1; attempt <= SERIALIZABLE_RETRY_LIMIT; attempt += 1) {
    try {
      return await prisma.$transaction(operation, { isolationLevel: "Serializable" });
    } catch (error) {
      if (!isRetryableTransactionError(error) || attempt === SERIALIZABLE_RETRY_LIMIT) {
        throw error;
      }
    }
  }

  throw new Error("Core project transaction retry exhausted.");
}

export async function lockCoreProjectMutation(
  transaction: Prisma.TransactionClient,
  projectId: string
): Promise<void> {
  const lockKey = `bielos-core-project:${projectId}`;

  await transaction.$queryRaw`
    SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}, 0)) IS NULL AS "locked"
  `;
}

function isRetryableTransactionError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "P2034"
  );
}
