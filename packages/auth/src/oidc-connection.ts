import type { Prisma } from "@virki/database";
import { hashOidcIdentifier } from "./oidc-secrets";

// Cleanup needs a fresh statement snapshot after waiting for an OIDC writer's connection lock.
export const PROJECT_CONNECTION_MUTATION_ISOLATION_LEVEL = "ReadCommitted" as const;

export async function setProjectConnectionEnabledInTransaction(
  transaction: Prisma.TransactionClient,
  connectionId: string,
  enabled: boolean
): Promise<{ id: string; clientId: string }> {
  const connection = await transaction.projectConnection.update({
    where: { id: connectionId },
    data: { enabled },
    select: { id: true, clientId: true }
  });
  if (!enabled) await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } });
  return connection;
}

export async function deleteProjectConnectionInTransaction(
  transaction: Prisma.TransactionClient,
  connectionId: string
): Promise<{ id: string; clientId: string }> {
  const [connection] = await transaction.$queryRaw<Array<{ id: string; clientId: string }>>`
    SELECT "id", "clientId"
    FROM "ProjectConnection"
    WHERE "id" = ${connectionId}
    FOR UPDATE
  `;
  if (!connection) throw new Error("Connection was not found.");
  await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } });
  await transaction.projectConnection.delete({ where: { id: connection.id } });
  return connection;
}
