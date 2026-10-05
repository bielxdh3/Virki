export type ProjectConnectionSecretSnapshot = {
  id: string;
  clientId: string;
  enabled: boolean;
  clientSecretCiphertext: string;
};

type SecretRotationTransaction = {
  projectConnection: {
    updateMany(args: {
      where: {
        id: string;
        clientId: string;
        enabled: true;
        clientSecretCiphertext: string;
      };
      data: { clientSecretCiphertext: string };
    }): Promise<{ count: number }>;
  };
};

export async function compareAndSetProjectConnectionSecret(
  transaction: SecretRotationTransaction,
  connection: ProjectConnectionSecretSnapshot,
  nextCiphertext: string
): Promise<boolean> {
  const result = await transaction.projectConnection.updateMany({
    where: {
      id: connection.id,
      clientId: connection.clientId,
      enabled: true,
      clientSecretCiphertext: connection.clientSecretCiphertext
    },
    data: { clientSecretCiphertext: nextCiphertext }
  });
  return result.count === 1;
}
