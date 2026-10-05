import assert from "node:assert/strict";
import test from "node:test";
import { compareAndSetProjectConnectionSecret, type ProjectConnectionSecretSnapshot } from "./connection-secret-rotation";

test("concurrent client-secret rotations allow only one stale snapshot to win", async () => {
  const connection: ProjectConnectionSecretSnapshot = {
    id: "connection-1",
    clientId: "client-1",
    enabled: true,
    clientSecretCiphertext: "ciphertext-before-rotation"
  };
  let storedCiphertext = connection.clientSecretCiphertext;
  const transaction = {
    projectConnection: {
      async updateMany({ where, data }: {
        where: { id: string; clientId: string; enabled: true; clientSecretCiphertext: string };
        data: { clientSecretCiphertext: string };
      }) {
        if (
          where.id !== connection.id
          || where.clientId !== connection.clientId
          || where.enabled !== connection.enabled
          || where.clientSecretCiphertext !== storedCiphertext
        ) return { count: 0 };
        storedCiphertext = data.clientSecretCiphertext;
        return { count: 1 };
      }
    }
  };

  const [firstRotation, concurrentRotation] = await Promise.all([
    compareAndSetProjectConnectionSecret(transaction, connection, "ciphertext-first"),
    compareAndSetProjectConnectionSecret(transaction, connection, "ciphertext-second")
  ]);

  assert.deepEqual([firstRotation, concurrentRotation], [true, false]);
  assert.equal(storedCiphertext, "ciphertext-first");
});
