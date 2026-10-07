import { generateKeyPairSync, randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";

const issuer = "http://127.0.0.1:3010";

test("E2E JWKS accepts only this run's public test keys", async () => {
  const registrationToken = process.env.VIRKI_E2E_JWKS_REGISTRATION_TOKEN;
  expect(registrationToken).toBeTruthy();
  if (!registrationToken) throw new Error("E2E JWKS registration token is unavailable.");

  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = randomUUID();
  const publicJwk = {
    ...publicKey.export({ format: "jwk" }),
    kid: keyId,
    use: "sig",
    alg: "RS256"
  };

  const unauthorized = await fetch(`${issuer}/__test__/keys`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(publicJwk)
  });
  expect(unauthorized.status).toBe(403);

  const wrongRegistrationToken = `${registrationToken[0] === "A" ? "B" : "A"}${registrationToken.slice(1)}`;
  const wrongToken = await fetch(`${issuer}/__test__/keys`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${wrongRegistrationToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(publicJwk)
  });
  expect(wrongToken.status).toBe(403);

  const authorized = await fetch(`${issuer}/__test__/keys`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${registrationToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(publicJwk)
  });
  expect(authorized.status).toBe(204);

  const privateJwk = {
    ...publicJwk,
    kid: randomUUID(),
    d: privateKey.export({ format: "jwk" }).d
  };
  const privateKeyResponse = await fetch(`${issuer}/__test__/keys`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${registrationToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(privateJwk)
  });
  expect(privateKeyResponse.status).toBe(400);

  const keySetResponse = await fetch(`${issuer}/cdn-cgi/access/certs`);
  expect(keySetResponse.status).toBe(200);
  const keySet: unknown = await keySetResponse.json();
  expect(isJwks(keySet)).toBe(true);
  if (!isJwks(keySet)) throw new Error("E2E JWKS response is invalid.");
  const registered = keySet.keys.find((key) => key.kid === keyId);
  expect(registered).toMatchObject({ kty: "RSA", kid: keyId, use: "sig", alg: "RS256" });
  expect(registered).not.toHaveProperty("d");
  expect(keySet.keys.some((key) => key.kid === privateJwk.kid)).toBe(false);
});

function isJwks(value: unknown): value is { keys: Array<Record<string, unknown>> } {
  return Boolean(value && typeof value === "object" && "keys" in value && Array.isArray(value.keys));
}
