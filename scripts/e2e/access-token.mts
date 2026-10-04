import { createSign, generateKeyPairSync, randomUUID, type KeyObject } from "node:crypto";
import type { Page } from "@playwright/test";

const HUB_URL = "https://hub.localhost:3001";

type RegisteredSigningKey = { kid: string; privateKey: KeyObject };

let registeredSigningKey: Promise<RegisteredSigningKey> | undefined;

export async function addCloudflareAccessHeader(page: Page): Promise<void> {
  await page.route(`${HUB_URL}/**`, async (route) => {
    const token = await createCloudflareAccessToken();
    await route.continue({
      headers: {
        ...route.request().headers(),
        "cf-access-jwt-assertion": token
      }
    });
  });
}

async function createCloudflareAccessToken(): Promise<string> {
  const audience = process.env.BIELOS_E2E_ACCESS_AUDIENCE;
  const issuer = process.env.BIELOS_E2E_ACCESS_ISSUER;
  if (!audience || !issuer) throw new Error("Synthetic E2E Cloudflare Access signing configuration is unavailable.");

  const { kid, privateKey } = await getRegisteredSigningKey(issuer);
  const issuedAt = Math.floor(Date.now() / 1000);
  const protectedHeader = encode({ alg: "RS256", typ: "JWT", kid });
  const payload = encode({ iss: issuer, aud: audience, iat: issuedAt, exp: issuedAt + 60 });
  const signingInput = `${protectedHeader}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${signer.sign(privateKey, "base64url")}`;
}

async function getRegisteredSigningKey(issuer: string): Promise<RegisteredSigningKey> {
  const pendingKey = registeredSigningKey ??= registerSigningKey(issuer);
  try {
    return await pendingKey;
  } catch (error) {
    if (registeredSigningKey === pendingKey) registeredSigningKey = undefined;
    throw error;
  }
}

async function registerSigningKey(issuer: string): Promise<RegisteredSigningKey> {
  const kid = randomUUID();
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicJwk = {
    ...publicKey.export({ format: "jwk" }),
    kid,
    use: "sig",
    alg: "RS256"
  };
  await registerTestSigningKey(issuer, publicJwk);
  return { kid, privateKey };
}

function encode(value: Record<string, string | number>): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

async function registerTestSigningKey(issuer: string, jwk: Record<string, unknown>): Promise<void> {
  const registrationToken = process.env.BIELOS_E2E_JWKS_REGISTRATION_TOKEN;
  if (!registrationToken) throw new Error("Synthetic E2E Cloudflare Access registration token is unavailable.");

  const response = await fetch(`${issuer}/__test__/keys`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${registrationToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(jwk)
  });
  if (!response.ok) throw new Error("Synthetic E2E Cloudflare Access key registration failed.");
}
