import { createPrivateKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { SignJWT } from "jose";
import { validateCloudflareAccessJwt } from "@virki/auth/cloudflare-access";
import type { Page } from "@playwright/test";

const HUB_URL = process.env.VIRKI_E2E_HUB_MODE === "production" ? "https://hub.localhost" : "https://hub.localhost:3001";

type RegisteredSigningKey = { kid: string; privateKey: KeyObject };

let registeredSigningKey: Promise<RegisteredSigningKey> | undefined;

export async function addCloudflareAccessHeader(page: Page, options: { hubOnlyBrowserRedirects?: boolean } = {}): Promise<void> {
  if (options.hubOnlyBrowserRedirects) {
    // This option is restricted to the dedicated Hub reviewer page. A fixed,
    // independently validated synthetic Access assertion lets Chromium handle
    // the real form POST, 303, Set-Cookie and next GET without a route callback
    // carrying stale request headers across navigation. Never use on a page
    // that subsequently navigates to the public USER Portal.
    await page.setExtraHTTPHeaders({ "cf-access-jwt-assertion": await createCloudflareAccessToken(900) });
    return;
  }
  await page.context().route(`${HUB_URL}/**`, async (route) => {
    const token = await createCloudflareAccessToken();
    await route.continue({
      headers: {
        ...route.request().headers(),
        "cf-access-jwt-assertion": token
      }
    });
  });
}

async function createCloudflareAccessToken(ttlSeconds = 120): Promise<string> {
  const audience = process.env.VIRKI_E2E_ACCESS_AUDIENCE;
  const issuer = process.env.VIRKI_E2E_ACCESS_ISSUER;
  if (!audience || !issuer) throw new Error("Synthetic E2E Cloudflare Access signing configuration is unavailable.");

  const { kid, privateKey } = await getRegisteredSigningKey(issuer);
  const issuedAt = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(issuedAt)
    .setNotBefore(issuedAt)
    .setExpirationTime(issuedAt + ttlSeconds)
    .sign(privateKey);
  const verification = await validateCloudflareAccessJwt(new Headers({ "cf-access-jwt-assertion": token }), {
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: audience,
    CLOUDFLARE_TEAM_DOMAIN: issuer
  });
  if (!verification.allowed) throw new Error(`Synthetic E2E Cloudflare Access JWT did not validate (${verification.reason ?? verification.status}).`);
  return token;
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
  const keyFile = process.env.VIRKI_E2E_ACCESS_SIGNING_KEY_FILE;
  if (!keyFile) throw new Error("Synthetic E2E Cloudflare Access signing key is unavailable.");
  let key: unknown;
  try {
    key = JSON.parse(readFileSync(keyFile, "utf8"));
  } catch {
    throw new Error("Synthetic E2E Cloudflare Access signing key is invalid.");
  }
  if (!isSigningKey(key)) throw new Error("Synthetic E2E Cloudflare Access signing key is invalid.");
  await registerTestSigningKey(issuer, key.publicJwk);
  return { kid: key.kid, privateKey: createPrivateKey(key.privateKey) };
}

async function registerTestSigningKey(issuer: string, jwk: Record<string, unknown>): Promise<void> {
  const registrationToken = process.env.VIRKI_E2E_JWKS_REGISTRATION_TOKEN;
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

function isSigningKey(value: unknown): value is { kid: string; publicJwk: Record<string, unknown>; privateKey: string } {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  const publicJwk = candidate.publicJwk;
  if (!publicJwk || typeof publicJwk !== "object") return false;
  const jwk = publicJwk as Record<string, unknown>;
  return typeof candidate.kid === "string" && candidate.kid.length > 0 &&
    typeof candidate.privateKey === "string" && candidate.privateKey.includes("PRIVATE KEY") &&
    jwk.kid === candidate.kid && jwk.kty === "RSA" && jwk.alg === "RS256" && jwk.use === "sig" &&
    typeof jwk.n === "string" && typeof jwk.e === "string";
}
