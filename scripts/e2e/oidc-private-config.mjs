import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { isAbsolute } from "node:path";

export function createE2eOidcPrivateConfiguration(file) {
  if (!file || !isAbsolute(file)) throw new Error("E2E private OIDC configuration path is invalid.");
  const signingKey = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const signingJwks = { keys: [{ ...signingKey, kid: randomUUID(), use: "sig", alg: "ES256" }] };
  writeFileSync(file, JSON.stringify({
    adapterKey: randomBytes(32).toString("hex"),
    cookieKey: randomBytes(32).toString("base64url"),
    signingJwks
  }), { encoding: "utf8", flag: "wx", mode: 0o600 });
}

export function readE2eOidcPrivateConfiguration(file) {
  if (!file || !isAbsolute(file)) throw new Error("E2E private OIDC configuration path is invalid.");
  const config = JSON.parse(readFileSync(file, "utf8"));
  const signingKey = config?.signingJwks?.keys?.[0];
  if (!config || typeof config !== "object" || Array.isArray(config) ||
    typeof config.adapterKey !== "string" || !/^[a-f0-9]{64}$/iu.test(config.adapterKey) ||
    typeof config.cookieKey !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(config.cookieKey) ||
    !Array.isArray(config.signingJwks?.keys) || config.signingJwks.keys.length !== 1 ||
    !signingKey || signingKey.kty !== "EC" || signingKey.crv !== "P-256" ||
    signingKey.use !== "sig" || signingKey.alg !== "ES256" ||
    typeof signingKey.kid !== "string" || !signingKey.kid ||
    typeof signingKey.d !== "string" || !signingKey.d) {
    throw new Error("E2E private OIDC configuration is invalid.");
  }
  return { adapterKey: config.adapterKey, cookieKey: config.cookieKey, signingJwks: config.signingJwks, signingKeyId: signingKey.kid };
}
