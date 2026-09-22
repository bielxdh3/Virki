import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const KEY_BYTES = 32;

export function hashOidcIdentifier(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function encryptOidcClientSecret(secret: string, env: NodeJS.ProcessEnv = process.env): string {
  const key = readKey(env.BIELOS_OIDC_ADAPTER_KEY);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), ciphertext.toString("base64url")].join(".");
}

export function decryptOidcClientSecret(value: string, env: NodeJS.ProcessEnv = process.env): string {
  const [version, iv, tag, ciphertext, extra] = value.split(".");
  if (version !== "v1" || !iv || !tag || !ciphertext || extra !== undefined) {
    throw new Error("Invalid encrypted OIDC client secret.");
  }
  const decipher = createDecipheriv("aes-256-gcm", readKey(env.BIELOS_OIDC_ADAPTER_KEY), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64url")), decipher.final()]).toString("utf8");
}

export function encryptOidcPayload(value: string, env: NodeJS.ProcessEnv = process.env): string {
  const key = readKey(env.BIELOS_OIDC_ADAPTER_KEY);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), ciphertext.toString("base64url")].join(".");
}

export function decryptOidcPayload(value: string, env: NodeJS.ProcessEnv = process.env): string {
  const [version, iv, tag, ciphertext, extra] = value.split(".");
  if (version !== "v1" || !iv || !tag || !ciphertext || extra !== undefined) {
    throw new Error("Invalid encrypted OIDC data.");
  }
  const decipher = createDecipheriv("aes-256-gcm", readKey(env.BIELOS_OIDC_ADAPTER_KEY), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64url")), decipher.final()]).toString("utf8");
}

function readKey(value: string | undefined): Buffer {
  if (!value || !/^[a-f0-9]{64}$/iu.test(value)) {
    throw new Error("OIDC adapter encryption key is unavailable.");
  }
  const key = Buffer.from(value, "hex");
  if (key.length !== KEY_BYTES) throw new Error("OIDC adapter encryption key is invalid.");
  return key;
}
