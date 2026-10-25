import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { AuthorizationTransaction, TransactionStore } from "./store";

/** A pg.Pool or pg.Client satisfies this interface. Never interpolate SQL values. */
export type QueryExecutor = {
  query(text: string, values: readonly unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
};

const TABLE = '"VirkiOidcLoginFlow"';
const AAD_PREFIX = "virki-oidc-node-flow-v1:";

/** Expects the schema documented in docs/sso-node-sdk.md. Safe across hosts/workers. */
export class EncryptedPostgresTransactionStore implements TransactionStore {
  private readonly key: Buffer;

  constructor(private readonly db: QueryExecutor, key: Uint8Array) {
    if (key.byteLength !== 32) throw new Error("OIDC transaction encryption key must be exactly 32 bytes.");
    this.key = Buffer.from(key);
  }

  async put(record: AuthorizationTransaction): Promise<void> {
    if (record.expiresAt <= Date.now() || !/^[a-f0-9]{64}$/u.test(record.stateHash)) throw new Error("OIDC transaction unavailable.");
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(AAD_PREFIX + record.stateHash, "utf8"));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(record), "utf8"), cipher.final()]);
    const payload = ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), encrypted.toString("base64url")].join(".");
    await this.db.query(`INSERT INTO ${TABLE} ("stateHash", "ciphertext", "expiresAt") VALUES ($1, $2, $3)`, [record.stateHash, payload, new Date(record.expiresAt)]);
  }

  async take(stateHash: string): Promise<AuthorizationTransaction | null> {
    if (!/^[a-f0-9]{64}$/u.test(stateHash)) return null;
    // A single DELETE ... RETURNING is the concurrency boundary. Do NOT SELECT then DELETE.
    const result = await this.db.query(`DELETE FROM ${TABLE} WHERE "stateHash" = $1 RETURNING "ciphertext" AS ciphertext, "expiresAt" AS expires_at`, [stateHash]);
    if (result.rows.length === 0) return null;
    if (result.rows.length !== 1) throw new Error("OIDC transaction unavailable.");
    const { ciphertext, expires_at: expiry } = result.rows[0]!;
    if (typeof ciphertext !== "string" || !expiry || !Number.isFinite(new Date(expiry as string).getTime()) || new Date(expiry as string).getTime() <= Date.now()) return null;
    try {
      const [version, iv, tag, data, extra] = ciphertext.split(".");
      if (version !== "v1" || !iv || !tag || !data || extra !== undefined) throw new Error();
      const decipher = createDecipheriv("aes-256-gcm", this.key, Buffer.from(iv, "base64url"), { authTagLength: 16 });
      decipher.setAAD(Buffer.from(AAD_PREFIX + stateHash, "utf8"));
      decipher.setAuthTag(Buffer.from(tag, "base64url"));
      const record: unknown = JSON.parse(Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8"));
      if (!isAuthorizationTransaction(record) || record.stateHash !== stateHash || record.expiresAt <= Date.now()) return null;
      return record;
    } catch {
      throw new Error("OIDC transaction unavailable.");
    }
  }
}

function isAuthorizationTransaction(value: unknown): value is AuthorizationTransaction {
  if (!value || typeof value !== "object") return false;
  const object = value as Record<string, unknown>;
  return ["stateHash", "browserHash", "codeVerifier", "nonce", "issuer", "clientId", "redirectUri"].every((field) => typeof object[field] === "string" && (object[field] as string).length > 0)
    && typeof object.expiresAt === "number" && Number.isSafeInteger(object.expiresAt);
}
