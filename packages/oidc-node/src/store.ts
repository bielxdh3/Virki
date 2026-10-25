import { createHash } from "node:crypto";

/** Secrets are server-side only. Do not serialize this record into cookies, responses or logs. */
export type AuthorizationTransaction = {
  stateHash: string;
  browserHash: string;
  codeVerifier: string;
  nonce: string;
  issuer: string;
  clientId: string;
  redirectUri: string;
  expiresAt: number;
};

export type TransactionStore = {
  /** Must enforce unique stateHash and persist before redirecting the user. */
  put(record: AuthorizationTransaction): Promise<void>;
  /** Must DELETE atomically and return the original record to at most one caller. */
  take(stateHash: string): Promise<AuthorizationTransaction | null>;
};

export function hashFlowState(value: string): string {
  return createHash("sha256").update("virki-oidc-node-state\0", "utf8").update(value, "utf8").digest("hex");
}

/** For tests and single-process demos only. Use the PostgreSQL adapter for multi-process services. */
export class MemoryTransactionStore implements TransactionStore {
  private readonly records = new Map<string, AuthorizationTransaction>();

  async put(record: AuthorizationTransaction): Promise<void> {
    if (record.expiresAt <= Date.now() || this.records.has(record.stateHash)) throw new Error("OIDC transaction unavailable.");
    this.records.set(record.stateHash, structuredClone(record));
  }

  async take(stateHash: string): Promise<AuthorizationTransaction | null> {
    const record = this.records.get(stateHash);
    this.records.delete(stateHash);
    return record && record.expiresAt > Date.now() ? structuredClone(record) : null;
  }
}
