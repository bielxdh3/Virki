import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { MemoryTransactionStore, hashFlowState, type AuthorizationTransaction } from "./store.js";
import { EncryptedPostgresTransactionStore } from "./postgres-store.js";

function transaction(now = Date.now()): AuthorizationTransaction {
  return {
    stateHash: hashFlowState(randomBytes(32).toString("base64url")),
    browserHash: hashFlowState("browser-opaque-binding"),
    codeVerifier: randomBytes(32).toString("base64url"),
    nonce: randomBytes(32).toString("base64url"),
    issuer: "https://portal.biel.dev.br",
    clientId: "biel_test",
    redirectUri: "https://rp.example.test/callback",
    expiresAt: now + 300_000
  };
}

test("memory store consumes precisely once, including simultaneous callbacks", async () => {
  const store = new MemoryTransactionStore();
  const flow = transaction();
  await store.put(flow);
  const results = await Promise.all(Array.from({ length: 32 }, () => store.take(flow.stateHash)));
  assert.equal(results.filter(Boolean).length, 1);
  assert.equal(await store.take(flow.stateHash), null);
});

test("memory store rejects duplicate state and expired state", async () => {
  const store = new MemoryTransactionStore();
  const flow = transaction();
  await store.put(flow);
  await assert.rejects(store.put(flow));
  const expired = transaction(Date.now() - 310_000);
  await assert.rejects(store.put(expired));
});

test("postgres store encrypts flow before SQL and atomically deletes via RETURNING", async () => {
  const writes = new Map<string, { ciphertext: string; expires_at: Date }>();
  const calls: Array<{ text: string; values: readonly unknown[] }> = [];
  const db = {
    async query(text: string, values: readonly unknown[]) {
      calls.push({ text, values });
      if (text.startsWith("INSERT")) {
        if (writes.has(String(values[0]))) throw new Error("duplicate");
        writes.set(String(values[0]), { ciphertext: String(values[1]), expires_at: values[2] as Date });
        return { rows: [] };
      }
      if (text.startsWith("DELETE")) {
        const row = writes.get(String(values[0]));
        writes.delete(String(values[0]));
        return { rows: row ? [row] : [] };
      }
      throw new Error("unsupported query");
    }
  };
  const key = randomBytes(32);
  const store = new EncryptedPostgresTransactionStore(db, key);
  const flow = transaction();
  await store.put(flow);
  assert.ok(calls[0]?.text.includes("INSERT"));
  assert.equal(JSON.stringify(calls[0]?.values).includes(flow.nonce), false);
  assert.equal(JSON.stringify(calls[0]?.values).includes(flow.codeVerifier), false);
  assert.deepEqual(await store.take(flow.stateHash), flow);
  assert.equal(await store.take(flow.stateHash), null);
  const other = new EncryptedPostgresTransactionStore(db, randomBytes(32));
  await store.put(transaction());
  const hash = [...writes.keys()][0]!;
  await assert.rejects(other.take(hash), /transaction unavailable/u);
});
