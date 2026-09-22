import assert from "node:assert/strict";
import test from "node:test";
import { encryptOidcPayload } from "@bielos/auth/oidc-secrets";
import { PrismaOidcAdapter } from "./adapter";

const env = { BIELOS_OIDC_ADAPTER_KEY: "ab".repeat(32) };

test("OIDC artifact consume uses compare-and-set so a code cannot be replayed concurrently", async () => {
  const original = process.env.BIELOS_OIDC_ADAPTER_KEY;
  process.env.BIELOS_OIDC_ADAPTER_KEY = env.BIELOS_OIDC_ADAPTER_KEY;
  const whereArgs: unknown[] = [];
  let updates = 0;
  const database = {
    oidcArtifact: {
      findUnique: async () => ({ payloadCiphertext: encryptOidcPayload(JSON.stringify({ jti: "short-lived" }), env) }),
      updateMany: async (args: unknown) => { whereArgs.push(args); updates += 1; return { count: 1 }; }
    }
  };
  try {
    await new PrismaOidcAdapter("AuthorizationCode", database as never).consume("one-time-code");
    assert.equal(updates, 1);
    assert.match(JSON.stringify(whereArgs[0]), /consumedAt/);
  } finally {
    if (original === undefined) delete process.env.BIELOS_OIDC_ADAPTER_KEY;
    else process.env.BIELOS_OIDC_ADAPTER_KEY = original;
  }
});

test("OIDC artifact consume rejects a raced or already-consumed artifact", async () => {
  const original = process.env.BIELOS_OIDC_ADAPTER_KEY;
  process.env.BIELOS_OIDC_ADAPTER_KEY = env.BIELOS_OIDC_ADAPTER_KEY;
  const database = { oidcArtifact: {
    findUnique: async () => ({ payloadCiphertext: encryptOidcPayload(JSON.stringify({ jti: "short-lived" }), env) }),
    updateMany: async () => ({ count: 0 })
  } };
  try {
    await assert.rejects(() => new PrismaOidcAdapter("AuthorizationCode", database as never).consume("one-time-code"));
  } finally {
    if (original === undefined) delete process.env.BIELOS_OIDC_ADAPTER_KEY;
    else process.env.BIELOS_OIDC_ADAPTER_KEY = original;
  }
});
