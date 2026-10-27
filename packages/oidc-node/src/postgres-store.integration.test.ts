import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { EncryptedPostgresTransactionStore, type QueryExecutor } from "./postgres-store.js";
import { hashFlowState, type AuthorizationTransaction } from "./store.js";

/** Real PostgreSQL sessions, with no mock database or optional skip path. */
const execFileAsync = promisify(execFile);
const HEX64 = /^[a-f0-9]{64}$/u;
const CIPHERTEXT = /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u;
// This integration file is also directly runnable. Do not trust a caller's
// Docker context/binary even when bypassing the disposable parent runner.
const { createAdmittedOidcDockerClient } = await import(
  new URL("../../../scripts/lib/disposable-docker-session.mjs", import.meta.url).href
);
const admittedDocker = createAdmittedOidcDockerClient();

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Disposable PG18 runner required: ${name}`);
  return value;
}

function config(): { container: string; role: string; password: string; database: string; schema: string } {
  const container = required("VIRKI_OIDC_PG_CONTAINER");
  const role = required("VIRKI_OIDC_PG_ROLE");
  const password = required("VIRKI_OIDC_PG_PASSWORD");
  const database = required("VIRKI_OIDC_PG_DATABASE");
  const schema = required("VIRKI_OIDC_PG_SCHEMA");
  if (!/^virki-oidc-pg18-[a-f0-9-]{36}$/u.test(container)
    || !/^[a-z][a-z0-9_]{0,30}$/u.test(role)
    || !/^[a-z][a-z0-9_]{0,30}$/u.test(database)
    || !/^[a-z][a-z0-9_]{0,30}$/u.test(schema)
    || !/^[a-f0-9]{64}$/u.test(password)) {
    throw new Error("Invalid isolated PostgreSQL test configuration.");
  }
  return { container, role, password, database, schema };
}

async function psql(sql: string): Promise<string> {
  const c = config();
  try {
    const { stdout } = await execFileAsync(admittedDocker.subprocessEnv.VIRKI_OIDC_DOCKER_BINARY, [
      "--host", admittedDocker.subprocessEnv.DOCKER_HOST,
      "exec", "--env", `PGPASSWORD=${c.password}`, c.container,
      "psql", "--host", "127.0.0.1", "--username", c.role, "--dbname", c.database,
      "--no-psqlrc", "--quiet", "--tuples-only", "--no-align", "--field-separator=|",
      "--set", "ON_ERROR_STOP=1", "--command", sql
    ], { encoding: "utf8", timeout: 30_000, windowsHide: true, maxBuffer: 128 * 1024,
      env: admittedDocker.subprocessEnv });
    return stdout.trim();
  } catch {
    throw new Error("Disposable PostgreSQL statement failed.");
  }
}

function safeHash(hash: string): string {
  assert.match(hash, HEX64);
  return hash;
}

/** Adapter translates only the store's two fixed parameterized statements. */
function executor(options: { loseDeleteResponse?: boolean } = {}): QueryExecutor {
  return {
    async query(text, values) {
      if (text === 'INSERT INTO "VirkiOidcLoginFlow" ("stateHash", "ciphertext", "expiresAt") VALUES ($1, $2, $3)') {
        assert.equal(values.length, 3);
        const hash = safeHash(values[0] as string);
        const ciphertext = values[1];
        assert.equal(typeof ciphertext, "string");
        assert.match(ciphertext as string, CIPHERTEXT);
        assert.ok(values[2] instanceof Date && Number.isFinite(values[2].getTime()));
        await psql(`INSERT INTO "VirkiOidcLoginFlow" ("stateHash", "ciphertext", "expiresAt") VALUES ('${hash}', '${ciphertext}', '${(values[2] as Date).toISOString()}'::timestamptz)`);
        return { rows: [] };
      }
      if (text === 'DELETE FROM "VirkiOidcLoginFlow" WHERE "stateHash" = $1 RETURNING "ciphertext" AS ciphertext, "expiresAt" AS expires_at') {
        assert.equal(values.length, 1);
        const hash = safeHash(values[0] as string);
        const value = await psql(`WITH consumed AS (DELETE FROM "VirkiOidcLoginFlow" WHERE "stateHash" = '${hash}' RETURNING "ciphertext", "expiresAt") SELECT "ciphertext", to_char("expiresAt" AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM consumed`);
        if (options.loseDeleteResponse) throw new Error("Simulated caller crash after durable DELETE.");
        if (!value) return { rows: [] };
        const divider = value.indexOf("|");
        assert.ok(divider > 0);
        return { rows: [{ ciphertext: value.slice(0, divider), expires_at: value.slice(divider + 1) }] };
      }
      throw new Error("Unexpected SQL from OIDC transaction store.");
    }
  };
}

function record(expiresAt = Date.now() + 300_000): AuthorizationTransaction {
  return {
    stateHash: hashFlowState(randomBytes(32).toString("base64url")),
    browserHash: hashFlowState(randomBytes(32).toString("base64url")),
    codeVerifier: randomBytes(32).toString("base64url"),
    nonce: randomBytes(32).toString("base64url"),
    issuer: "https://issuer.example.test",
    clientId: "rp-disposable-test",
    redirectUri: "https://rp.example.test/oidc/callback",
    expiresAt
  };
}

if (process.env.VIRKI_OIDC_CHILD_FLOW === "1") {
  // Independent Node process, with a fresh store instance and PostgreSQL session.
  const key = required("VIRKI_OIDC_CHILD_KEY");
  const hash = safeHash(required("VIRKI_OIDC_CHILD_HASH"));
  assert.match(key, HEX64);
  const consumed = await new EncryptedPostgresTransactionStore(executor(), Buffer.from(key, "hex")).take(hash);
  process.stdout.write(consumed === null ? "MISS" : "WINNER");
} else {

test("PG18 independent RP-owned table uses TIMESTAMPTZ and America/Porto_Velho", async () => {
  const c = config();
  const meta = await psql(`SELECT current_user, current_setting('TimeZone'), pg_typeof("expiresAt")::text FROM "VirkiOidcLoginFlow" LIMIT 1`);
  // An empty table returns no rows; inspect the catalog independently.
  assert.equal(meta, "");
  const actual = await psql(`SELECT current_user, current_setting('TimeZone'), pg_get_userbyid(tbl.relowner), att.atttypid::regtype::text FROM pg_class tbl JOIN pg_namespace ns ON ns.oid=tbl.relnamespace JOIN pg_attribute att ON att.attrelid=tbl.oid AND att.attname='expiresAt' WHERE ns.nspname='${c.schema}' AND tbl.relname='VirkiOidcLoginFlow'`);
  assert.deepEqual(actual.split("|"), [c.role, "America/Porto_Velho", c.role, "timestamp with time zone"]);
  assert.equal(await psql(`SELECT count(*) FROM information_schema.columns WHERE table_schema='${c.schema}' AND table_name='VirkiOidcLoginFlow'`), "3");
});

test("PG18 persists only authenticated ciphertext and single-use restart replay", async () => {
  const key = randomBytes(32);
  const first = new EncryptedPostgresTransactionStore(executor(), key);
  const tx = record();
  await first.put(tx);
  const persisted = await psql(`SELECT "ciphertext" FROM "VirkiOidcLoginFlow" WHERE "stateHash"='${safeHash(tx.stateHash)}'`);
  assert.match(persisted, CIPHERTEXT);
  assert.equal(persisted.includes(tx.nonce), false);
  assert.equal(persisted.includes(tx.codeVerifier), false);
  assert.equal(persisted.includes(tx.browserHash), false);
  assert.equal(persisted.includes(tx.issuer), false);
  assert.deepEqual(await new EncryptedPostgresTransactionStore(executor(), key).take(tx.stateHash), tx);
  assert.equal(await first.take(tx.stateHash), null);
});

test("PG18 24 concurrent independent DELETE RETURNING sessions yield one callback winner", async () => {
  const key = randomBytes(32);
  const tx = record();
  await new EncryptedPostgresTransactionStore(executor(), key).put(tx);
  const participants = Array.from({ length: 24 }, () => new EncryptedPostgresTransactionStore(executor(), key));
  const results = await Promise.all(participants.map((store) => store.take(tx.stateHash)));
  assert.equal(results.filter((v) => v !== null).length, 1);
  assert.deepEqual(results.find(Boolean), tx);
  const replay = await Promise.all(participants.map((store) => store.take(tx.stateHash)));
  assert.ok(replay.every((v) => v === null));
});

test("PG18 two independent Node processes competing for same state yield one winner", async () => {
  const key = randomBytes(32);
  const tx = record();
  await new EncryptedPostgresTransactionStore(executor(), key).put(tx);
  const cli = required("VIRKI_OIDC_TSX_PATH");
  const run = () => execFileAsync(process.execPath, [cli, fileURLToPath(import.meta.url)], {
    env: {
      ...process.env,
      VIRKI_OIDC_CHILD_FLOW: "1",
      VIRKI_OIDC_CHILD_KEY: key.toString("hex"),
      VIRKI_OIDC_CHILD_HASH: tx.stateHash
    }, encoding: "utf8", windowsHide: true, timeout: 30_000
  });
  const results = await Promise.all([run(), run()]);
  assert.deepEqual(results.map(({ stdout }) => stdout).sort(), ["MISS", "WINNER"]);
  assert.equal(await new EncryptedPostgresTransactionStore(executor(), key).take(tx.stateHash), null);
});

test("PG18 rejects invalid/expired writes and expires/deletes an existing flow", async () => {
  const store = new EncryptedPostgresTransactionStore(executor(), randomBytes(32));
  await assert.rejects(store.put(record(Date.now() - 1_000)), /transaction unavailable/u);
  const tx = record();
  await store.put(tx);
  await assert.rejects(store.put(tx), /statement failed/u);
  await psql(`UPDATE "VirkiOidcLoginFlow" SET "expiresAt" = now() - interval '1 second' WHERE "stateHash"='${safeHash(tx.stateHash)}'`);
  assert.equal(await store.take(tx.stateHash), null);
  assert.equal(await store.take(tx.stateHash), null);
});

test("PG18 row locked while expiry changes cannot be consumed after lock release", async () => {
  const store = new EncryptedPostgresTransactionStore(executor(), randomBytes(32));
  const tx = record();
  await store.put(tx);
  const marker = randomBytes(8).toString("hex");
  const locked = psql(`BEGIN; UPDATE "VirkiOidcLoginFlow" SET "expiresAt"=now()-interval '1 second' WHERE "stateHash"='${safeHash(tx.stateHash)}'; SELECT pg_sleep(4); COMMIT; /* oidc-row-lock-${marker} */`);
  let acquired = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    const visible = await psql(`SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND state='active' AND query LIKE '%/* oidc-row-lock-${marker} */%'`);
    if (Number(visible) > 0) { acquired = true; break; }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.ok(acquired, "PG18 expiry writer must hold the row lock before a competing take");
  const start = Date.now();
  const take = store.take(tx.stateHash);
  await locked;
  assert.equal(await take, null);
  assert.ok(Date.now() - start >= 300, "take must await the locked row before observing expiry");
  assert.equal(await store.take(tx.stateHash), null);
});

test("PG18 transaction ROLLBACK restores deleted row for subsequent valid callback", async () => {
  const key = randomBytes(32);
  const store = new EncryptedPostgresTransactionStore(executor(), key);
  const tx = record();
  await store.put(tx);
  const rolledBack = await psql(`BEGIN; DELETE FROM "VirkiOidcLoginFlow" WHERE "stateHash"='${safeHash(tx.stateHash)}' RETURNING "stateHash"; ROLLBACK`);
  assert.equal(rolledBack, tx.stateHash);
  assert.deepEqual(await new EncryptedPostgresTransactionStore(executor(), key).take(tx.stateHash), tx);
  assert.equal(await store.take(tx.stateHash), null);
});

test("PG18 tamper, wrong encryption key and wrong bound stateHash fail closed and consume once", async () => {
  const key = randomBytes(32);
  const store = new EncryptedPostgresTransactionStore(executor(), key);
  const wrongKey = record();
  await store.put(wrongKey);
  await assert.rejects(new EncryptedPostgresTransactionStore(executor(), randomBytes(32)).take(wrongKey.stateHash), /transaction unavailable/u);
  assert.equal(await store.take(wrongKey.stateHash), null);

  const tampered = record();
  await store.put(tampered);
  await psql(`UPDATE "VirkiOidcLoginFlow" SET "ciphertext"='v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AAAA' WHERE "stateHash"='${safeHash(tampered.stateHash)}'`);
  await assert.rejects(store.take(tampered.stateHash), /transaction unavailable/u);
  assert.equal(await store.take(tampered.stateHash), null);

  const rebound = record();
  const alternate = record();
  await store.put(rebound);
  await psql(`UPDATE "VirkiOidcLoginFlow" SET "stateHash"='${safeHash(alternate.stateHash)}' WHERE "stateHash"='${safeHash(rebound.stateHash)}'`);
  await assert.rejects(store.take(alternate.stateHash), /transaction unavailable/u);
  assert.equal(await store.take(alternate.stateHash), null);
  assert.equal(await store.take(rebound.stateHash), null);
});

test("PG18 lost process response after committed DELETE cannot revive state", async () => {
  const key = randomBytes(32);
  const tx = record();
  await new EncryptedPostgresTransactionStore(executor(), key).put(tx);
  await assert.rejects(
    new EncryptedPostgresTransactionStore(executor({ loseDeleteResponse: true }), key).take(tx.stateHash),
    /Simulated caller crash/u
  );
  assert.equal(await new EncryptedPostgresTransactionStore(executor(), key).take(tx.stateHash), null);
});

test("PG18 unavailability never falls back to unencrypted or in-memory transactions", async () => {
  const unavailable: QueryExecutor = { async query() { throw new Error("Database disconnected."); } };
  const store = new EncryptedPostgresTransactionStore(unavailable, randomBytes(32));
  const tx = record();
  await assert.rejects(store.put(tx), /Database disconnected/u);
  await assert.rejects(store.take(tx.stateHash), /Database disconnected/u);
});

}
