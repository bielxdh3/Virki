import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes, createHash } from "node:crypto";
import {
  chmodSync, copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync,
  readdirSync, rmSync, writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN, GENESIS_HEAD, GENESIS_RECEIPT,
  verifyIndependentWitnessCasReceipt, verifyIndependentWitnessHead,
} from "./lib/offline-independent-witness-service.mjs";

const isLinux = process.platform === "linux";
const nonce = () => randomBytes(32).toString("hex");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const script = fileURLToPath(new URL("./offline-independent-witness-server.mjs", import.meta.url));

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "virki-witness-w7-"));
  const db = join(root, "database");
  const anchors = join(root, "anchors");
  const sockets = join(root, "sockets");
  for (const path of [db, anchors, sockets]) mkdirSync(path, { mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signerKey = join(root, "witness-private.pem");
  writeFileSync(signerKey, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  chmodSync(signerKey, 0o600);
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
  const pinSha256 = digest(publicKey.export({ format: "der", type: "spki" }));
  const hostIdentitySha256 = nonce();
  const ledgerIdSha256 = nonce();
  const children = [];
  const env = {
    ...process.env,
    VIRKI_DISPOSABLE_WITNESS_SERVICE: "1",
    VIRKI_WITNESS_DB_DIRECTORY: db,
    VIRKI_WITNESS_ANCHOR_DIRECTORY: anchors,
    VIRKI_WITNESS_SIGNER_KEY: signerKey,
    VIRKI_WITNESS_SIGNER_PIN: pinSha256,
    VIRKI_WITNESS_HOST_SHA256: hostIdentitySha256,
    VIRKI_WITNESS_LEDGER_SHA256: ledgerIdSha256,
  };
  return { root, db, anchors, sockets, children, publicKeyPem, pinSha256,
    hostIdentitySha256, ledgerIdSha256, env,
    cleanup: () => {
      for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      rmSync(root, { force: true, recursive: true });
    } };
}

async function start(f, name, extra = {}) {
  const socket = join(f.sockets, `${name}.sock`);
  const child = spawn(process.execPath, [script], {
    env: { ...f.env, ...extra, VIRKI_WITNESS_SOCKET: socket }, stdio: ["ignore", "pipe", "pipe"],
  });
  f.children.push(child);
  let output = "";
  let errors = "";
  const ready = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`witness start timed out: ${errors}`)), 7000);
    child.stdout.on("data", (chunk) => {
      output += chunk;
      if (output.includes("WITNESS_DISPOSABLE_READY")) {
        clearTimeout(timeout);
        resolve(true);
      }
    });
    child.stderr.on("data", (chunk) => { errors += chunk; });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      if (!output.includes("WITNESS_DISPOSABLE_READY")) reject(new Error(`witness start failed ${code}: ${errors}`));
    });
  });
  assert.equal(ready, true);
  return { child, socket };
}

async function stop(server) {
  if (!server || server.child.exitCode !== null || server.child.signalCode !== null) return;
  server.child.kill("SIGTERM");
  await once(server.child, "exit");
}

async function send(socket, endpoint, payload) {
  const body = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath: socket, path: endpoint, method: "POST", agent: false,
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
    (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => {
        try { resolve({ code: res.statusCode, body: JSON.parse(text) }); }
        catch (error) { reject(error); }
      });
    });
    request.once("error", reject);
    request.end(body);
  });
}

function nextRequest(f, state, headSha = nonce().slice(0, 40)) {
  return {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: nonce(), requestId: nonce(),
    hostIdentitySha256: f.hostIdentitySha256, ledgerIdSha256: f.ledgerIdSha256,
    expectedSequence: state.sequence, expectedHeadSha: state.headSha,
    expectedReceiptSha256: state.receiptSha256, nextHeadSha: headSha,
    transitionSha256: nonce(),
  };
}

function readRequest(f) {
  return {
    version: 1, domain: WITNESS_READ_DOMAIN, challenge: nonce(),
    hostIdentitySha256: f.hostIdentitySha256, ledgerIdSha256: f.ledgerIdSha256,
  };
}

async function head(server, fixtureData, minimum) {
  const request = readRequest(fixtureData);
  const res = await send(server.socket, "/v1/head", request);
  assert.equal(res.code, 200);
  assert.equal(res.body.witnessCasAuthorized, false);
  assert.equal(res.body.deployAuthorized, false);
  const proof = verifyIndependentWitnessHead({
    receipt: res.body.receipt, request,
    publicKeyPem: fixtureData.publicKeyPem, pinSha256: fixtureData.pinSha256,
    minimumSequence: minimum?.sequence ?? 0,
    minimumReceiptSha256: minimum?.receiptSha256,
  });
  return { sequence: proof.sequence, headSha: proof.headSha, receiptSha256: proof.receiptSha256 };
}

async function cas(server, f, request, expectedCode = 201) {
  const response = await send(server.socket, "/v1/cas", request);
  assert.equal(response.code, expectedCode, JSON.stringify(response.body));
  assert.equal(response.body.deployAuthorized, false);
  assert.equal(response.body.witnessCasAuthorized, false);
  if (expectedCode !== 201) return response.body;
  return verifyIndependentWitnessCasReceipt({
    receipt: response.body.receipt, request,
    publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
  });
}

test("native Linux disposable independent Ed25519 witness CAS and rollback resistance", { skip: !isLinux }, async (t) => {
  const f = fixture();
  let server;
  try {
    await t.test("genesis signed head, pin mismatch and challenge replay are rejected", async () => {
      server = await start(f, "first");
      const genesis = await head(server, f);
      assert.deepEqual(genesis, { sequence: 0, headSha: GENESIS_HEAD, receiptSha256: GENESIS_RECEIPT });
      const request = readRequest(f);
      const response = await send(server.socket, "/v1/head", request);
      assert.equal(response.code, 200);
      const verifyOptions = {
        receipt: response.body.receipt, request,
        pinSha256: f.pinSha256, publicKeyPem: f.publicKeyPem,
      };
      assert.throws(() => verifyIndependentWitnessHead({ ...verifyOptions, request: { ...request, challenge: nonce() } }), /refused/u);
      assert.throws(() => verifyIndependentWitnessHead({ ...verifyOptions, pinSha256: nonce() }), /refused/u);
      assert.throws(() => verifyIndependentWitnessHead({ ...verifyOptions, nowSeconds: 1 }), /refused/u);
    });

    let current;
    await t.test("concurrent CAS across two OS processes yields one winner, signed proof and 409 fencing", async () => {
      const other = await start(f, "second");
      try {
        const initial = await head(server, f);
        const r1 = nextRequest(f, initial);
        const r2 = nextRequest(f, initial);
        const results = await Promise.all([
          send(server.socket, "/v1/cas", r1), send(other.socket, "/v1/cas", r2),
        ]);
        assert.deepEqual(results.map((r) => r.code).sort(), [201, 409]);
        const winningIndex = results.findIndex((r) => r.code === 201);
        const accepted = results[winningIndex].body.receipt;
        const winningRequest = [r1, r2][winningIndex];
        const verified = verifyIndependentWitnessCasReceipt({
          receipt: accepted, request: winningRequest,
          publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
        });
        assert.equal(verified.sequence, 1);
        assert.equal(verified.deployAuthorized, false);
        assert.throws(() => verifyIndependentWitnessCasReceipt({
          receipt: accepted, request: { ...winningRequest, challenge: nonce() },
          publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
        }), /refused/u);
        assert.throws(() => verifyIndependentWitnessCasReceipt({
          receipt: accepted, request: winningRequest,
          publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
          nowSeconds: accepted.message.expiresAt,
        }), /refused/u);
        assert.equal((await send(server.socket, "/v1/cas", winningRequest)).code, 409);
        assert.equal((await send(other.socket, "/v1/cas", { ...winningRequest, requestId: nonce() })).code, 409);
        assert.equal((await send(server.socket, "/v1/cas", { ...winningRequest, ledgerIdSha256: nonce() })).code, 400);
        assert.equal((await send(server.socket, "/v1/cas", { ...winningRequest, extra: true })).code, 400);
        const next = nextRequest(f, verified);
        current = await cas(other, f, next);
        assert.deepEqual(await head(server, f, current), {
          sequence: 2, headSha: next.nextHeadSha, receiptSha256: current.receiptSha256,
        });
      } finally { await stop(other); }
    });

    await t.test("crash before COMMIT is absent after restart", async () => {
      await stop(server);
      const faulty = await start(f, "before", { VIRKI_DISPOSABLE_WITNESS_FAULT: "beforeCommit" });
      const expected = current;
      await assert.rejects(send(faulty.socket, "/v1/cas", nextRequest(f, expected)), /ECONNRESET|socket hang up/u);
      await once(faulty.child, "exit");
      assert.equal(faulty.child.exitCode, 74);
      server = await start(f, "after-before");
      const restored = await head(server, f, expected);
      assert.deepEqual(restored, {
        sequence: expected.sequence, headSha: expected.headSha,
        receiptSha256: expected.receiptSha256,
      });
    });

    await t.test("crash after durable SQLite COMMIT reconstructs missing signed anchor", async () => {
      await stop(server);
      const faulty = await start(f, "middle", { VIRKI_DISPOSABLE_WITNESS_FAULT: "afterCommitBeforeAnchor" });
      const request = nextRequest(f, current);
      await assert.rejects(send(faulty.socket, "/v1/cas", request), /ECONNRESET|socket hang up/u);
      await once(faulty.child, "exit");
      assert.equal(faulty.child.exitCode, 73);
      assert.equal(readdirSync(f.anchors).length, 2);
      server = await start(f, "after-middle");
      const recovered = await head(server, f);
      assert.equal(recovered.sequence, 3);
      assert.equal(recovered.headSha, request.nextHeadSha);
      assert.equal(readdirSync(f.anchors).length, 3);
      assert.equal((await send(server.socket, "/v1/cas", request)).code, 409);
      current = recovered;
    });

    await t.test("crash after anchor remains committed across restart", async () => {
      await stop(server);
      const faulty = await start(f, "after", { VIRKI_DISPOSABLE_WITNESS_FAULT: "afterAnchor" });
      const request = nextRequest(f, current);
      await assert.rejects(send(faulty.socket, "/v1/cas", request), /ECONNRESET|socket hang up/u);
      await once(faulty.child, "exit");
      assert.equal(faulty.child.exitCode, 75);
      server = await start(f, "after-anchor");
      current = await head(server, f);
      assert.equal(current.sequence, 4);
      assert.equal(current.headSha, request.nextHeadSha);
      assert.equal(readdirSync(f.anchors).length, 4);
    });

    await t.test("restoring an older committed SQLite image is refused due to independent anchors", async () => {
      await stop(server);
      const oldDb = join(f.root, "previous.sqlite");
      const dbFile = join(f.db, "witness.sqlite");
      assert.equal(existsSync(`${dbFile}-wal`), false);
      copyFileSync(dbFile, oldDb);
      server = await start(f, "ahead");
      const successor = nextRequest(f, current);
      current = await cas(server, f, successor);
      assert.equal(current.sequence, 5);
      await stop(server);
      copyFileSync(oldDb, dbFile);
      await assert.rejects(start(f, "rollback"), /rollback: durable anchor ahead of database/u);
    });
  } finally {
    await stop(server);
    f.cleanup();
  }
});

test("tampered signed SQL history and corrupted durable anchor refuse boot", { skip: !isLinux }, async (t) => {
  const f = fixture();
  let server;
  try {
    server = await start(f, "first");
    const current = await head(server, f);
    await cas(server, f, nextRequest(f, current));
    await stop(server);
    const anchor = join(f.anchors, "00000001.receipt");
    const before = readFileSync(anchor, "utf8");
    writeFileSync(anchor, before.replace(/a/u, "b"));
    await t.test("modified anchor rejected", async () => {
      await assert.rejects(start(f, "modified-anchor"), /corrupted anchor/u);
    });
    writeFileSync(anchor, before);
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(join(f.db, "witness.sqlite"));
    db.prepare("UPDATE events SET signature=? WHERE seq=1").run("A".repeat(86) + "==");
    db.close();
    await t.test("forged database signature rejected before any receipt", async () => {
      await assert.rejects(start(f, "modified-sql"), /invalid signed history receipt/u);
    });
  } finally {
    await stop(server);
    f.cleanup();
  }
});
