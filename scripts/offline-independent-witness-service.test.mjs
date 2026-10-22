import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes, createHash, sign } from "node:crypto";
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
  independentWitnessOwnerCasSigningBytes,
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
  const { privateKey: ownerPrivateKey, publicKey: ownerPublicKey } = generateKeyPairSync("ed25519");
  const signerKey = join(root, "witness-private.pem");
  writeFileSync(signerKey, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  chmodSync(signerKey, 0o600);
  const ownerPublicKeyFile = join(root, "owner-public.pem");
  writeFileSync(ownerPublicKeyFile, ownerPublicKey.export({ format: "pem", type: "spki" }), { mode: 0o600 });
  const ownerPinSha256 = digest(ownerPublicKey.export({ format: "der", type: "spki" }));
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
    VIRKI_WITNESS_OWNER_PUBLIC_KEY: ownerPublicKeyFile,
    VIRKI_WITNESS_OWNER_PIN: ownerPinSha256,
    VIRKI_WITNESS_HOST_SHA256: hostIdentitySha256,
    VIRKI_WITNESS_LEDGER_SHA256: ledgerIdSha256,
  };
  return { root, db, anchors, sockets, children, publicKeyPem, pinSha256, privateKey,
    ownerPrivateKey, ownerPublicKeyPem: ownerPublicKey.export({ format: "pem", type: "spki" }),
    ownerPinSha256,
    hostIdentitySha256, ledgerIdSha256, env,
    cleanup: () => {
      for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      rmSync(root, { force: true, recursive: true });
    } };
}

// Preload at the filesystem boundary in real Node processes. These hooks make
// the crash and interleaving deterministic without relying on scheduler luck.
function faultPreload(f, name, source) {
  const file = join(f.root, `${name}.cjs`);
  writeFileSync(file, source);
  return { NODE_OPTIONS: `--require=${file}` };
}

async function waitForFile(file) {
  const deadline = Date.now() + 5000;
  while (!existsSync(file) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.ok(existsSync(file), `interleaving marker missing: ${file}`);
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
  return authorizeCas(f, {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: nonce(), requestId: nonce(),
    hostIdentitySha256: f.hostIdentitySha256, ledgerIdSha256: f.ledgerIdSha256,
    expectedSequence: state.sequence, expectedHeadSha: state.headSha,
    expectedReceiptSha256: state.receiptSha256, nextHeadSha: headSha,
    transitionSha256: nonce(), ownerExpiresAt: Math.floor(Date.now() / 1000) + 30,
  });
}

function authorizeCas(f, request) {
  const unsigned = { ...request };
  delete unsigned.ownerSignature;
  return { ...unsigned, ownerSignature: sign(null,
    independentWitnessOwnerCasSigningBytes(unsigned), f.ownerPrivateKey).toString("base64") };
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
    ownerPublicKeyPem: f.ownerPublicKeyPem, ownerPinSha256: f.ownerPinSha256,
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
          ownerPublicKeyPem: f.ownerPublicKeyPem, ownerPinSha256: f.ownerPinSha256,
        });
        assert.equal(verified.sequence, 1);
        assert.equal(verified.deployAuthorized, false);
        assert.throws(() => verifyIndependentWitnessCasReceipt({
          receipt: accepted, request: { ...winningRequest, challenge: nonce() },
          publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
          ownerPublicKeyPem: f.ownerPublicKeyPem, ownerPinSha256: f.ownerPinSha256,
        }), /refused/u);
        assert.throws(() => verifyIndependentWitnessCasReceipt({
          receipt: accepted, request: { ...winningRequest, ownerSignature: "A".repeat(86) + "==" },
          publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
          ownerPublicKeyPem: f.ownerPublicKeyPem, ownerPinSha256: f.ownerPinSha256,
        }), /refused/u);
        assert.throws(() => verifyIndependentWitnessCasReceipt({
          receipt: accepted, request: winningRequest,
          publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
          nowSeconds: accepted.message.expiresAt,
          ownerPublicKeyPem: f.ownerPublicKeyPem, ownerPinSha256: f.ownerPinSha256,
        }), /refused/u);
        assert.equal((await send(server.socket, "/v1/cas", winningRequest)).code, 409);
        assert.equal((await send(other.socket, "/v1/cas", authorizeCas(f,
          { ...winningRequest, requestId: nonce() }))).code, 409);
        assert.equal((await send(server.socket, "/v1/cas", { ...winningRequest, ledgerIdSha256: nonce() })).code, 400);
        assert.equal((await send(server.socket, "/v1/cas", { ...winningRequest, extra: true })).code, 400);
        const next = nextRequest(f, verified);
        current = await cas(other, f, next);
        assert.equal((await send(server.socket, "/v1/cas",
          nextRequest(f, current, verified.headSha))).code, 409);
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

test("partial anchor write crash remains recoverable from independently signed SQLite history", { skip: !isLinux }, async () => {
  const f = fixture();
  let server;
  try {
    server = await start(f, "baseline");
    const initial = await head(server, f);
    await stop(server);
    const injected = faultPreload(f, "crash-mid-write", `
      const fs = require("node:fs");
      const original = fs.writeSync;
      fs.writeSync = function(fd, buffer, offset, length, ...rest) {
        const target = fs.readlinkSync("/proc/self/fd/" + fd);
        if (target.includes("/anchors/")) {
          original.call(fs, fd, buffer, offset, Math.max(1, Math.floor(length / 2)), ...rest);
          process.exit(76);
        }
        return original.call(fs, fd, buffer, offset, length, ...rest);
      };
      require("node:module").syncBuiltinESMExports();
    `);
    const faulty = await start(f, "partial", injected);
    const request = nextRequest(f, initial);
    await assert.rejects(send(faulty.socket, "/v1/cas", request), /ECONNRESET|socket hang up/u);
    if (faulty.child.exitCode === null) await once(faulty.child, "exit");
    assert.equal(faulty.child.exitCode, 76);
    server = await start(f, "restored");
    const recovered = await head(server, f);
    assert.equal(recovered.sequence, 1);
    assert.equal(recovered.headSha, request.nextHeadSha);
    assert.equal((await send(server.socket, "/v1/cas", request)).code, 409);
  } finally { await stop(server); f.cleanup(); }
});

test("HEAD or fresh constructor cannot mistake concurrent SQLite COMMIT and anchor publication for rollback", { skip: !isLinux }, async (t) => {
  for (const mode of ["constructor", "head"]) {
    await t.test(mode, async () => {
      const f = fixture();
      let writer;
      let reader;
      try {
        writer = await start(f, "writer");
        const initial = await head(writer, f);
        const marker = join(f.root, "snapshot-held");
        const injected = faultPreload(f, `hold-${mode}`, `
          const fs = require("node:fs");
          const original = fs.readdirSync;
          let count = 0;
          fs.readdirSync = function(path, ...args) {
            if (path === process.env.VIRKI_WITNESS_ANCHOR_DIRECTORY && ++count === ${mode === "head" ? 2 : 1}) {
              fs.writeFileSync(${JSON.stringify(marker)}, "ready");
              Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 900);
            }
            return original.call(fs, path, ...args);
          };
          require("node:module").syncBuiltinESMExports();
        `);
        if (mode === "constructor") {
          const startup = start(f, "reader", injected);
          await waitForFile(marker);
          const request = nextRequest(f, initial);
          const [newReader, committed] = await Promise.all([startup, cas(writer, f, request)]);
          reader = newReader;
          assert.equal(committed.sequence, 1);
        } else {
          reader = await start(f, "reader", injected);
          const pendingHead = send(reader.socket, "/v1/head", readRequest(f));
          await waitForFile(marker);
          const request = nextRequest(f, initial);
          const [response, committed] = await Promise.all([pendingHead, cas(writer, f, request)]);
          assert.equal(response.code, 200, JSON.stringify(response.body));
          assert.equal(committed.sequence, 1);
        }
        assert.equal((await head(reader, f)).sequence, 1);
      } finally { await stop(reader); await stop(writer); f.cleanup(); }
    });
  }
});

test("two processes publishing one committed anchor never overwrite or expose an incomplete receipt", { skip: !isLinux }, async () => {
  const f = fixture();
  let writer;
  let recoveringReader;
  try {
    const marker = join(f.root, "anchor-before-link");
    const injected = faultPreload(f, "pause-link", `
      const fs = require("node:fs");
      const original = fs.linkSync;
      fs.linkSync = function(source, target) {
        if (target.startsWith(process.env.VIRKI_WITNESS_ANCHOR_DIRECTORY + "/")) {
          fs.writeFileSync(${JSON.stringify(marker)}, "ready");
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
        }
        return original.call(fs, source, target);
      };
      require("node:module").syncBuiltinESMExports();
    `);
    writer = await start(f, "paused-writer", injected);
    const initial = await head(writer, f);
    const request = nextRequest(f, initial);
    const pendingCas = send(writer.socket, "/v1/cas", request);
    await waitForFile(marker);
    recoveringReader = await start(f, "concurrent-recovery");
    const recovery = await head(recoveringReader, f);
    assert.equal(recovery.sequence, 1);
    assert.equal(recovery.headSha, request.nextHeadSha);
    const response = await pendingCas;
    assert.equal(response.code, 201, JSON.stringify(response.body));
    const verified = verifyIndependentWitnessCasReceipt({
      receipt: response.body.receipt, request,
      publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
      ownerPublicKeyPem: f.ownerPublicKeyPem, ownerPinSha256: f.ownerPinSha256,
    });
    assert.equal(verified.receiptSha256, recovery.receiptSha256);
    assert.equal(readdirSync(f.anchors).filter((name) => name.endsWith(".receipt")).length, 1);
  } finally { await stop(recoveringReader); await stop(writer); f.cleanup(); }
});

test("CAS signing is independently authenticated by a pinned owner key, not the witness signer", { skip: !isLinux }, async () => {
  const f = fixture();
  let server;
  try {
    await assert.rejects(start(f, "owner-pin-mismatch", {
      VIRKI_WITNESS_OWNER_PIN: nonce(),
    }), /owner verification key must be independently pinned/u);
    await assert.rejects(start(f, "owner-key-equals-signer", {
      VIRKI_WITNESS_OWNER_PUBLIC_KEY: f.env.VIRKI_WITNESS_SIGNER_KEY,
      VIRKI_WITNESS_OWNER_PIN: f.pinSha256,
    }), /owner verification key/u);
    server = await start(f, "authenticated");
    const initial = await head(server, f);
    const valid = nextRequest(f, initial);
    const { privateKey: attackerKey } = generateKeyPairSync("ed25519");
    const wrongSignature = sign(null,
      independentWitnessOwnerCasSigningBytes(valid), attackerKey).toString("base64");
    for (const candidate of [
      { ...valid, ownerSignature: undefined },
      { ...valid, ownerSignature: wrongSignature },
      { ...valid, requestId: nonce() },
      { ...valid, challenge: nonce() },
      { ...valid, nextHeadSha: nonce().slice(0, 40) },
      { ...valid, ownerSignature: "not-base64" },
    ]) {
      assert.equal((await send(server.socket, "/v1/cas", candidate)).code, 400);
      assert.equal((await head(server, f)).sequence, 0);
    }
    const accepted = await cas(server, f, valid);
    assert.equal(accepted.sequence, 1);
    assert.equal((await send(server.socket, "/v1/cas", valid)).code, 409);
  } finally { await stop(server); f.cleanup(); }
});

test("receipt verifier independently rejects forged owner signature and altered owner expiry even with valid witness signature", { skip: !isLinux }, async () => {
  const f = fixture();
  let server;
  try {
    server = await start(f, "owner-proof");
    const request = nextRequest(f, await head(server, f));
    const response = await send(server.socket, "/v1/cas", request);
    assert.equal(response.code, 201, JSON.stringify(response.body));
    const receipt = response.body.receipt;
    const options = {
      receipt, request, publicKeyPem: f.publicKeyPem, pinSha256: f.pinSha256,
      ownerPublicKeyPem: f.ownerPublicKeyPem, ownerPinSha256: f.ownerPinSha256,
      nowSeconds: receipt.message.issuedAt,
    };
    assert.equal(verifyIndependentWitnessCasReceipt(options).sequence, 1);
    assert.equal(receipt.message.ownerSignature, request.ownerSignature);
    assert.equal(receipt.message.ownerExpiresAt, request.ownerExpiresAt);

    // A compromised receipt signer can re-sign a forged message, but it must
    // never impersonate the separately pinned owner of a CAS transition.
    const witnessResign = (message) => {
      const signature = sign(null, Buffer.from(JSON.stringify(message)), f.privateKey).toString("base64");
      return { message, signature, receiptSha256: digest(JSON.stringify({ message, signature })) };
    };
    const { privateKey: attackerKey, publicKey: attackerPublicKey } = generateKeyPairSync("ed25519");
    const forgedRequest = { ...request, ownerSignature: sign(null,
      independentWitnessOwnerCasSigningBytes(request), attackerKey).toString("base64") };
    const forgedMessage = { ...receipt.message, ownerSignature: forgedRequest.ownerSignature,
      ownerSignatureSha256: digest(forgedRequest.ownerSignature) };
    assert.throws(() => verifyIndependentWitnessCasReceipt({
      ...options, request: forgedRequest, receipt: witnessResign(forgedMessage),
    }), /refused/u);
    assert.throws(() => verifyIndependentWitnessCasReceipt({
      ...options, ownerPublicKeyPem: attackerPublicKey.export({ format: "pem", type: "spki" }),
    }), /refused/u);
    assert.throws(() => verifyIndependentWitnessCasReceipt({
      ...options, ownerPinSha256: nonce(),
    }), /refused/u);
    assert.throws(() => verifyIndependentWitnessCasReceipt({
      ...options,
      receipt: witnessResign({ ...receipt.message, ownerExpiresAt: request.ownerExpiresAt + 1 }),
    }), /refused/u);
    assert.throws(() => verifyIndependentWitnessCasReceipt({
      ...options, nowSeconds: request.ownerExpiresAt,
    }), /refused/u);
  } finally { await stop(server); f.cleanup(); }
});

test("CAS owner expires while waiting for a real competing SQLite BEGIN IMMEDIATE lock", { skip: !isLinux }, async () => {
  const f = fixture();
  let server;
  let lockHolder;
  try {
    server = await start(f, "lock-wait");
    const initial = await head(server, f);
    // First show a short-lived owner authorization succeeds without contention.
    const immediate = authorizeCas(f, { ...nextRequest(f, initial),
      ownerExpiresAt: Math.floor(Date.now() / 1000) + 2 });
    const accepted = await cas(server, f, immediate);
    assert.equal(accepted.sequence, 1);

    const marker = join(f.root, "lock-acquired");
    const holderScript = `
      import { DatabaseSync } from "node:sqlite";
      import { writeFileSync } from "node:fs";
      const db = new DatabaseSync(process.argv[1]);
      db.exec("BEGIN IMMEDIATE");
      writeFileSync(process.argv[2], "locked");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2900);
      db.exec("COMMIT");
      db.close();
    `;
    lockHolder = spawn(process.execPath, ["--input-type=module", "-e", holderScript,
      join(f.db, "witness.sqlite"), marker], { stdio: ["ignore", "pipe", "pipe"] });
    f.children.push(lockHolder);
    await waitForFile(marker);
    const expiring = authorizeCas(f, { ...nextRequest(f, accepted),
      ownerExpiresAt: Math.floor(Date.now() / 1000) + 1 });
    const pending = send(server.socket, "/v1/cas", expiring);
    const [rejected] = await Promise.all([pending, once(lockHolder, "exit")]);
    assert.equal(rejected.code, 400, JSON.stringify(rejected.body));
    assert.deepEqual(await head(server, f, accepted), {
      sequence: accepted.sequence, headSha: accepted.headSha,
      receiptSha256: accepted.receiptSha256,
    });
    assert.equal(readdirSync(f.anchors).filter((file) => file.endsWith(".receipt")).length, 1);
  } finally {
    if (lockHolder && lockHolder.exitCode === null) lockHolder.kill("SIGKILL");
    await stop(server); f.cleanup();
  }
});

test("lstat-to-read signer and owner key symlink swap fails closed on Linux", { skip: !isLinux }, async (t) => {
  for (const role of ["signer", "owner"]) {
    await t.test(role, async () => {
      const f = fixture();
      try {
        const target = role === "signer" ? f.env.VIRKI_WITNESS_SIGNER_KEY : f.env.VIRKI_WITNESS_OWNER_PUBLIC_KEY;
        const saved = join(f.root, `${role}-original-outside-private-key`);
        const injected = faultPreload(f, `swap-${role}`, `
          const fs = require("node:fs");
          const original = fs.lstatSync;
          let swapped = false;
          fs.lstatSync = function(path, ...args) {
            const stats = original.call(fs, path, ...args);
            if (!swapped && path === ${JSON.stringify(target)}) {
              swapped = true;
              fs.renameSync(path, ${JSON.stringify(saved)});
              fs.symlinkSync(${JSON.stringify(saved)}, path);
            }
            return stats;
          };
          require("node:module").syncBuiltinESMExports();
        `);
        await assert.rejects(start(f, `reject-${role}`, injected), /symlink|private|changed|ELOOP|refused/u);
        assert.equal(readFileSync(saved).length > 0, true);
      } finally { f.cleanup(); }
    });
  }
});

test("lstat-to-read committed anchor symlink swap fails closed despite identical signed bytes", { skip: !isLinux }, async () => {
  const f = fixture();
  let server;
  try {
    server = await start(f, "anchor-base");
    await cas(server, f, nextRequest(f, await head(server, f)));
    await stop(server);
    server = undefined;
    const anchor = join(f.anchors, "00000001.receipt");
    const saved = join(f.root, "valid-signed-anchor-outside-anchor-directory");
    const injected = faultPreload(f, "swap-anchor", `
      const fs = require("node:fs");
      const original = fs.lstatSync;
      let swapped = false;
      fs.lstatSync = function(path, ...args) {
        const stats = original.call(fs, path, ...args);
        if (!swapped && path === ${JSON.stringify(anchor)}) {
          swapped = true;
          fs.renameSync(path, ${JSON.stringify(saved)});
          fs.symlinkSync(${JSON.stringify(saved)}, path);
        }
        return stats;
      };
      require("node:module").syncBuiltinESMExports();
    `);
    await assert.rejects(start(f, "reject-anchor", injected), /symlink|anchor|changed|ELOOP|refused/u);
    assert.match(readFileSync(saved, "utf8"), /receiptSha256/u);
  } finally { await stop(server); f.cleanup(); }
});

test("same-content regular inode replacement after lstat is rejected for key and anchor", { skip: !isLinux }, async (t) => {
  for (const targetKind of ["key", "anchor"]) {
    await t.test(targetKind, async () => {
      const f = fixture();
      let server;
      try {
        if (targetKind === "anchor") {
          server = await start(f, "create-anchor");
          await cas(server, f, nextRequest(f, await head(server, f)));
          await stop(server);
          server = undefined;
        }
        const target = targetKind === "key" ? f.env.VIRKI_WITNESS_SIGNER_KEY :
          join(f.anchors, "00000001.receipt");
        const replacement = join(f.root, `${targetKind}-replacement-same-content`);
        const injected = faultPreload(f, `inode-${targetKind}`, `
          const fs = require("node:fs");
          const original = fs.lstatSync;
          let replaced = false;
          fs.lstatSync = function(path, ...args) {
            const stats = original.call(fs, path, ...args);
            if (!replaced && path === ${JSON.stringify(target)}) {
              replaced = true;
              fs.copyFileSync(path, ${JSON.stringify(replacement)});
              fs.renameSync(${JSON.stringify(replacement)}, path);
            }
            return stats;
          };
          require("node:module").syncBuiltinESMExports();
        `);
        await assert.rejects(start(f, `reject-inode-${targetKind}`, injected),
          /changed before opening pinned descriptor|refused/u);
      } finally { await stop(server); f.cleanup(); }
    });
  }
});

test("anchor pathname swapped after FD read is rejected by final inode recheck", { skip: !isLinux }, async () => {
  const f = fixture();
  let server;
  try {
    server = await start(f, "anchor-for-read-swap");
    await cas(server, f, nextRequest(f, await head(server, f)));
    await stop(server);
    server = undefined;
    const anchor = join(f.anchors, "00000001.receipt");
    const backup = join(f.root, "valid-anchor-after-read-swap");
    const injected = faultPreload(f, "swap-after-fd-read", `
      const fs = require("node:fs");
      const original = fs.readSync;
      let swapped = false;
      fs.readSync = function(fd, ...args) {
        const count = original.call(fs, fd, ...args);
        if (!swapped && count > 0 && fs.readlinkSync("/proc/self/fd/" + fd) === ${JSON.stringify(anchor)}) {
          swapped = true;
          fs.renameSync(${JSON.stringify(anchor)}, ${JSON.stringify(backup)});
          fs.symlinkSync(${JSON.stringify(backup)}, ${JSON.stringify(anchor)});
        }
        return count;
      };
      require("node:module").syncBuiltinESMExports();
    `);
    await assert.rejects(start(f, "reject-after-fd-read", injected), /durable anchor changed during pinned read/u);
    assert.match(readFileSync(backup, "utf8"), /receiptSha256/u);
  } finally { await stop(server); f.cleanup(); }
});
