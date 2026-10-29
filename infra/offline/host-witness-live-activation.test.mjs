import assert from "node:assert/strict";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign, X509Certificate } from "node:crypto";
import { once } from "node:events";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { GENESIS_HEAD, GENESIS_RECEIPT, WITNESS_CAS_DOMAIN } from "../../scripts/lib/offline-independent-witness-service.mjs";
import { remoteWitnessCas, remoteWitnessHead } from "../../scripts/lib/offline-independent-witness-remote-client.mjs";
import { offlineWitnessLedgerTransitionDigest } from "./disposable-witness-ledger-reservation.mjs";
import { FLOOR_READ_DOMAIN } from "./trusted-out-of-host-floor-evidence.mjs";
import { activationSigningBytes } from "./manual-activation-transaction.mjs";
import { recordHostWitnessLedgerActivationWithLiveWitness } from "./host-witness-ledger-activation-bridge.mjs";

// WSL root disposable lab. A separate TLS witness process owns a separate
// SQLite database/anchor tree. The floor signer here is a test fixture,
// NEVER a substitute for independently provisioned production custody.
const enabled = process.platform === "linux" && process.getuid?.() === 0 &&
  /wsl|microsoft/iu.test(os.release());
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const nonce = () => randomBytes(32).toString("hex");
const pem = (key) => key.export({ format: "pem", type: "spki" });
const pin = (key) => sha(key.export({ format: "der", type: "spki" }));
const now = () => Math.floor(Date.now() / 1000);
const serverPath = fileURLToPath(new URL("../../scripts/offline-independent-witness-server.mjs", import.meta.url));
const entryPath = fileURLToPath(new URL("../../scripts/offline-host-witness-manual-intent.mjs", import.meta.url));
const signFloor = (message, key) => sign(null,
  Buffer.from(`${FLOOR_READ_DOMAIN}\0${JSON.stringify(message)}`), key).toString("base64");

function fixture({ unsafeParent = false } = {}) {
  const outer = mkdtempSync("/dev/shm/virki-witness-bridge-fixture-");
  const dir = unsafeParent ? path.join(outer, "owner-root") : outer;
  if (unsafeParent) {
    mkdirSync(dir, { mode: 0o700 });
    chmodSync(outer, 0o777);
  }
  const separate = mkdtempSync("/dev/shm/virki-remote-witness-process-");
  const intents = path.join(dir, "intents");
  const ledgerDirectory = path.join(dir, "ledger");
  const db = path.join(separate, "database");
  const anchors = path.join(separate, "anchors");
  for (const folder of [intents, ledgerDirectory, db, anchors]) mkdirSync(folder, { mode: 0o700 });
  const owner = generateKeyPairSync("ed25519");
  const witness = generateKeyPairSync("ed25519");
  const floor = generateKeyPairSync("ed25519");
  const ownerPublicKeyPem = pem(owner.publicKey);
  const witnessPublicKeyPem = pem(witness.publicKey);
  const keys = {
    ownerPublicKeyPem, ownerPinSha256: pin(owner.publicKey),
    witnessPublicKeyPem, witnessPinSha256: pin(witness.publicKey),
    floorPublicKeyPem: pem(floor.publicKey), floorPinSha256: pin(floor.publicKey),
  };
  const write = (folder, name, bytes) => {
    const file = path.join(folder, name);
    writeFileSync(file, bytes, { mode: 0o600 });
    chmodSync(file, 0o600);
    return file;
  };
  const openssl = (...args) => execFileSync("openssl", args, { stdio: "ignore" });
  const caKey = path.join(separate, "ca.key");
  const ca = path.join(separate, "ca.crt");
  openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey,
    "-out", ca, "-days", "1", "-subj", "/CN=Virki disposable remote test CA");
  const certificate = (name, usage) => {
    const key = path.join(separate, `${name}.key`);
    const csr = path.join(separate, `${name}.csr`);
    const cert = path.join(separate, `${name}.crt`);
    const ext = write(separate, `${name}.ext`, usage === "serverAuth" ?
      "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" :
      "subjectAltName=DNS:client\nextendedKeyUsage=clientAuth\n");
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
      "-out", csr, "-subj", `/CN=${name}`);
    openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey,
      "-CAcreateserial", "-out", cert, "-days", "1", "-extfile", ext);
    chmodSync(key, 0o600);
    chmodSync(cert, 0o600);
    return { key, cert };
  };
  const server = certificate("server", "serverAuth");
  const client = certificate("client", "clientAuth");
  chmodSync(ca, 0o600);
  const serverCertSha256 = sha(new X509Certificate(readFileSync(server.cert)).raw);
  const clientCertSha256 = sha(new X509Certificate(readFileSync(client.cert)).raw);
  const hostIdentitySha256 = nonce();
  const ledgerIdSha256 = nonce();
  const manifest = Buffer.from('{"version":1,"release":"disposable-live-w48"}');
  const manifestSha256 = sha(manifest);
  const manifestFile = write(dir, "manifest.json", manifest);
  const ledgerState = { version: 1, anchorSha: GENESIS_HEAD, entries: [] };
  write(ledgerDirectory, "ledger.json", JSON.stringify(ledgerState));
  const nextSha = nonce().slice(0, 40);
  const ledgerRequest = { directory: ledgerDirectory, manifestSha256, priorSha: GENESIS_HEAD,
    nextSha, nonce: "4".repeat(32), sequence: 1, approvalDigest: "5".repeat(64) };
  const checkpoint = { version: 1, attemptId: "6".repeat(32), hostIdentitySha256,
    manifestSha256, sequence: 0, receiptSha256: GENESIS_RECEIPT, completed: [],
    pending: null, previousDigest: "0".repeat(64) };
  const activationCheckpointFile = write(dir, "activation.json", JSON.stringify(checkpoint));
  const policy = { version: 1, hostIdentitySha256, ledgerIdSha256, manifestSha256,
    manifestFile, sourceSha: nextSha, ledgerDirectory, activationCheckpointFile,
    activationAttemptId: checkpoint.attemptId, expectedSequence: 0,
    expectedHeadSha: GENESIS_HEAD, expectedReceiptSha256: GENESIS_RECEIPT, ...keys };
  const installedPolicyFile = write(dir, "owner-installed-trust.json", JSON.stringify(policy));
  const signerFile = write(separate, "witness-key.pem", witness.privateKey.export({ type: "pkcs8", format: "pem" }));
  const ownerFile = write(separate, "owner.pub", ownerPublicKeyPem);
  const transportFiles = {
    caFile: write(dir, "tls-ca.pem", readFileSync(ca)),
    clientCertFile: write(dir, "tls-client.crt", readFileSync(client.cert)),
    clientKeyFile: write(dir, "tls-client.key", readFileSync(client.key)),
  };
  const env = { ...process.env, VIRKI_WITNESS_MODE: "remote", VIRKI_DISPOSABLE_WITNESS_SERVICE: "1",
    VIRKI_WITNESS_DB_DIRECTORY: db, VIRKI_WITNESS_ANCHOR_DIRECTORY: anchors,
    VIRKI_WITNESS_SIGNER_KEY: signerFile, VIRKI_WITNESS_SIGNER_PIN: keys.witnessPinSha256,
    VIRKI_WITNESS_OWNER_PUBLIC_KEY: ownerFile, VIRKI_WITNESS_OWNER_PIN: keys.ownerPinSha256,
    VIRKI_WITNESS_HOST_SHA256: hostIdentitySha256, VIRKI_WITNESS_LEDGER_SHA256: ledgerIdSha256,
    VIRKI_WITNESS_TLS_KEY: server.key, VIRKI_WITNESS_TLS_CERT: server.cert,
    VIRKI_WITNESS_TLS_CA: ca, VIRKI_WITNESS_TLS_CLIENT_CERT_SHA256: clientCertSha256,
    VIRKI_WITNESS_BIND_HOST: "127.0.0.1", VIRKI_WITNESS_BIND_PORT: "0" };
  const stage = { version: 1, domain: "VIRKI_MANUAL_ACTIVATION_OWNER_STAGE_V1",
    attemptId: checkpoint.attemptId, hostIdentitySha256, manifestSha256,
    stage: "fence-writers", sequence: 1, previousDigest: sha(JSON.stringify(checkpoint)),
    expiresAt: now() + 25 };
  const stageApproval = { message: stage,
    signature: sign(null, activationSigningBytes(stage), owner.privateKey).toString("base64") };
  return { dir, outer, separate, intents, keys, owner, floor, env, policy, checkpoint, ledgerState,
    ledgerRequest, stageApproval, installedPolicyFile, transportFiles,
    serverCertSha256, hostIdentitySha256, ledgerIdSha256,
    cleanup: () => { rmSync(outer, { recursive: true, force: true });
      rmSync(separate, { recursive: true, force: true }); } };
}

async function service(f) {
  const child = spawn(process.execPath, [serverPath], { env: f.env,
    stdio: ["ignore", "pipe", "pipe"] });
  let errors = "";
  child.stderr.on("data", (data) => { errors += data; });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`witness startup timeout ${errors}`)), 7000);
    child.stdout.on("data", (bytes) => {
      const found = /WITNESS_REMOTE_READY (\d+)/u.exec(String(bytes));
      if (found) { clearTimeout(timer); resolve(Number(found[1])); }
    });
    child.on("exit", (code) => { clearTimeout(timer); reject(new Error(`exit ${code}: ${errors}`)); });
  });
  const config = { hostname: "127.0.0.1", port, serverCertSha256: f.serverCertSha256,
    ca: readFileSync(f.transportFiles.caFile), cert: readFileSync(f.transportFiles.clientCertFile),
    key: readFileSync(f.transportFiles.clientKeyFile),
    publicKeyPem: f.keys.witnessPublicKeyPem, pinSha256: f.keys.witnessPinSha256,
    ownerPublicKeyPem: f.keys.ownerPublicKeyPem, ownerPinSha256: f.keys.ownerPinSha256,
    ownerPrivateKeyPem: f.owner.privateKey.export({ type: "pkcs8", format: "pem" }),
    hostIdentitySha256: f.hostIdentitySha256, ledgerIdSha256: f.ledgerIdSha256 };
  const transport = { version: 1, hostname: config.hostname, port: config.port,
    serverCertSha256: config.serverCertSha256, ...f.transportFiles };
  const installedTransportFile = path.join(f.dir, "owner-installed-transport.json");
  writeFileSync(installedTransportFile, JSON.stringify(transport), { mode: 0o600 });
  const stop = async () => { if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM"); await once(child, "exit"); } };
  return { config, installedTransportFile, stop };
}

async function prepared(f, s) {
  const accepted = await remoteWitnessCas(s.config, {
    expectedSequence: 0, expectedHeadSha: GENESIS_HEAD,
    expectedReceiptSha256: GENESIS_RECEIPT, nextHeadSha: f.ledgerRequest.nextSha,
    transitionSha256: offlineWitnessLedgerTransitionDigest(f.ledgerRequest),
  });
  const m = accepted.signedReceipt.message;
  assert.equal(m.domain, WITNESS_CAS_DOMAIN);
  const casRequest = { version: m.version, domain: m.domain, challenge: m.challenge,
    requestId: m.requestId, hostIdentitySha256: m.hostIdentitySha256,
    ledgerIdSha256: m.ledgerIdSha256, expectedSequence: m.sequence - 1,
    expectedHeadSha: m.priorHeadSha, expectedReceiptSha256: m.previousReceiptSha256,
    nextHeadSha: m.headSha, transitionSha256: m.transitionSha256,
    ownerExpiresAt: m.ownerExpiresAt, ownerSignature: m.ownerSignature };
  const head = await remoteWitnessHead(s.config, { minimumSequence: 1,
    expectedHeadSha: m.headSha, minimumReceiptSha256: accepted.receiptSha256 });
  const headRequest = { version: 1, domain: "VIRKI_OFFLINE_INDEPENDENT_WITNESS_HEAD_V1",
    challenge: head.signedReceipt.message.challenge, hostIdentitySha256: f.hostIdentitySha256,
    ledgerIdSha256: f.ledgerIdSha256 };
  const floorRequest = { version: 1, domain: FLOOR_READ_DOMAIN,
    challenge: headRequest.challenge, hostIdentitySha256: f.hostIdentitySha256,
    ledgerIdSha256: f.ledgerIdSha256, phase: "after",
    casRequestSha256: sha(JSON.stringify(casRequest)) };
  const floorMessage = { ...floorRequest, sequence: 1, headSha: accepted.headSha,
    receiptSha256: accepted.receiptSha256, issuedAt: now(), expiresAt: now() + 30 };
  const floorReceipt = { message: floorMessage, signature: signFloor(floorMessage, f.floor.privateKey) };
  const evidence = { phase: "after", pins: f.keys,
    expected: { hostIdentitySha256: f.hostIdentitySha256,
      ledgerIdSha256: f.ledgerIdSha256, sequence: 0,
      headSha: GENESIS_HEAD, receiptSha256: GENESIS_RECEIPT },
    casRequest, casReceipt: accepted.signedReceipt,
    headRequest, headReceipt: head.signedReceipt, floorRequest, floorReceipt, ack: "confirmed" };
  return { installedPolicyFile: f.installedPolicyFile, intentDirectory: f.intents,
    installedTransportFile: s.installedTransportFile, ledgerState: f.ledgerState,
    ledgerRequest: f.ledgerRequest, checkpoint: f.checkpoint,
    stageApproval: f.stageApproval, evidence };
}

test("installed root TLS witness validates exact signed external floor before durable live confirmation; replay blocks", { skip: !enabled }, async () => {
  const f = fixture(); let s;
  try {
    s = await service(f);
    const input = await prepared(f, s);
    const result = await recordHostWitnessLedgerActivationWithLiveWitness(input);
    assert.equal(result.status, "BRIDGE_INTENT_LIVE_CONFIRMED_NONAUTHORIZING");
    assert.equal(result.deployAuthorized, false);
    const artifacts = readdirSync(f.intents);
    assert.equal(artifacts.filter((name) => name.endsWith(".intent")).length, 1);
    assert.equal(artifacts.filter((name) => name.endsWith(".confirmed")).length, 1);
    const confirmation = JSON.parse(readFileSync(path.join(f.intents,
      artifacts.find((name) => name.endsWith(".confirmed"))), "utf8"));
    assert.equal(confirmation.receiptSha256, input.evidence.casReceipt.receiptSha256);
    assert.equal(confirmation.liveHead.message.headSha, f.ledgerRequest.nextSha);
    await assert.rejects(recordHostWitnessLedgerActivationWithLiveWitness(input), /refused/u);
  } finally { if (s) await s.stop(); f.cleanup(); }
});

test("native manual entrypoint uses installed proof file and rejects forged file locations", { skip: !enabled }, async () => {
  const f = fixture(); let s;
  try {
    s = await service(f);
    const input = await prepared(f, s);
    const proofFile = path.join(f.dir, "owner-installed-proof.json");
    const { ledgerState, ledgerRequest, checkpoint, stageApproval, evidence } = input;
    writeFileSync(proofFile, JSON.stringify({ ledgerState, ledgerRequest, checkpoint,
      stageApproval, evidence }), { mode: 0o600 });
    const deny = spawnSync(process.execPath, [entryPath, "/tmp/not-installed-proof.json"],
      { encoding: "utf8", env: { ...process.env, VIRKI_DISPOSABLE_WITNESS_BRIDGE: "1" } });
    assert.notEqual(deny.status, 0);
    assert.deepEqual(readdirSync(f.intents), []);
    const accepted = spawnSync(process.execPath, [entryPath, proofFile],
      { encoding: "utf8", env: { ...process.env, VIRKI_DISPOSABLE_WITNESS_BRIDGE: "1" } });
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).status,
      "BRIDGE_INTENT_LIVE_CONFIRMED_NONAUTHORIZING");
    assert.equal(readdirSync(f.intents).length, 2);
  } finally { if (s) await s.stop(); f.cleanup(); }
});

test("live head unavailable after signed floor: durable uncertain intent blocks retry", { skip: !enabled }, async () => {
  const f = fixture(); let s;
  try {
    s = await service(f);
    const input = await prepared(f, s);
    await s.stop();
    const result = await recordHostWitnessLedgerActivationWithLiveWitness(input);
    assert.equal(result.status, "BRIDGE_INTENT_LIVE_UNCERTAIN_NONAUTHORIZING");
    assert.equal(result.deployAuthorized, false);
    assert.deepEqual(readdirSync(f.intents).map((x) => path.extname(x)), [".intent"]);
    await assert.rejects(recordHostWitnessLedgerActivationWithLiveWitness(input), /refused/u);
    assert.equal(readdirSync(f.intents).length, 1);
  } finally { if (s) await s.stop(); f.cleanup(); }
});

test("stale remote head after another valid owner CAS cannot confirm earlier signed floor", { skip: !enabled }, async () => {
  const f = fixture(); let s;
  try {
    s = await service(f);
    const input = await prepared(f, s);
    await remoteWitnessCas(s.config, { expectedSequence: 1,
      expectedHeadSha: f.ledgerRequest.nextSha,
      expectedReceiptSha256: input.evidence.casReceipt.receiptSha256,
      nextHeadSha: nonce().slice(0, 40), transitionSha256: nonce() });
    const result = await recordHostWitnessLedgerActivationWithLiveWitness(input);
    assert.equal(result.status, "BRIDGE_INTENT_LIVE_UNCERTAIN_NONAUTHORIZING");
    assert.deepEqual(readdirSync(f.intents).map((x) => path.extname(x)), [".intent"]);
  } finally { if (s) await s.stop(); f.cleanup(); }
});

test("bad installed TLS pin remains uncertain; tampered signed floor refuses before intent", { skip: !enabled }, async () => {
  for (const kind of ["tls", "floor"]) {
    const f = fixture(); let s;
    try {
      s = await service(f);
      const input = await prepared(f, s);
      if (kind === "tls") {
        const transport = JSON.parse(readFileSync(s.installedTransportFile, "utf8"));
        transport.serverCertSha256 = nonce();
        writeFileSync(s.installedTransportFile, JSON.stringify(transport));
      } else {
        input.evidence.floorReceipt.message.sequence = 2;
      }
      const result = await recordHostWitnessLedgerActivationWithLiveWitness(input).catch(() => null);
      if (kind === "floor") {
        assert.equal(result, null);
        assert.deepEqual(readdirSync(f.intents), []);
      } else {
        assert.equal(result.status, "BRIDGE_INTENT_LIVE_UNCERTAIN_NONAUTHORIZING");
        assert.deepEqual(readdirSync(f.intents).map((name) => path.extname(name)), [".intent"]);
      }
      assert.deepEqual(readdirSync(f.intents).filter((name) => name.endsWith(".confirmed")), []);
    } finally { if (s) await s.stop(); f.cleanup(); }
  }
});

test("RED: nobody cannot bypass a durable replay intent by renaming a root-owned 0700 tree under an unsafe ancestor", { skip: !enabled }, async () => {
  const f = fixture({ unsafeParent: true }); let s;
  try {
    s = await service(f);
    const input = await prepared(f, s);
    const replacement = path.join(f.outer, "replacement");
    const displaced = path.join(f.outer, "displaced");
    cpSync(f.dir, replacement, { recursive: true });
    // If a vulnerable implementation accepts the first intent, nobody must
    // not be able to make the same signed CAS appear unseen a second time.
    let first;
    try { first = await recordHostWitnessLedgerActivationWithLiveWitness(input); }
    catch { /* Mandatory fail-closed refusal before any durable write. */ }
    const move = spawnSync("/usr/sbin/runuser", ["-u", "nobody", "--", "/bin/sh", "-c",
      "mv -- \"$1\" \"$2\" && mv -- \"$3\" \"$1\"", "sh", f.dir, displaced, replacement],
    { encoding: "utf8" });
    assert.equal(move.status, 0, move.stderr);
    assert.equal(first, undefined,
      "a root-owned 0700 tree under nonsticky writable ancestry must be refused before durable intent");
    assert.deepEqual(readdirSync(path.join(displaced, "intents")), []);
    assert.deepEqual(readdirSync(f.intents), []);
  } finally { if (s) await s.stop(); f.cleanup(); }
});

test("RED: delayed genuine mTLS HEAD cannot confirm an expired signed owner stage", { skip: !enabled }, async () => {
  const f = fixture(); let s; let proxy;
  try {
    s = await service(f);
    const input = await prepared(f, s);
    input.stageApproval.message.expiresAt = now() + 3;
    input.stageApproval.signature = sign(null, activationSigningBytes(input.stageApproval.message),
      f.owner.privateKey).toString("base64");
    proxy = createServer((downstream) => {
      downstream.on("error", () => {});
      setTimeout(() => {
        if (downstream.destroyed) return;
        const upstream = connect(s.config.port, "127.0.0.1");
        upstream.on("error", () => {});
        downstream.pipe(upstream);
        upstream.pipe(downstream);
        downstream.once("close", () => upstream.destroy());
      }, 3600);
    });
    await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const transport = JSON.parse(readFileSync(s.installedTransportFile, "utf8"));
    transport.port = proxy.address().port;
    writeFileSync(s.installedTransportFile, JSON.stringify(transport));
    const result = await recordHostWitnessLedgerActivationWithLiveWitness(input);
    assert.equal(result.status, "BRIDGE_INTENT_LIVE_UNCERTAIN_NONAUTHORIZING");
    assert.equal(result.reconciliationRequired, true);
    assert.deepEqual(readdirSync(f.intents).map((name) => path.extname(name)), [".intent"]);
    await assert.rejects(recordHostWitnessLedgerActivationWithLiveWitness(input), /refused/u);
  } finally {
    if (proxy) await new Promise((resolve) => proxy.close(resolve));
    if (s) await s.stop();
    f.cleanup();
  }
});
