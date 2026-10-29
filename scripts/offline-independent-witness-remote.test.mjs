import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, X509Certificate } from "node:crypto";
import { once } from "node:events";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { GENESIS_HEAD, GENESIS_RECEIPT } from "./lib/offline-independent-witness-service.mjs";
import { remoteWitnessCas, remoteWitnessHead } from "./lib/offline-independent-witness-remote-client.mjs";

const linux = process.platform === "linux";
const serverPath = fileURLToPath(new URL("./offline-independent-witness-server.mjs", import.meta.url));
const clientPath = fileURLToPath(new URL("./offline-independent-witness-remote-client.mjs", import.meta.url));
const hash = (data) => createHash("sha256").update(data).digest("hex");
const nonce = () => randomBytes(32).toString("hex");
function openssl(...args) { execFileSync("openssl", args, { stdio: "ignore" }); }

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "virki-remote-w26-"));
  const db = join(root, "database");
  const anchors = join(root, "anchors");
  for (const dir of [db, anchors]) mkdirSync(dir, { mode: 0o700 });
  const { privateKey: signer, publicKey: witnessPublic } = generateKeyPairSync("ed25519");
  const { privateKey: owner, publicKey: ownerPublic } = generateKeyPairSync("ed25519");
  const writePem = (name, pem) => {
    const file = join(root, name);
    writeFileSync(file, pem, { mode: 0o600 });
    chmodSync(file, 0o600);
    return file;
  };
  const signerFile = writePem("signer.pem", signer.export({ format: "pem", type: "pkcs8" }));
  const signerPublicFile = writePem("signer-public.pem", witnessPublic.export({ format: "pem", type: "spki" }));
  const ownerPubFile = writePem("owner-public.pem", ownerPublic.export({ format: "pem", type: "spki" }));
  const ownerPrivateFile = writePem("owner-private-client-only.pem", owner.export({ format: "pem", type: "pkcs8" }));
  const caKey = join(root, "ca.key");
  const caCrt = join(root, "ca.crt");
  openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey,
    "-out", caCrt, "-days", "1", "-subj", "/CN=Virki disposable local test CA");
  const issueCert = (name, role) => {
    const key = join(root, `${name}.key`);
    const csr = join(root, `${name}.csr`);
    const crt = join(root, `${name}.crt`);
    const ext = writePem(`${name}.ext`, role === "server" ?
      "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" :
      `subjectAltName=DNS:${name}\nextendedKeyUsage=clientAuth\n`);
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
      "-out", csr, "-subj", `/CN=${name}`);
    openssl("x509", "-req", "-in", csr, "-CA", caCrt, "-CAkey", caKey,
      "-CAcreateserial", "-out", crt, "-days", "1", "-extfile", ext);
    chmodSync(key, 0o600);
    chmodSync(crt, 0o600);
    return { key, crt };
  };
  const server = issueCert("witness", "server");
  const client = issueCert("trusted", "client");
  const intruder = issueCert("intruder", "client");
  chmodSync(caKey, 0o600);
  chmodSync(caCrt, 0o600);
  const serverCertSha256 = hash(new X509Certificate(readFileSync(server.crt)).raw);
  const clientCertSha256 = hash(new X509Certificate(readFileSync(client.crt)).raw);
  const pinSha256 = hash(witnessPublic.export({ format: "der", type: "spki" }));
  const ownerPinSha256 = hash(ownerPublic.export({ format: "der", type: "spki" }));
  const hostIdentitySha256 = nonce();
  const ledgerIdSha256 = nonce();
  const tls = {
    ca: readFileSync(caCrt), cert: readFileSync(client.crt), key: readFileSync(client.key),
    serverCertSha256, hostname: "127.0.0.1", port: 0,
    publicKeyPem: witnessPublic.export({ format: "pem", type: "spki" }), pinSha256,
    ownerPublicKeyPem: ownerPublic.export({ format: "pem", type: "spki" }), ownerPinSha256,
    ownerPrivateKeyPem: owner.export({ format: "pem", type: "pkcs8" }),
    hostIdentitySha256, ledgerIdSha256,
  };
  const env = {
    ...process.env, VIRKI_WITNESS_MODE: "remote", VIRKI_DISPOSABLE_WITNESS_SERVICE: "1",
    VIRKI_WITNESS_DB_DIRECTORY: db, VIRKI_WITNESS_ANCHOR_DIRECTORY: anchors,
    VIRKI_WITNESS_SIGNER_KEY: signerFile, VIRKI_WITNESS_SIGNER_PIN: pinSha256,
    VIRKI_WITNESS_OWNER_PUBLIC_KEY: ownerPubFile, VIRKI_WITNESS_OWNER_PIN: ownerPinSha256,
    VIRKI_WITNESS_HOST_SHA256: hostIdentitySha256, VIRKI_WITNESS_LEDGER_SHA256: ledgerIdSha256,
    VIRKI_WITNESS_TLS_KEY: server.key, VIRKI_WITNESS_TLS_CERT: server.crt,
    VIRKI_WITNESS_TLS_CA: caCrt, VIRKI_WITNESS_TLS_CLIENT_CERT_SHA256: clientCertSha256,
    VIRKI_WITNESS_BIND_HOST: "127.0.0.1", VIRKI_WITNESS_BIND_PORT: "0",
  };
  const clientEnv = {
    VIRKI_WITNESS_CLIENT_SERVER_HOST: "127.0.0.1",
    VIRKI_WITNESS_CLIENT_SERVER_CERT_SHA256: serverCertSha256,
    VIRKI_WITNESS_CLIENT_TLS_CA: caCrt,
    VIRKI_WITNESS_CLIENT_TLS_CERT: client.crt,
    VIRKI_WITNESS_CLIENT_TLS_KEY: client.key,
    VIRKI_WITNESS_SIGNER_PUBLIC_KEY: signerPublicFile,
    VIRKI_WITNESS_SIGNER_PIN: pinSha256,
    VIRKI_WITNESS_OWNER_PUBLIC_KEY: ownerPubFile,
    VIRKI_WITNESS_OWNER_PIN: ownerPinSha256,
    VIRKI_WITNESS_CLIENT_OWNER_SIGNER_KEY: ownerPrivateFile,
    VIRKI_WITNESS_HOST_SHA256: hostIdentitySha256,
    VIRKI_WITNESS_LEDGER_SHA256: ledgerIdSha256,
  };
  return { root, anchors, env, tls, clientEnv, intruder, cleanup: () => rmSync(root, { force: true, recursive: true }) };
}

async function start(f, extra = {}) {
  const child = spawn(process.execPath, [serverPath], { env: { ...f.env, ...extra }, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (bytes) => { stderr += bytes; });
  const port = await new Promise((resolve, reject) => {
    let stdout = "";
    const timeout = setTimeout(() => reject(new Error(`remote startup timeout ${stderr}`)), 7000);
    child.stdout.on("data", (bytes) => {
      stdout += bytes;
      const ready = /WITNESS_REMOTE_READY (\d+)/u.exec(stdout);
      if (ready) { clearTimeout(timeout); resolve(Number(ready[1])); }
    });
    child.once("exit", (code) => { clearTimeout(timeout); reject(new Error(`remote startup exit ${code}: ${stderr}`)); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  return { child, options: { ...f.tls, port }, close: async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit");
    }
  } };
}

function cli(f, service, command, ...args) {
  return JSON.parse(execFileSync(process.execPath, [clientPath, command, ...args.map(String)], {
    encoding: "utf8", env: { ...process.env, ...f.clientEnv,
      VIRKI_WITNESS_CLIENT_SERVER_PORT: String(service.options.port) },
  }));
}

test("native Linux independent remote mTLS witness: authentication, CAS, rollback and restart", { skip: !linux }, async () => {
  const f = fixture();
  let service;
  try {
    service = await start(f);
    const genesis = await remoteWitnessHead(service.options, { minimumSequence: 0,
      expectedHeadSha: GENESIS_HEAD, minimumReceiptSha256: GENESIS_RECEIPT });
    assert.equal(genesis.sequence, 0);
    assert.equal(genesis.headSha, GENESIS_HEAD);
    assert.equal(genesis.deployAuthorized, false);
    assert.equal(cli(f, service, "head", 0, GENESIS_HEAD, GENESIS_RECEIPT).sequence, 0);

    const floor = { minimumSequence: 0, expectedHeadSha: GENESIS_HEAD,
      minimumReceiptSha256: GENESIS_RECEIPT };
    await assert.rejects(remoteWitnessHead(service.options, {
      ...floor, expectedHeadSha: nonce().slice(0, 40),
    }), /head|pin|refused/u);

    await assert.rejects(remoteWitnessHead({ ...service.options, serverCertSha256: nonce() }, floor), /pin|certificate|refused/u);
    await assert.rejects(remoteWitnessHead({ ...service.options, cert: readFileSync(f.intruder.crt),
      key: readFileSync(f.intruder.key) }, floor), /certificate|unauthorized|socket|ECONNRESET|alert|403|CLIENT_IDENTITY_REFUSED/u);
    await assert.rejects(remoteWitnessHead({ ...service.options, cert: undefined, key: undefined }, floor), /certificate|unauthorized|socket|ECONNRESET|alert|pin|refused/u);
    await assert.rejects(remoteWitnessHead({ ...service.options, ownerPinSha256: nonce() }, floor), /pin|refused/u);

    const next = nonce().slice(0, 40);
    const proposal = { expectedSequence: 0, expectedHeadSha: GENESIS_HEAD,
      expectedReceiptSha256: GENESIS_RECEIPT, nextHeadSha: next, transitionSha256: nonce() };
    const [winner, loser] = await Promise.allSettled([
      remoteWitnessCas(service.options, proposal), remoteWitnessCas(service.options, { ...proposal, nextHeadSha: nonce().slice(0, 40) }),
    ]);
    assert.deepEqual([winner.status, loser.status].sort(), ["fulfilled", "rejected"]);
    const accepted = winner.status === "fulfilled" ? winner.value : loser.value;
    assert.equal(accepted.sequence, 1);
    assert.equal(accepted.deployAuthorized, false);
    assert.equal(readdirSync(f.anchors).filter((name) => name.endsWith(".receipt")).length, 1);
    await assert.rejects(remoteWitnessCas(service.options, proposal), /409|CAS_CONFLICT/u);

    await service.close();
    service = await start(f);
    const restored = await remoteWitnessHead(service.options, {
      minimumSequence: accepted.sequence, expectedHeadSha: accepted.headSha,
      minimumReceiptSha256: accepted.receiptSha256,
    });
    assert.equal(restored.headSha, accepted.headSha);
    await assert.rejects(remoteWitnessHead(service.options, {
      minimumSequence: accepted.sequence + 1, expectedHeadSha: accepted.headSha,
      minimumReceiptSha256: accepted.receiptSha256,
    }), /refused|minimum|stale/u);

    // Even an authentic TLS client cannot impersonate the separately pinned owner.
    const { privateKey: attacker } = generateKeyPairSync("ed25519");
    await assert.rejects(remoteWitnessCas({ ...service.options,
      ownerPrivateKeyPem: attacker.export({ type: "pkcs8", format: "pem" }) },
    { expectedSequence: accepted.sequence, expectedHeadSha: accepted.headSha,
      expectedReceiptSha256: accepted.receiptSha256,
      nextHeadSha: nonce().slice(0, 40), transitionSha256: nonce() }), /pin|owner|refused/u);

    // Real owner-key CLI transport signs a second transition without ever
    // disclosing the private key to the witness service.
    const cliNextHead = nonce().slice(0, 40);
    const cliAccepted = cli(f, service, "cas", accepted.sequence, accepted.headSha,
      accepted.receiptSha256, cliNextHead, nonce());
    assert.equal(cliAccepted.sequence, 2);
    assert.equal(cliAccepted.headSha, cliNextHead);
    assert.ok(cliAccepted.signedReceipt?.signature);
    assert.equal((await remoteWitnessHead(service.options, {
      minimumSequence: 2, expectedHeadSha: cliNextHead,
      minimumReceiptSha256: cliAccepted.receiptSha256,
    })).headSha, cliNextHead);

    // Simulated SIGKILL between SQLite COMMIT and anchor publication. The
    // next Linux process restores the durable, signed anchor suffix.
    await service.close();
    const crash = await start(f, { VIRKI_DISPOSABLE_WITNESS_FAULT: "afterCommitBeforeAnchor" });
    const postCrashHead = nonce().slice(0, 40);
    await assert.rejects(remoteWitnessCas(crash.options, {
      expectedSequence: 2, expectedHeadSha: cliAccepted.headSha,
      expectedReceiptSha256: cliAccepted.receiptSha256,
      nextHeadSha: postCrashHead, transitionSha256: nonce(),
    }), /ECONNRESET|socket hang up|aborted/u);
    if (crash.child.exitCode === null) await once(crash.child, "exit");
    assert.equal(crash.child.exitCode, 73);
    assert.equal(readdirSync(f.anchors).filter((name) => name.endsWith(".receipt")).length, 2);
    service = await start(f);
    const recoveredAnchor = JSON.parse(readFileSync(join(f.anchors, "00000003.receipt"), "utf8"));
    // The entry does not exist until server startup has recovered it.
    assert.equal(recoveredAnchor.sequence, 3);
    const recovered = await remoteWitnessHead(service.options, {
      minimumSequence: 3, expectedHeadSha: postCrashHead,
      minimumReceiptSha256: recoveredAnchor.receiptSha256,
    });
    assert.equal(recovered.headSha, postCrashHead);
  } finally { if (service) await service.close(); f.cleanup(); }
});
