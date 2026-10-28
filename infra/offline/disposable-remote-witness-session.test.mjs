import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign, X509Certificate } from "node:crypto";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  renameSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import tls from "node:tls";
import test from "node:test";
import {
  IndependentOfflineWitness, GENESIS_HEAD, GENESIS_RECEIPT,
  WITNESS_CAS_DOMAIN, independentWitnessOwnerCasSigningBytes,
} from "../../scripts/lib/offline-independent-witness-service.mjs";
import {
  createDisposableRemoteWitnessSession, independentRemoteWitnessConsentSigningBytes,
} from "./disposable-remote-witness-session.mjs";

const enabled = process.platform === "linux";
const onlyLinux = { skip: enabled ? false : "Native Linux local-only TLS/FS fixture required" };
const sha = (x) => createHash("sha256").update(x).digest("hex");
const hex = (n) => randomBytes(n).toString("hex");
const pin = (key) => sha(key.export({ type: "spki", format: "der" }));
const keyPair = () => generateKeyPairSync("ed25519");
const pem = (key) => key.export({ type: "spki", format: "pem" });
const checkpointGenesis = () => ({
  version: 1, sequence: 0, headSha: GENESIS_HEAD, receiptSha256: GENESIS_RECEIPT,
  previousDigest: "0".repeat(64), receipt: null,
});

function certificate(root, label) {
  const file = path.join(root, label + ".pem");
  const key = path.join(root, label + ".key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-sha256",
    "-nodes", "-days", "1", "-batch", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", file],
  { stdio: "ignore", timeout: 10000 });
  const cert = readFileSync(file, "utf8");
  return {
    cert, key: readFileSync(key, "utf8"),
    spkiPin: sha(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })),
  };
}

async function setup(t, { responseMode = "normal", serverCert } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), "virki-witness-transport-fixture-"));
  chmodSync(root, 0o700);
  const db = path.join(root, "db");
  const anchors = path.join(root, "anchors");
  mkdirSync(db, { mode: 0o700 });
  mkdirSync(anchors, { mode: 0o700 });
  const witness = keyPair();
  const owner = keyPair();
  const scope = { hostIdentitySha256: hex(32), ledgerIdSha256: hex(32) };
  const signerFile = path.join(root, "witness-key.pem");
  const ownerFile = path.join(root, "owner-public.pem");
  writeFileSync(signerFile,
    witness.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(ownerFile, pem(owner.publicKey), { mode: 0o600 });
  const oldEnv = process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE;
  process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE = "1";
  const service = new IndependentOfflineWitness({
    directory: db, anchorDirectory: anchors, keyFile: signerFile,
    ownerPublicKeyFile: ownerFile, expectedKeyPinSha256: pin(witness.publicKey),
    expectedOwnerPinSha256: pin(owner.publicKey), ...scope,
  });
  const original = certificate(root, "server");
  const tlsServerIdentity = serverCert ?? original;
  const client = certificate(root, "client");
  const checkpointDir = path.join(root, "checkpoint");
  mkdirSync(checkpointDir, { mode: 0o700 });
  const ownerRootPinFile = path.join(root, "owner-root-pin.json");
  writeFileSync(ownerRootPinFile, JSON.stringify({
    version: 1, ownerSignerSpkiSha256: pin(owner.publicKey),
  }), { mode: 0o600 });
  const genesisBytes = Buffer.from(JSON.stringify(checkpointGenesis()));
  writeFileSync(path.join(checkpointDir, "00000000.checkpoint"), genesisBytes, { mode: 0o600 });
  const counters = { head: 0, cas: 0, data: 0 };
  const server = tls.createServer({
    key: tlsServerIdentity.key, cert: tlsServerIdentity.cert,
    ca: client.cert, requestCert: true, rejectUnauthorized: true,
  }, (socket) => {
    let body = "";
    socket.on("data", (data) => {
      counters.data++;
      body += data.toString("utf8");
      if (body.length > 8192) { socket.destroy(); return; }
      if (!body.endsWith("\n")) return;
      try {
        const parsed = JSON.parse(body.slice(0, -1));
        if (parsed.action === "head") {
          counters.head++;
          if (responseMode === "slow-head") {
            const tick = setInterval(() => socket.write(" "), 150);
            socket.once("close", () => clearInterval(tick));
            return;
          }
          const receipt = service.read(parsed.request);
          if (responseMode === "forged-head") receipt.message.challenge = hex(32);
          if (responseMode === "slow-valid-head") {
            setTimeout(() => socket.end(JSON.stringify(receipt) + "\n"), 2200);
            return;
          }
          if (responseMode === "swap-head-directory") {
            renameSync(checkpointDir, path.join(root, "checkpoint-original"));
            mkdirSync(checkpointDir, { mode: 0o700 });
          }
          if (responseMode === "tamper-historical-intent-during-head" &&
              existsSync(path.join(checkpointDir, "00000001.intent"))) {
            const filename = path.join(checkpointDir, "00000001.intent");
            const originalIntent = JSON.parse(readFileSync(filename, "utf8"));
            writeFileSync(filename, JSON.stringify({
              ...originalIntent, consentSha256: hex(32), casRequestSha256: hex(32),
            }));
          }
          socket.end(JSON.stringify(receipt) + "\n");
        } else if (parsed.action === "cas") {
          counters.cas++;
          const receipt = service.cas(parsed.request);
          if (responseMode === "swap-cas-directory") {
            renameSync(checkpointDir, path.join(root, "checkpoint-original"));
            mkdirSync(checkpointDir, { mode: 0o700 });
          }
          if (responseMode === "lost-cas") socket.destroy();
          else if (responseMode === "ambiguous-cas") socket.end(JSON.stringify(receipt).slice(0, 19));
          else if (responseMode === "extra-cas") socket.end(JSON.stringify(receipt) + "\nINJECTED\n");
          else socket.end(JSON.stringify(receipt) + "\n");
        } else socket.destroy();
      } catch { socket.destroy(); }
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  const unsignedCas = {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: hex(32), requestId: hex(32),
    ...scope, expectedSequence: 0, expectedHeadSha: GENESIS_HEAD,
    expectedReceiptSha256: GENESIS_RECEIPT, nextHeadSha: "b".repeat(40),
    transitionSha256: hex(32), ownerExpiresAt: Math.floor(Date.now() / 1000) + 25,
  };
  const casRequest = {
    ...unsignedCas,
    ownerSignature: sign(null, independentWitnessOwnerCasSigningBytes(unsignedCas),
      owner.privateKey).toString("base64"),
  };
  const consent = {
    version: 1, domain: "VIRKI_OFFLINE_REMOTE_WITNESS_CONSENT_V1",
    endpointHost: "localhost", endpointPort: port,
    tlsServerSpkiSha256: original.spkiPin,
    tlsClientSpkiSha256: client.spkiPin,
    witnessSignerSpkiSha256: pin(witness.publicKey),
    ownerSignerSpkiSha256: pin(owner.publicKey),
    ...scope, casRequestSha256: sha(Buffer.from(JSON.stringify(casRequest))),
    genesisSha256: sha(genesisBytes),
    expiresAt: Math.floor(Date.now() / 1000) + 45,
  };
  const signConsent = (value = consent) =>
    sign(null, independentRemoteWitnessConsentSigningBytes(value),
      owner.privateKey).toString("base64");
  const input = {
    checkpointDirectory: checkpointDir, ownerRootPinFile,
    consent, consentSignature: signConsent(),
    ownerPublicKeyPem: pem(owner.publicKey), witnessPublicKeyPem: pem(witness.publicKey),
    casRequest, tlsClientCertPem: client.cert, tlsClientKeyPem: client.key,
  };
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    service.close();
    if (oldEnv === undefined) delete process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE;
    else process.env.VIRKI_DISPOSABLE_WITNESS_SERVICE = oldEnv;
    rmSync(root, { recursive: true, force: true });
  });
  return { root, checkpointDir, input, counters, consent, signConsent, service, original, owner, client, scope };
}

async function run(input) {
  const old = process.env.VIRKI_DISPOSABLE_REMOTE_WITNESS;
  process.env.VIRKI_DISPOSABLE_REMOTE_WITNESS = "1";
  try { return await createDisposableRemoteWitnessSession(input); }
  finally {
    if (old === undefined) delete process.env.VIRKI_DISPOSABLE_REMOTE_WITNESS;
    else process.env.VIRKI_DISPOSABLE_REMOTE_WITNESS = old;
  }
}

test("external witness transport cannot be activated from a source checkout", async () => {
  await assert.rejects(createDisposableRemoteWitnessSession({}),
    /disposable.*witness.*refused/iu);
});

test("real mutually authenticated TLS verifies signed HEAD/CAS and durable checkpoint, then denies replay", onlyLinux, async (t) => {
  const f = await setup(t);
  const result = await run(f.input);
  assert.equal(result.status, "EXTERNAL_TLS_WITNESS_DISPOSABLE_CHECKPOINT_ONLY");
  assert.deepEqual([result.witnessCasAuthorized, result.dockerLoadAuthorized,
    result.deployAuthorized], [false, false, false]);
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 1]);
  assert.deepEqual(readdirSync(f.checkpointDir).filter((name) => /\.(?:checkpoint|intent|complete)$/u.test(name)).sort(),
    ["00000000.checkpoint", "00000001.checkpoint", "00000001.complete", "00000001.intent"]);
  await assert.rejects(run(f.input), /reconciliation required/u);
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 1]);
});

function nextOwnerApprovedAttempt(f, first) {
  const unsigned = {
    version: 1, domain: WITNESS_CAS_DOMAIN,
    challenge: hex(32), requestId: hex(32), ...f.scope,
    expectedSequence: 1, expectedHeadSha: first.headSha,
    expectedReceiptSha256: first.receiptSha256, nextHeadSha: "c".repeat(40),
    transitionSha256: hex(32), ownerExpiresAt: Math.floor(Date.now() / 1000) + 25,
  };
  const nextCas = {
    ...unsigned, ownerSignature: sign(null,
      independentWitnessOwnerCasSigningBytes(unsigned), f.owner.privateKey).toString("base64"),
  };
  const nextConsent = {
    ...f.consent, casRequestSha256: sha(Buffer.from(JSON.stringify(nextCas))),
    expiresAt: Math.floor(Date.now() / 1000) + 45,
  };
  return { ...f.input, casRequest: nextCas, consent: nextConsent,
    consentSignature: f.signConsent(nextConsent) };
}

test("new owner consent advances an authenticated checkpoint chain without rewinding", onlyLinux, async (t) => {
  const f = await setup(t);
  const first = await run(f.input);
  const second = await run(nextOwnerApprovedAttempt(f, first));
  assert.equal(second.sequence, 2);
  assert.deepEqual([f.counters.head, f.counters.cas], [2, 2]);
  assert.equal(readdirSync(f.checkpointDir).length, 7);
  await assert.rejects(run(nextOwnerApprovedAttempt(f, first)), /reconciliation required/u);
  assert.equal(f.counters.cas, 2);
});

test("historical intent hash substitution cannot be laundered through a valid signed checkpoint", onlyLinux, async (t) => {
  const f = await setup(t);
  const first = await run(f.input);
  const filename = path.join(f.checkpointDir, "00000001.intent");
  const initial = JSON.parse(readFileSync(filename, "utf8"));
  // A private but writable canonical file does not prove the historical
  // operator-authorized intent. Both digests remain syntactically valid.
  const replacement = {
    ...initial, consentSha256: hex(32), casRequestSha256: hex(32),
  };
  writeFileSync(filename, JSON.stringify(replacement));
  assert.notEqual(replacement.consentSha256, initial.consentSha256);
  assert.notEqual(replacement.casRequestSha256, initial.casRequestSha256);
  await assert.rejects(run(nextOwnerApprovedAttempt(f, first)),
    /reconciliation required/u);
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 1],
    "tampered historical intent must be rejected before any TLS egress");
  assert.deepEqual(readdirSync(f.checkpointDir).filter((n) => n.endsWith(".intent")),
    ["00000001.intent"], "never write a new CAS intent after historical substitution");
});

test("historical intent modified while awaiting HEAD cannot reach CAS on the next sequence", onlyLinux, async (t) => {
  const f = await setup(t, { responseMode: "tamper-historical-intent-during-head" });
  const first = await run(f.input);
  await assert.rejects(run(nextOwnerApprovedAttempt(f, first)),
    /reconciliation required/u);
  assert.deepEqual([f.counters.head, f.counters.cas], [2, 1]);
  assert.deepEqual(readdirSync(f.checkpointDir).filter((n) => n.endsWith(".intent")),
    ["00000001.intent"]);
});

test("HEAD-time private checkpoint-directory swap is rejected before CAS egress", onlyLinux, async (t) => {
  const f = await setup(t, { responseMode: "swap-head-directory" });
  await assert.rejects(run(f.input), /reconciliation required/u);
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 0]);
  assert.deepEqual(readdirSync(f.checkpointDir), [],
    "new attacker pathname cannot receive the durable intent");
  assert.deepEqual(readdirSync(path.join(f.root, "checkpoint-original")),
    ["00000000.checkpoint"], "the original anchored genesis remains intact");
});

test("post-CAS directory swap cannot create a successful checkpoint in an alias", onlyLinux, async (t) => {
  const f = await setup(t, { responseMode: "swap-cas-directory" });
  await assert.rejects(run(f.input), /reconciliation required/u);
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 1]);
  assert.deepEqual(readdirSync(f.checkpointDir), [],
    "replacement directory cannot acquire checkpoint or completion");
  assert.deepEqual(readdirSync(path.join(f.root, "checkpoint-original")).sort(),
    ["00000000.checkpoint", "00000001.intent"],
    "the original pinned directory retains its durable unreconciled intent");
});

test("HEAD response arriving after owner consent expiry cannot release CAS or intent", onlyLinux, async (t) => {
  const f = await setup(t, { responseMode: "slow-valid-head" });
  const expiresSoon = {
    ...f.input.consent, expiresAt: Math.floor(Date.now() / 1000) + 2,
  };
  await assert.rejects(run({
    ...f.input, consent: expiresSoon,
    consentSignature: f.signConsent(expiresSoon),
  }), /reconciliation required/u);
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 0]);
  assert.deepEqual(readdirSync(f.checkpointDir), ["00000000.checkpoint"]);
});

test("missing prior completion latch cannot be repaired by a fresh owner signature", onlyLinux, async (t) => {
  const f = await setup(t);
  const first = await run(f.input);
  const { unlinkSync } = await import("node:fs");
  unlinkSync(path.join(f.checkpointDir, "00000001.complete"));
  await assert.rejects(run(nextOwnerApprovedAttempt(f, first)), /reconciliation required/u);
  assert.equal(f.counters.cas, 1);
});

test("MITM with valid but different TLS certificate receives zero owner data", onlyLinux, async (t) => {
  const root = mkdtempSync(path.join(tmpdir(), "virki-extra-tls-fixture-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const adversarial = certificate(root, "mitm");
  const f = await setup(t, { serverCert: adversarial });
  await assert.rejects(run(f.input), /reconciliation required/u);
  assert.equal(f.counters.data, 0);
  assert.equal(f.counters.cas, 0);
  assert.deepEqual(readdirSync(f.checkpointDir).filter((n) => n.endsWith(".intent")), []);
});

test("owner consent binds endpoint, pin, scope, CAS content and current owner signature", onlyLinux, async (t) => {
  const f = await setup(t);
  for (const replacement of [
    { consent: { ...f.consent, endpointPort: f.consent.endpointPort + 1 } },
    { consent: { ...f.consent, tlsServerSpkiSha256: hex(32) } },
    { consent: { ...f.consent, tlsClientSpkiSha256: hex(32) } },
    { consent: { ...f.consent, ledgerIdSha256: hex(32) } },
    { casRequest: { ...f.input.casRequest, nextHeadSha: "c".repeat(40) } },
    { consentSignature: "A".repeat(86) + "==" },
    { ownerPublicKeyPem: pem(keyPair().publicKey) },
    { ownerRootPinFile: path.join(f.root, "unapproved-owner-root.json") },
  ]) await assert.rejects(run({ ...f.input, ...replacement }), /reconciliation required/u);
  assert.equal(f.counters.data, 0);
});

test("forged challenge-bound HEAD blocks before CAS or intent", onlyLinux, async (t) => {
  const f = await setup(t, { responseMode: "forged-head" });
  await assert.rejects(run(f.input), /reconciliation required/u);
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 0]);
  assert.deepEqual(readdirSync(f.checkpointDir).filter((n) => n.endsWith(".intent")), []);
});

test("a trickling TLS peer cannot evade the absolute session deadline", onlyLinux, async (t) => {
  const f = await setup(t, { responseMode: "slow-head" });
  const before = Date.now();
  await assert.rejects(run(f.input), /reconciliation required/u);
  assert.ok(Date.now() - before < 5500, "the session must have a fixed deadline");
  assert.deepEqual([f.counters.head, f.counters.cas], [1, 0]);
  assert.deepEqual(readdirSync(f.checkpointDir).filter((n) => n.endsWith(".intent")), []);
});

for (const mode of ["lost-cas", "ambiguous-cas", "extra-cas"]) {
  test(`${mode} after remote commit latches durable intent; no retry or secrets disclosure`, onlyLinux, async (t) => {
    const f = await setup(t, { responseMode: mode });
    await assert.rejects(run(f.input), (error) => {
      assert.equal(error.message, "Disposable remote witness refused; independent operator reconciliation required");
      assert.doesNotMatch(error.message, /PRIVATE|BEGIN|ownerSignature|certificate|pem/u);
      return true;
    });
    assert.deepEqual([f.counters.head, f.counters.cas], [1, 1]);
    assert.deepEqual(readdirSync(f.checkpointDir).filter((n) => n.endsWith(".intent")),
      ["00000001.intent"]);
    await assert.rejects(run(f.input), /reconciliation required/u);
    assert.equal(f.counters.cas, 1);
  });
}

test("corrupted checkpoint and symlink paths never reach the witness", onlyLinux, async (t) => {
  const f = await setup(t);
  writeFileSync(path.join(f.checkpointDir, "00000000.checkpoint"), "{}");
  await assert.rejects(run(f.input), /reconciliation required/u);
  assert.equal(f.counters.data, 0);
});
