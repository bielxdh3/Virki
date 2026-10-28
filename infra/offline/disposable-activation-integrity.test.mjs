import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
  chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync,
  readlinkSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  activateDisposableRevision, confirmDisposableRevisionHealth,
  rollbackDisposableRevision, inspectDisposableActivation,
} from "./disposable-activation-integrity.mjs";

const LINUX = { skip: process.platform !== "linux" };
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const OLD = "a".repeat(40);
const NEXT = "b".repeat(40);
const DOMAIN = "VIRKI_DISPOSABLE_ACTIVATION_HEALTH_V1";
const put = (root, rel, bytes) => {
  const target = path.join(root, rel);
  writeFileSync(target, bytes, { mode: 0o600, flag: "wx" });
  chmodSync(target, 0o600);
};

function fixture(t) {
  const oldGate = process.env.VIRKI_DISPOSABLE_ACTIVATION_INTEGRITY;
  process.env.VIRKI_DISPOSABLE_ACTIVATION_INTEGRITY = "1";
  t.after(() => {
    if (oldGate === undefined) delete process.env.VIRKI_DISPOSABLE_ACTIVATION_INTEGRITY;
    else process.env.VIRKI_DISPOSABLE_ACTIVATION_INTEGRITY = oldGate;
  });
  const root = mkdtempSync(path.join(tmpdir(), "virki-activation-integrity-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const folder of ["operator", "state", "state/journal", "releases",
    `releases/${OLD}`, `releases/${NEXT}`, "data", "evidence"]) {
    mkdirSync(path.join(root, folder), { mode: 0o700 });
  }
  const pair = generateKeyPairSync("ed25519");
  const key = pair.publicKey.export({ format: "pem", type: "spki" });
  const previousRuntime = Buffer.from("previous-runtime");
  const runtime = Buffer.from("native-fixture-runtime-new");
  const data = Buffer.from("PRIVATE-DATA-MUST-STAY-UNCHANGED");
  put(root, `releases/${OLD}/runtime.bin`, previousRuntime);
  put(root, `releases/${NEXT}/runtime.bin`, runtime);
  put(root, "data/live.bin", data);
  symlinkSync(`releases/${OLD}`, path.join(root, "current"));
  const plan = {
    version: 1, txId: randomBytes(32).toString("hex"),
    hostIdentitySha256: randomBytes(32).toString("hex"),
    previousSha: OLD, nextSha: NEXT,
    expectedDataSha256: digest(data),
    expectedPreviousRuntimeSha256: digest(previousRuntime),
    expectedRuntimeSha256: digest(runtime),
    healthPublicKeyPem: key,
    healthPinSha256: digest(pair.publicKey.export({ format: "der", type: "spki" })),
  };
  put(root, "operator/activation.json", Buffer.from(JSON.stringify(plan)));
  const request = { fixtureRoot: root };
  function health(overrides = {}) {
    const switchEvent = JSON.parse(readFileSync(path.join(root, "state/journal/00000002.json"), "utf8"));
    const message = {
      version: 1, domain: DOMAIN, txId: plan.txId,
      hostIdentitySha256: plan.hostIdentitySha256, previousSha: OLD, nextSha: NEXT,
      route: `releases/${NEXT}`, runtimeSha256: digest(runtime),
      dataSha256: digest(data), switchEventSha256: switchEvent.eventSha256,
      healthy: true, ...overrides,
    };
    const signature = sign(null, Buffer.from(`${DOMAIN}\0${JSON.stringify(message)}`),
      pair.privateKey).toString("base64");
    put(root, "evidence/health.json", Buffer.from(JSON.stringify({ message, signature })));
  }
  const journal = () => path.join(root, "state/journal");
  return { root, request, plan, data, runtime, health, journal };
}

test("TDD: activate keeps predecessor+data, journals intent and switch; independent bound health completes", LINUX, (t) => {
  const f = fixture(t);
  const activated = activateDisposableRevision(f.request);
  assert.equal(activated.deployAuthorized, false);
  assert.equal(activated.status, "pending-independent-health-dev-only");
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${NEXT}`);
  assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
  assert.ok(existsSync(path.join(f.root, `releases/${OLD}/runtime.bin`)));
  assert.equal(inspectDisposableActivation(f.request).status, "pending-independent-health-dev-only");
  assert.throws(() => confirmDisposableRevisionHealth(f.request), /blocked/u);
  f.health();
  const completed = confirmDisposableRevisionHealth(f.request);
  assert.equal(completed.status, "health-evidence-recorded-dev-only");
  assert.equal(completed.deployAuthorized, false);
  assert.equal(inspectDisposableActivation(f.request).status, "health-evidence-recorded-dev-only");
  assert.throws(() => activateDisposableRevision(f.request), /blocked/u);
  assert.throws(() => rollbackDisposableRevision(f.request), /blocked/u);
});

test("TDD: signed health bound to wrong current revision or changed runtime/data refuses", LINUX, (t) => {
  for (const variant of ["wrong-revision", "changed-runtime", "changed-data", "corrupt-signature"]) {
    const f = fixture(t);
    activateDisposableRevision(f.request);
    if (variant === "changed-runtime") {
      rmSync(path.join(f.root, `releases/${NEXT}/runtime.bin`));
      put(f.root, `releases/${NEXT}/runtime.bin`, Buffer.from("tampered"));
    }
    if (variant === "changed-data") {
      rmSync(path.join(f.root, "data/live.bin"));
      put(f.root, "data/live.bin", Buffer.from("tampered"));
    }
    f.health(variant === "wrong-revision" ? { nextSha: OLD } :
      variant === "corrupt-signature" ? { healthy: false } : {});
    assert.throws(() => confirmDisposableRevisionHealth(f.request), /blocked/u, variant);
    assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${NEXT}`);
  }
});

test("TDD: rollback creates durable intent and restores only previous route", LINUX, (t) => {
  const f = fixture(t);
  activateDisposableRevision(f.request);
  const status = rollbackDisposableRevision(f.request);
  assert.equal(status.status, "rolled-back-dev-only");
  assert.equal(status.deployAuthorized, false);
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${OLD}`);
  assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
  assert.equal(inspectDisposableActivation(f.request).status, "rolled-back-dev-only");
  assert.throws(() => rollbackDisposableRevision(f.request), /blocked/u);
});

test("TDD RED P2: corrupting owner-private predecessor bytes blocks rollback before switching current", LINUX, (t) => {
  const f = fixture(t);
  activateDisposableRevision(f.request);
  const oldRuntime = path.join(f.root, `releases/${OLD}/runtime.bin`);
  const original = readFileSync(oldRuntime);
  const corrupted = Buffer.from(original);
  corrupted[0] ^= 1;
  // Same length, same path, regular owner-only 0600: metadata checks alone pass.
  rmSync(oldRuntime);
  put(f.root, `releases/${OLD}/runtime.bin`, corrupted);
  assert.equal(readFileSync(oldRuntime).length, original.length);
  assert.equal(inspectDisposableActivation(f.request).status, "blocked-ambiguous-dev-only");
  assert.throws(() => rollbackDisposableRevision(f.request), /blocked/u);
  assert.throws(() => confirmDisposableRevisionHealth(f.request), /blocked/u);
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${NEXT}`);
  assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
  assert.ok(!existsSync(path.join(f.journal(), "00000003.json")),
    "rollback-intent must never be written for a corrupt predecessor");
});

test("TDD RED P2: even after a completed rollback predecessor integrity remains required", LINUX, (t) => {
  const f = fixture(t);
  activateDisposableRevision(f.request);
  rollbackDisposableRevision(f.request);
  const oldRuntime = path.join(f.root, `releases/${OLD}/runtime.bin`);
  rmSync(oldRuntime);
  put(f.root, `releases/${OLD}/runtime.bin`, Buffer.from("corrupted-previous-runtime"));
  assert.equal(inspectDisposableActivation(f.request).status, "blocked-ambiguous-dev-only");
  assert.throws(() => rollbackDisposableRevision(f.request), /blocked/u);
  assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
});

test("TDD: process SIGKILL after intent or rename never permits implicit replay or rollback", LINUX, (t) => {
  for (const stage of ["after-intent", "after-rename", "after-rollback-intent", "after-rollback-rename"]) {
    const f = fixture(t);
    if (stage.startsWith("after-rollback")) activateDisposableRevision(f.request);
    const code = stage.startsWith("after-rollback") ? "rollbackDisposableRevision" : "activateDisposableRevision";
    const js = `import { ${code} } from ${JSON.stringify(new URL("./disposable-activation-integrity.mjs", import.meta.url).href)}; ${code}({fixtureRoot:process.argv[1]});`;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", js, f.root], {
      env: { ...process.env, VIRKI_DISPOSABLE_ACTIVATION_FAULT: stage },
      timeout: 10000, encoding: "utf8",
    });
    assert.notEqual(child.status, 0, stage);
    assert.equal(inspectDisposableActivation(f.request).status, "blocked-ambiguous-dev-only");
    assert.throws(() => activateDisposableRevision(f.request), /blocked/u);
    assert.throws(() => rollbackDisposableRevision(f.request), /blocked/u);
    assert.throws(() => confirmDisposableRevisionHealth(f.request), /blocked/u);
    assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
  }
});

test("TDD: duplicate attempts, untrusted journal rewrites and symlink paths are refused", LINUX, (t) => {
  const f = fixture(t);
  activateDisposableRevision(f.request);
  assert.throws(() => activateDisposableRevision(f.request), /blocked/u);
  const filename = path.join(f.journal(), "00000001.json");
  const original = readFileSync(filename);
  rmSync(filename);
  put(f.root, "state/journal/00000001.json", Buffer.from(JSON.stringify({ forged: true })));
  assert.equal(inspectDisposableActivation(f.request).status, "blocked-ambiguous-dev-only");
  assert.throws(() => rollbackDisposableRevision(f.request), /blocked/u);
  assert.ok(original.length > 0);
});

test("TDD: unsafe owner/mode or symlink candidate refuses before modifying the route", LINUX, (t) => {
  for (const kind of ["mode", "symlink", "hardlink"]) {
    const f = fixture(t);
    if (kind === "mode") chmodSync(path.join(f.root, "state"), 0o777);
    else if (kind === "symlink") {
      rmSync(path.join(f.root, `releases/${NEXT}/runtime.bin`));
      symlinkSync(path.join(f.root, "data/live.bin"), path.join(f.root, `releases/${NEXT}/runtime.bin`));
    } else linkSync(path.join(f.root, "data/live.bin"), path.join(f.root, "evidence/data-alias"));
    assert.throws(() => activateDisposableRevision(f.request), /blocked/u);
    assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${OLD}`);
    assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
  }
});

test("TDD: a signed report from another Ed25519 principal or swapped active route cannot confirm health", LINUX, (t) => {
  for (const variant of ["wrong-signer", "wrong-route"]) {
    const f = fixture(t);
    activateDisposableRevision(f.request);
    f.health();
    if (variant === "wrong-signer") {
      const proofPath = path.join(f.root, "evidence/health.json");
      const proof = JSON.parse(readFileSync(proofPath, "utf8"));
      const attacker = generateKeyPairSync("ed25519");
      proof.signature = sign(null, Buffer.from(`${DOMAIN}\0${JSON.stringify(proof.message)}`),
        attacker.privateKey).toString("base64");
      rmSync(proofPath);
      put(f.root, "evidence/health.json", Buffer.from(JSON.stringify(proof)));
    } else {
      const route = path.join(f.root, "current");
      rmSync(route);
      symlinkSync("data", route);
    }
    assert.throws(() => confirmDisposableRevisionHealth(f.request), /blocked/u, variant);
    assert.equal(inspectDisposableActivation(f.request).status, "blocked-ambiguous-dev-only");
    assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
  }
});

test("TDD: replacing a still-valid signed health receipt after journal commit is detected", LINUX, (t) => {
  const f = fixture(t);
  activateDisposableRevision(f.request);
  f.health();
  confirmDisposableRevisionHealth(f.request);
  const file = path.join(f.root, "evidence/health.json");
  const proof = JSON.parse(readFileSync(file, "utf8"));
  // The signer and message remain valid; only outer JSON byte order changes.
  rmSync(file);
  put(f.root, "evidence/health.json",
    Buffer.from(JSON.stringify({ signature: proof.signature, message: proof.message })));
  assert.equal(inspectDisposableActivation(f.request).status, "blocked-ambiguous-dev-only");
  assert.throws(() => confirmDisposableRevisionHealth(f.request), /blocked/u);
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${NEXT}`);
  assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
});

test("TDD: two native OS processes race same journal and only one can change the route", LINUX, async (t) => {
  const f = fixture(t);
  const script = `import {activateDisposableRevision} from ${JSON.stringify(new URL("./disposable-activation-integrity.mjs", import.meta.url).href)};
    try { activateDisposableRevision({ fixtureRoot: process.argv[1] }); process.exit(0); }
    catch { process.exit(9); }`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script, f.root], {
      env: { ...process.env, VIRKI_DISPOSABLE_ACTIVATION_INTEGRITY: "1" },
      stdio: "ignore",
    });
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
  const results = await Promise.all([run(), run()]);
  assert.deepEqual(results.sort(), [0, 9]);
  assert.equal(inspectDisposableActivation(f.request).status, "pending-independent-health-dev-only");
  assert.equal(readlinkSync(path.join(f.root, "current")), `releases/${NEXT}`);
  assert.deepEqual(readFileSync(path.join(f.root, "data/live.bin")), f.data);
});
