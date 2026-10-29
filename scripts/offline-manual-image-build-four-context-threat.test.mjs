import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assertSourceMatchesCommittedBlobs, createOfflineManualBuildWithCachePlan } from './offline-manual-image-build.mjs';

// DEV-ONLY adversarial CONTRACT/CONSUMER model; this deliberately does NOT
// invoke buildOfflineManualImages, Docker Desktop, BuildKit, an actual daemon,
// a privileged broker, npm/Prisma cache verifiers or any production trust gate.
// A passing test confirms an EXISTING hazard in pathname-at-use semantics.
// It NEVER establishes that the published builder is secured or functional.

const REVISION = 'a'.repeat(40);
const ORIGINAL = Buffer.from('reviewed unsigned DEV fixture bytes\n');
const MALICIOUS = Buffer.from('same-user substitution consumed by fake Docker\n');
const gitBlob = (bytes) => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// The child accepts the exact `createOfflineManualBuildWithCachePlan` args and
// consumes the path like Docker's CLI would, without ever invoking Docker.
const FAKE_DOCKER = String.raw`
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
const next = (arg) => { const i = args.indexOf(arg); if (i === -1 || !args[i + 1]) process.exit(40); return args[i + 1]; };
if (args[0] !== 'build' || !args.includes('--network=none') || !args.includes('--pull=false')) process.exit(41);
const contexts = new Map([['source', path.join(args.at(-1), 'payload.txt')], ['dockerfile', next('-f')]]);
for (let i = 0; i < args.length - 1; i++) {
  if (args[i] !== '--build-context') continue;
  const split = args[i + 1].indexOf('=');
  if (split === -1) process.exit(42);
  const name = args[i + 1].slice(0, split);
  const dir = args[i + 1].slice(split + 1);
  if (name === 'offline-npm-cacache') contexts.set('npm', path.join(dir, 'cache-entry.bin'));
  if (name === 'offline-prisma-engines') contexts.set('prisma', path.join(dir, 'engine.bin'));
}
if (contexts.size !== 4 || !contexts.has(process.env.FAKE_ATTACK_TARGET)) process.exit(43);
const destination = contexts.get(process.env.FAKE_ATTACK_TARGET);
const attacker = process.env.FAKE_ATTACK_SCRIPT;
const change = spawnSync(process.execPath, [attacker, destination, process.env.FAKE_ATTACK_BYTES]);
if (change.status !== 0) process.exit(44);
const consumed = readFileSync(destination);
const restore = spawnSync(process.execPath, [attacker, destination, process.env.FAKE_ORIGINAL_BYTES]);
if (restore.status !== 0) process.exit(45);
process.stdout.write(JSON.stringify({
  role: next('--target'),
  target: process.env.FAKE_ATTACK_TARGET,
  consumedBase64: consumed.toString('base64'),
  restoredBase64: readFileSync(destination).toString('base64'),
  contextPaths: Object.fromEntries(contexts),
}));
`;

const FAKE_ATTACKER = String.raw`
import { writeFileSync } from 'node:fs';
if (process.argv.length !== 4) process.exit(51);
writeFileSync(process.argv[2], Buffer.from(process.argv[3], 'base64'));
`;

test('DEV-only: all four Docker pathname inputs for BOTH roles permit deterministic same-SID swap/read/restore', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'virki-four-context-threat-'));
  try {
    const source = path.join(scratch, 'source');
    const npm = path.join(scratch, 'npm', '_cacache');
    const prisma = path.join(scratch, 'prisma');
    const dockerfile = path.join(scratch, 'Dockerfile.manual-offline');
    for (const dir of [source, npm, prisma]) mkdirSync(dir, { recursive: true });
    const inputs = Object.freeze({
      source: path.join(source, 'payload.txt'), dockerfile,
      npm: path.join(npm, 'cache-entry.bin'), prisma: path.join(prisma, 'engine.bin'),
    });
    for (const filename of Object.values(inputs)) writeFileSync(filename, ORIGINAL);
    const sourceEntries = [{ file: 'payload.txt', objectId: gitBlob(ORIGINAL) }];
    const baselineSha = sha256(ORIGINAL);
    const plan = createOfflineManualBuildWithCachePlan({
      revision: REVISION, stagingDirectory: scratch, attemptId: '1234567890abcdef12345678',
      npmCacacheDirectory: npm, prismaEngineDirectory: prisma,
    });
    assert.deepEqual(plan.map(({ role }) => role), ['runtime', 'migrator']);
    const fakeDocker = path.join(scratch, 'fake-docker.mjs');
    const fakeAttacker = path.join(scratch, 'same-user-attacker.mjs');
    writeFileSync(fakeDocker, FAKE_DOCKER);
    writeFileSync(fakeAttacker, FAKE_ATTACKER);

    for (const rolePlan of plan) {
      for (const target of Object.keys(inputs)) {
        await t.test(`${rolePlan.role}/${target}: changed-at-use but clean Git+hash postcheck`, () => {
        // Real exported source SHA validator; other inputs use exact byte SHA.
        // These pre/post checks are INSUFFICIENT for authenticating at-use.
        assertSourceMatchesCommittedBlobs(source, sourceEntries);
        for (const filename of Object.values(inputs)) assert.equal(sha256(readFileSync(filename)), baselineSha);

        const fake = spawnSync(process.execPath, [fakeDocker, ...rolePlan.buildArgs], {
          cwd: scratch, timeout: 15000, encoding: 'utf8',
          env: { ...process.env, FAKE_ATTACK_TARGET: target,
            FAKE_ATTACK_SCRIPT: fakeAttacker,
            FAKE_ATTACK_BYTES: MALICIOUS.toString('base64'),
            FAKE_ORIGINAL_BYTES: ORIGINAL.toString('base64') },
        });
        assert.equal(fake.status, 0, `${rolePlan.role}/${target}: ${fake.stderr}`);
        const observation = JSON.parse(fake.stdout);
        assert.equal(observation.role, rolePlan.target);
        assert.equal(observation.target, target);
        assert.equal(observation.contextPaths[target], inputs[target], 'fake consumer must follow exact real argv path');
        assert.deepEqual(Buffer.from(observation.consumedBase64, 'base64'), MALICIOUS,
          'the false-consumer at-use observation must be malicious, not a fabricated success');
        assert.deepEqual(Buffer.from(observation.restoredBase64, 'base64'), ORIGINAL);

        assertSourceMatchesCommittedBlobs(source, sourceEntries);
        for (const filename of Object.values(inputs)) assert.equal(sha256(readFileSync(filename)), baselineSha);
        });
      }
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
