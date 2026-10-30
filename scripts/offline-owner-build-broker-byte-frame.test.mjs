import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import test from 'node:test';
import {
  encodeUnsignedDevFourContextFrame, consumeUnsignedDevFourContextFrame,
  consumeUnsignedDevFourContextStream,
} from './offline-owner-build-broker-byte-frame.mjs';

// A transport proof, NOT a protected broker or an image build. Unlike a
// caller-supplied JSON "readout", the child MUST receive and hash real bytes
// from stdin. It never receives any file path and cannot re-open the source.
const REVISION = 'a'.repeat(40);
const NONCE = 'b'.repeat(32);
const KINDS = ['source', 'dockerfile', 'npm', 'prisma'];
const ORIGINAL = Buffer.from('original synthetic development context bytes\n');
const ORIGINAL_BY_KIND = Object.freeze(Object.fromEntries(
  KINDS.map((kind) => [kind, Buffer.concat([Buffer.from(kind + ':'), ORIGINAL])])));
const ATTACK = Buffer.from('same SID modified source pathname contents\n');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const pins = (role) => ({
  revision: REVISION, role, nonce: NONCE,
  inputs: Object.fromEntries(KINDS.map((name) => [name,
    { sha256: sha256(ORIGINAL_BY_KIND[name]), bytes: ORIGINAL_BY_KIND[name].length }])),
});
const originalInputs = () => Object.fromEntries(
  KINDS.map((name) => [name, Buffer.from(ORIGINAL_BY_KIND[name])]));
const consumerModule = fileURLToPath(new URL('./offline-owner-build-broker-byte-frame.mjs', import.meta.url));
const consumeChild = [
  "import { createHash } from 'node:crypto';",
  'const { consumeUnsignedDevFourContextStream } = await import(process.argv[1]);',
  'const expected = JSON.parse(process.argv[2]);',
  'const result = await consumeUnsignedDevFourContextStream(process.stdin, expected);',
  'process.stdout.write(JSON.stringify({ status: result.status, authorized: result.dockerBuildAuthorized,',
  '  actual: Object.fromEntries(Object.entries(result.bytes).map(([key, value]) =>',
  '    [key, createHash("sha256").update(value).digest("hex")])) }));',
].join('\n');

test('byte frame parser consumes all four actual pinned buffers without any pathname inputs', () => {
  const expected = pins('runtime');
  const frame = encodeUnsignedDevFourContextFrame(originalInputs(), expected);
  const result = consumeUnsignedDevFourContextFrame(frame, expected);
  assert.equal(result.status, 'DEV_ONLY_UNSIGNED_BYTE_SNAPSHOT_NO_AUTHORITY');
  assert.equal(result.dockerBuildAuthorized, false);
  assert.equal(result.daemonIdentityVerified, false);
  assert.equal(result.ownerSignatureVerified, false);
  assert.equal(result.deployAuthorized, false);
  assert.deepEqual(Object.keys(result.bytes), KINDS);
  for (const kind of KINDS) assert.deepEqual(result.bytes[kind], ORIGINAL_BY_KIND[kind]);
});

test('child receives pinned input bytes over stdin despite same-user pathname swap for all four roles/contexts', async (t) => {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'virki-dev-byte-frame-'));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const files = Object.fromEntries(KINDS.map((kind) => [kind, path.join(scratch, kind + '.bin')]));
  for (const kind of KINDS) writeFileSync(files[kind], ORIGINAL_BY_KIND[kind]);
  for (const role of ['runtime', 'migrator']) {
    const expected = pins(role);
    const frame = encodeUnsignedDevFourContextFrame(
      Object.fromEntries(KINDS.map((kind) => [kind, readFileSync(files[kind])])), expected);
    for (const kind of KINDS) {
      await t.test(role + '/' + kind, () => {
        // A second same-user process can alter the pathname, but the child
        // will receive ONLY immutable-by-value stdin bytes, never the path.
        const attack = spawnSync(process.execPath, ['-e',
          "require('node:fs').writeFileSync(process.argv[1], Buffer.from(process.argv[2], 'base64'))",
          files[kind], ATTACK.toString('base64')], { encoding: 'utf8', timeout: 5000 });
        assert.equal(attack.status, 0, attack.stderr);
        assert.deepEqual(readFileSync(files[kind]), ATTACK);
        const child = spawnSync(process.execPath,
          ['--input-type=module', '-e', consumeChild, 'file:///' + consumerModule.replaceAll('\\', '/'),
            JSON.stringify(expected)],
          { input: frame, encoding: 'utf8', timeout: 5000 });
        assert.equal(child.status, 0, child.stderr);
        const consumed = JSON.parse(child.stdout);
        assert.equal(consumed.status, 'DEV_ONLY_UNSIGNED_BYTE_SNAPSHOT_NO_AUTHORITY');
        assert.equal(consumed.authorized, false);
        for (const [observedKind, observed] of Object.entries(consumed.actual))
          assert.equal(observed, sha256(ORIGINAL_BY_KIND[observedKind]),
            'actual byte consumer must receive pinned snapshot instead of raced pathname');
        writeFileSync(files[kind], ORIGINAL_BY_KIND[kind]);
      });
    }
  }
});

test('modified framing bytes, wrong revision, mismatched nonce and fake authority cannot pass receiver-owned pins', () => {
  const expected = pins('migrator');
  const frame = encodeUnsignedDevFourContextFrame(originalInputs(), expected);
  const tampered = Buffer.from(frame);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => consumeUnsignedDevFourContextFrame(tampered, expected),
    /byte snapshot digest mismatch/u);
  for (const badPins of [
    { ...expected, nonce: 'c'.repeat(32) },
    { ...expected, revision: 'c'.repeat(40) },
    { ...expected, role: 'runtime' },
  ]) assert.throws(() => consumeUnsignedDevFourContextFrame(frame, badPins));
  assert.throws(() => encodeUnsignedDevFourContextFrame(
    { ...originalInputs(), prisma: ATTACK }, expected), /digest mismatch/u);
  assert.throws(() => encodeUnsignedDevFourContextFrame(
    originalInputs(), { ...expected, deployAuthorized: true }));
  const swapped = originalInputs();
  [swapped.source, swapped.prisma] = [swapped.prisma, swapped.source];
  assert.throws(() => encodeUnsignedDevFourContextFrame(swapped, expected),
    /source-to-frame digest mismatch/u, 'distinct kind pins must reject cross-context swapping');
  const oversized = { ...originalInputs(), npm: Buffer.alloc(64 * 1024 + 1) };
  assert.throws(() => encodeUnsignedDevFourContextFrame(oversized, expected));
  assert.throws(() => consumeUnsignedDevFourContextFrame(frame.subarray(0, frame.length - 1), expected),
    /incomplete byte payload/u);
  assert.throws(() => consumeUnsignedDevFourContextFrame(Buffer.concat([frame, Buffer.from([0])]), expected),
    /trailing unsigned frame bytes/u);
  // This stateless DEV parser CANNOT deny a second use of the same valid nonce.
  assert.equal(consumeUnsignedDevFourContextFrame(frame, expected).dockerBuildAuthorized, false);
  assert.equal(consumeUnsignedDevFourContextFrame(frame, expected).dockerBuildAuthorized, false);
});

test('DEV stream receiver bounds stdin before accumulation and consumes exact separately pinned bytes', async () => {
  const expected = pins('runtime');
  const frame = encodeUnsignedDevFourContextFrame(originalInputs(), expected);
  const consumed = await consumeUnsignedDevFourContextStream(
    Readable.from([frame.subarray(0, 7), frame.subarray(7, 19), frame.subarray(19)]), expected);
  assert.equal(consumed.dockerBuildAuthorized, false);
  for (const kind of KINDS) assert.deepEqual(consumed.bytes[kind], ORIGINAL_BY_KIND[kind]);
  await assert.rejects(consumeUnsignedDevFourContextStream(
    Readable.from([Buffer.alloc(4 * 65536 + 2048 + frame.length + 1)]), expected),
  /oversized stdin byte frame/u);
  await assert.rejects(consumeUnsignedDevFourContextStream(
    Readable.from([frame.subarray(0, frame.length - 1)]), expected),
  /incomplete byte payload/u);
});
