import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { constants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { verifyOfflineLocalTarOnLinux } from './offline-local-tar-verify-linux.mjs';

const script = fileURLToPath(new URL('./offline-local-tar-verify-linux.mjs', import.meta.url));
const valid = Object.freeze({
  archivePath: path.join(os.tmpdir(), 'nonexistent-virki-docker-save-fixture.tar'),
  imageId: `sha256:${'a'.repeat(64)}`,
  revision: 'b'.repeat(40), sha256: 'c'.repeat(64), size: 2048, role: 'runtime',
});

test('Linux TAR inspector never accepts an unverified or nonexistent Docker image', async () => {
  await assert.rejects(verifyOfflineLocalTarOnLinux(valid));
  for (const v of [
    { ...valid, role: 'owner' },
    { ...valid, archivePath: '../relative' },
    { ...valid, sha256: 'bad' },
    { ...valid, size: 0 },
    { ...valid, imageId: 'sha256:bad' },
    { ...valid, revision: 'main' },
  ]) await assert.rejects(verifyOfflineLocalTarOnLinux(v));
});

test('Linux TAR inspection CLI always exits nonzero without required identity and archive', () => {
  const args = [script, '--archive', valid.archivePath, '--image-id', valid.imageId,
    '--revision', valid.revision, '--sha256', valid.sha256,
    '--size', String(valid.size), '--role', valid.role];
  for (const malicious of [args.slice(0, -2), [...args, '--approve'], args]) {
    const r = spawnSync(process.execPath, malicious, { encoding: 'utf8',
      shell: false, timeout: 10000 });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /NOT_VERIFIED/u);
    assert.doesNotMatch(r.stdout, /deployAuthorized|dockerLoadAuthorized/u);
  }
  if (process.platform !== 'linux') assert.equal(Number.isInteger(constants.O_NOFOLLOW), false);
});
