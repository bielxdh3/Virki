import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('./oidc-node-disposable-postgres.mjs', import.meta.url));

test('disposable PG runner finds its own installed tsx before invoking Docker', () => {
  const root = mkdtempSync(join(tmpdir(), 'virki-oidc-runner-path-'));
  try {
    const localRunner = join(root, 'scripts', 'oidc-node-disposable-postgres.mjs');
    const installedTsx = join(root, 'node_modules', 'tsx', 'dist', 'cli.mjs');
    mkdirSync(dirname(localRunner), { recursive: true });
    mkdirSync(dirname(installedTsx), { recursive: true });
    copyFileSync(source, localRunner);
    writeFileSync(installedTsx, '// Isolated resolution sentinel; not executable.\n');

    // Docker must remain unreachable: the only purpose of this test is to
    // confirm the runner passes its tsx preflight without starting a DB.
    const env = { ...process.env, VIRKI_OIDC_DOCKER_BINARY: join(root, 'nonexistent-docker') };
    delete env.VIRKI_OIDC_TSX_PATH;
    const run = spawnSync(process.execPath, [localRunner], {
      cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 15_000
    });
    assert.equal(run.error, undefined, 'The isolated subprocess itself must run');
    assert.equal(run.status, 1, 'Missing Docker must stop the test before any DB mutation');
    assert.match(run.stderr, /Disposable Docker operation failed \(image\)\./u);
    assert.doesNotMatch(run.stderr, /tsx from Virki/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
