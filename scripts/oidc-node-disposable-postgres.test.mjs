import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createAdmittedOidcDockerClient } from './lib/disposable-docker-session.mjs';
import { createVerifiedPortableOidcPgClient } from './lib/oidc-portable-native-transport.mjs';

const source = fileURLToPath(new URL('./oidc-node-disposable-postgres.mjs', import.meta.url));

test('disposable PG runner finds its own installed tsx before invoking Docker', () => {
  const root = mkdtempSync(join(tmpdir(), 'virki-oidc-runner-path-'));
  try {
    const localRunner = join(root, 'scripts', 'oidc-node-disposable-postgres.mjs');
    const installedTsx = join(root, 'node_modules', 'tsx', 'dist', 'cli.mjs');
    mkdirSync(dirname(localRunner), { recursive: true });
    mkdirSync(dirname(installedTsx), { recursive: true });
    copyFileSync(source, localRunner);
    for (const name of [
      'disposable-docker-session.mjs', 'disposable-docker-cleanup.mjs',
      'disposable-docker-mutation-policy.mjs', 'production-boundary-assertion.mjs',
      'disposable-docker-receipt-security.mjs'
    ]) {
      const dest = join(root, 'scripts', 'lib', name);
      mkdirSync(dirname(dest), { recursive: true });
      copyFileSync(fileURLToPath(new URL(`./lib/${name}`, import.meta.url)), dest);
    }
    writeFileSync(installedTsx, '// Isolated resolution sentinel; not executable.\n');

    // Refuse engine admission before any Docker call. The pinned CLI ignores
    // VIRKI_OIDC_DOCKER_BINARY, so an invalid architecture is the safe gate.
    const env = { ...process.env, VIRKI_BUILD_ARCH: 'unsupported-test-arch' };
    delete env.VIRKI_OIDC_TSX_PATH;
    const run = spawnSync(process.execPath, [localRunner], {
      cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 15_000
    });
    assert.equal(run.error, undefined, 'The isolated subprocess itself must run');
    assert.equal(run.status, 1, 'Unadmitted engine must stop before any DB mutation');
    assert.match(run.stderr, /Disposable Docker session refused:/u);
    if (process.platform === 'win32') {
      assert.match(run.stderr, /Windows Docker Desktop validation requires amd64/u);
    }
    assert.doesNotMatch(run.stderr, /tsx from Virki/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('OIDC Docker runner pins all invocations and child processes to the admitted Windows engine', () => {
  const calls = [];
  const ambient = {
    DOCKER_HOST: 'tcp://prod.internal:2376',
    DOCKER_CONTEXT: 'production',
    DOCKER_CONFIG: 'C:\\untrusted-docker-config',
    DOCKER_TLS_VERIFY: '1',
    DOCKER_CERT_PATH: 'C:\\untrusted-certificates',
    VIRKI_OIDC_DOCKER_BINARY: 'evil-docker',
    PATH: 'system-path'
  };
  const docker = createAdmittedOidcDockerClient({
    env: ambient, platform: 'win32', nativeArch: 'x64',
    spawn: (cli, args, options) => {
      calls.push({ cli, args, env: options.env });
      return { status: 0, stdout: args[2] === 'version' ? 'linux|amd64\n' : 'ok\n' };
    }
  });
  for (const args of [
    ['image', 'inspect', 'postgres:18.6-alpine3.24'],
    ['run', '--detach', '--name', 'virki-owned'],
    ['exec', 'virki-owned', 'pg_isready'],
    ['inspect', 'virki-owned'],
    ['rm', '--force', '--volumes', 'virki-owned']
  ]) assert.equal(docker.invoke(args).status, 0);

  assert.equal(calls.length, 6, 'preflight must precede every use, including cleanup');
  for (const call of calls) {
    assert.equal(call.cli, 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe');
    assert.deepEqual(call.args.slice(0, 2), ['--host', 'npipe:////./pipe/dockerDesktopLinuxEngine']);
    assert.equal(call.env.DOCKER_HOST, 'npipe:////./pipe/dockerDesktopLinuxEngine');
    assert.equal(call.env.DOCKER_CONTEXT, undefined);
    assert.equal(call.env.DOCKER_CONFIG, undefined);
    assert.equal(call.env.DOCKER_TLS_VERIFY, undefined);
    assert.equal(call.env.DOCKER_CERT_PATH, undefined);
    assert.equal(call.env.PATH, 'system-path');
  }
  assert.equal(docker.subprocessEnv.VIRKI_OIDC_DOCKER_BINARY, calls[0].cli);
  assert.equal(docker.subprocessEnv.DOCKER_CONTEXT, undefined);
  assert.equal(docker.subprocessEnv.DOCKER_HOST, 'npipe:////./pipe/dockerDesktopLinuxEngine');
});

test('OIDC Docker refuses a missing or untrusted engine before any resource mutation', () => {
  const calls = [];
  assert.throws(() => createAdmittedOidcDockerClient({
    platform: 'linux', nativeArch: 'x64', env: {
      DOCKER_HOST: 'ssh://root@production', DOCKER_CONTEXT: 'production'
    },
    spawn: (...args) => { calls.push(args); return { status: 0, stdout: 'linux|amd64' }; }
  }), /Disposable Docker session refused/u);
  assert.equal(calls.length, 0, 'untrusted Linux host cannot even run Docker preflight');
  assert.throws(() => createAdmittedOidcDockerClient({
    platform: 'win32', nativeArch: 'x64', env: { DOCKER_HOST: 'tcp://prod.internal:2376' },
    spawn: (cli, args) => {
      calls.push({ cli, args });
      return { status: 1, stdout: '', stderr: 'daemon unavailable' };
    }
  }), /explicit Linux\/amd64 Docker endpoint was not verified/u);
  assert.equal(calls.length, 1, 'daemon failure must abort before image inspect and run');
});

test('direct PG18 integration entrypoint cannot bypass Docker admission', () => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const repoRoot = fileURLToPath(new URL('../', import.meta.url));
  const direct = 'packages/oidc-node/src/postgres-store.integration.test.ts';
  assert.ok(existsSync(tsx), 'local tsx must be installed');
  const env = { ...process.env, VIRKI_BUILD_ARCH: 'untrusted-test-arch',
    DOCKER_HOST: 'tcp://production.internal:2376', DOCKER_CONTEXT: 'production',
    VIRKI_OIDC_DOCKER_BINARY: 'evil-docker' };
  // Node's parent test worker must not suppress a nested --test invocation.
  delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, [tsx, '--test', direct], {
    cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 15_000,
    env
  });
  assert.equal(run.error, undefined);
  assert.equal(run.status, 1,
    'direct invocation must fail before SQL and remote Docker calls: ' + run.stdout + run.stderr);
  assert.match(run.stdout + run.stderr, /Disposable Docker session refused:/u);
});

test('portable PG18 socket transport requires an owned private cluster, never an ambient Docker context', () => {
  const owner = '12345678-1234-4123-8123-123456789abc';
  const root = '/dev/shm/virki59-oidc-store-Ab1cD234';
  const socket = root + '/socket';
  const shim = root + '/tools/docker';
  const psql = '/opt/private-pg18/root/usr/lib/postgresql/18/bin/psql';
  const env = {
    VIRKI_OIDC_PG_TRANSPORT: 'portable-native',
    VIRKI_OIDC_PG_SOCKET: socket,
    VIRKI_OIDC_DOCKER_BINARY: shim,
    VIRKI_OIDC_PSQL_BINARY: psql,
    VIRKI_OIDC_PG_CONTAINER: 'virki-oidc-pg18-' + owner,
    VIRKI_OIDC_PG_ROLE: 'rp_oidc_owner',
    VIRKI_OIDC_PG_DATABASE: 'rp_oidc_proof',
    VIRKI_OIDC_PG_SCHEMA: 'rp_oidc_private',
    VIRKI_OIDC_PG_PASSWORD: 'a'.repeat(64),
    PGHOST: socket,
    PGPORT: '25575',
    PGHOSTADDR: '10.0.0.4',
    PGSERVICE: 'production',
    DOCKER_HOST: 'tcp://production.internal:2376',
    DOCKER_CONTEXT: 'production',
    LD_LIBRARY_PATH: '/opt/private-pg18/root/usr/lib/x86_64-linux-gnu'
  };
  const fsState = new Map([
    [root, 'directory'], [socket, 'directory'], [root + '/pgdata', 'directory'],
    [root + '/tools', 'directory'], [shim, 'file'],
    [root + '/.owner', 'file'], [psql, 'file']
  ]);
  const fakeStat = (p) => ({
    uid: 1001,
    mode: p === psql ? 0o100755 : fsState.get(p) === 'file' ? 0o100600 : 0o40700,
    isDirectory: () => fsState.get(p) === 'directory',
    isFile: () => fsState.get(p) === 'file',
    isSymbolicLink: () => false
  });
  const args = { env, platform: 'linux', uid: 1001, stat: fakeStat, read: () => owner + '\n' };
  const admitted = createVerifiedPortableOidcPgClient(args);
  assert.equal(admitted.binary, shim);
  assert.equal(admitted.subprocessEnv.PGHOST, socket);
  assert.equal(admitted.subprocessEnv.PGPORT, '25575');
  assert.equal(admitted.subprocessEnv.PGHOSTADDR, undefined);
  assert.equal(admitted.subprocessEnv.PGSERVICE, undefined);
  assert.equal(admitted.subprocessEnv.DOCKER_HOST, undefined);
  assert.equal(admitted.subprocessEnv.DOCKER_CONTEXT, undefined);
  assert.equal(admitted.subprocessEnv.LD_LIBRARY_PATH, env.LD_LIBRARY_PATH);
  for (const hostile of [
    { VIRKI_OIDC_DOCKER_BINARY: '/usr/bin/docker' },
    { VIRKI_OIDC_PG_SOCKET: '/tmp/prod/socket' },
    { VIRKI_OIDC_PG_CONTAINER: 'virki-oidc-pg18-' + '0'.repeat(36) },
    { PGHOST: '/var/run/postgresql' },
    { VIRKI_OIDC_PG_ROLE: 'postgres' }
  ]) {
    assert.throws(() => createVerifiedPortableOidcPgClient({
      ...args, env: { ...env, ...hostile }
    }), /Portable PostgreSQL transport refused/u);
  }
  assert.throws(() => createVerifiedPortableOidcPgClient({
    ...args, platform: 'win32'
  }), /Portable PostgreSQL transport refused/u);
  assert.throws(() => createVerifiedPortableOidcPgClient({
    ...args, stat: (p) => p === root ? { ...fakeStat(p), mode: 0o40777 } : fakeStat(p)
  }), /Portable PostgreSQL transport refused/u);
  assert.throws(() => createVerifiedPortableOidcPgClient({
    ...args, stat: (p) => p === shim ? { ...fakeStat(p), isSymbolicLink: () => true } : fakeStat(p)
  }), /Portable PostgreSQL transport refused/u);
});

test('OIDC runner cleanup distinguishes auto-removed containers from denied or uncertain inspect', () => {
  const root = mkdtempSync(join(tmpdir(), 'virki-oidc-cleanup-fixture-'));
  try {
    const runner = join(root, 'scripts', 'oidc-node-disposable-postgres.mjs');
    const mockDocker = join(root, 'scripts', 'lib', 'disposable-docker-session.mjs');
    const mockChild = join(root, 'scripts', 'mock-child.mjs');
    const tsx = join(root, 'node_modules', 'tsx', 'dist', 'cli.mjs');
    mkdirSync(dirname(mockDocker), { recursive: true });
    mkdirSync(dirname(tsx), { recursive: true });
    writeFileSync(tsx, '// Exists only to pass runner tsx preflight.\n');
    const original = readFileSync(source, 'utf8');
    const patched = original
      .replace('import { spawnSync } from "node:child_process";',
        'import { spawnSync } from "./mock-child.mjs";')
      .replace('from "./lib/disposable-docker-receipt-security.mjs";',
        'from "./lib/mock-security.mjs";')
      .replace('from "node:fs";', 'from "./mock-fs.mjs";');
    assert.notEqual(patched, original, 'fixture must replace child launcher to prevent DB access');
    writeFileSync(runner, patched);
    writeFileSync(join(root, 'package.json'), '{"type":"module"}\n');
    writeFileSync(mockChild, `
      export function spawnSync() { return { status: 0 }; }
    `);
    writeFileSync(join(root, 'scripts', 'lib', 'mock-security.mjs'), `
      import { fileURLToPath } from 'node:url';
      import { join } from 'node:path';
      export const ownerEvidenceDirectory = (_, kind) => join(
        fileURLToPath(new URL("../../", import.meta.url)),
        '.virki-mission-tmp', kind + '-docker-recovery'
      );
      export const ensurePrivateEvidenceDirectory = () => {};
      export const assertPrivateEvidenceFile = () => {};
    `);
    writeFileSync(join(root, 'scripts', 'mock-fs.mjs'), `
      export { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync } from 'node:fs';
      import { writeSync as actualWriteSync } from 'node:fs';
      export function writeSync(fd, bytes, offset, length) {
        if (process.env.VIRKI_FAKE_CLEANUP_SCENARIO === 'zero-write') return 0;
        return actualWriteSync(fd, bytes, offset, Math.min(length, 3));
      }
    `);
    // This private stub cannot launch Docker or connect to any daemon.
    writeFileSync(mockDocker, `
      import { appendFileSync } from 'node:fs';
      export function createAdmittedOidcDockerClient() {
        let owner = null, name, removed = false, inspectCount = 0;
        const cid = 'a'.repeat(64);
        const otherCid = 'b'.repeat(64);
        const missing = (target) => ({
          status: 1, stderr: 'Error: No such object: ' + target + '\\n'
        });
        const record = (args) => appendFileSync(process.env.VIRKI_FAKE_DOCKER_LOG, JSON.stringify(args) + '\\n');
        return {
          subprocessEnv: { DOCKER_HOST: 'npipe:////./pipe/dockerDesktopLinuxEngine',
            VIRKI_OIDC_DOCKER_BINARY: 'nonexistent-test-only' },
          invoke(args) {
            record(args);
            const ok = (stdout = 'ok') => ({ status: 0, stdout });
            if (args[0] === 'run') {
              name = args[args.indexOf('--name') + 1];
              owner = args[args.indexOf('--label') + 1].split('=').at(-1);
              return ['run-error', 'late-create'].includes(process.env.VIRKI_FAKE_CLEANUP_SCENARIO)
                ? { status: 1, stderr: 'lost Docker ACK' } : ok(cid);
            }
            if (args[0] === 'port') return ok('127.0.0.1:5432');
            if (args[0] === 'exec' && args.includes('SHOW server_version')) return ok('18.6');
            if (args[0] === 'inspect') {
              inspectCount += 1;
              const scenario = process.env.VIRKI_FAKE_CLEANUP_SCENARIO;
              if (['absent', 'late-create'].includes(scenario) ||
                  (removed && scenario !== 'still-present')) return missing(args.at(-1));
              if (scenario === 'denied') return {
                status: 1, stderr: 'permission denied by daemon\\n'
              };
              if (scenario === 'timeout') return {
                status: null, error: { code: 'ETIMEDOUT' }, stderr: ''
              };
              if (scenario === 'wrong-owner') return ok(cid + '|/' + name + '|foreign-owner');
              if (scenario === 'id-swap') return ok(otherCid + '|/' + name + '|' + owner);
              if (scenario === 'name-swap' && inspectCount > 1) {
                return ok(cid + '|/replaced-name|' + owner);
              }
              return ok(cid + '|/' + name + '|' + owner);
            }
            if (args[0] === 'rm' && process.env.VIRKI_FAKE_CLEANUP_SCENARIO === 'rm-denied') {
              return { status: 1, stderr: 'permission denied' };
            }
            if (args[0] === 'rm') removed = true;
            return ok();
          }
        };
      }
    `);
    for (const [scenario, expected, expectedRemoval] of [
      ['absent', 0, false],
      ['denied', 1, false],
      ['timeout', 1, false],
      ['wrong-owner', 1, false],
      ['rm-denied', 1, true],
      ['owned', 0, true],
      ['run-error', 1, true],
      ['late-create', 1, false],
      ['id-swap', 1, false],
      ['name-swap', 1, false],
      ['still-present', 1, true],
      ['zero-write', 1, false]
    ]) {
      const log = join(root, 'scenario-' + scenario + '.jsonl');
      const receiptDir = join(root, '.virki-mission-tmp', 'oidc-docker-recovery');
      mkdirSync(receiptDir, { recursive: true });
      const before = new Set(readdirSync(receiptDir));
      const run = spawnSync(process.execPath, [runner], {
        cwd: root, encoding: 'utf8', timeout: 10_000, windowsHide: true,
        env: {
          ...process.env, VIRKI_OIDC_TSX_PATH: tsx,
          VIRKI_FAKE_CLEANUP_SCENARIO: scenario, VIRKI_FAKE_DOCKER_LOG: log,
          DOCKER_HOST: 'tcp://production.example:2376', DOCKER_CONTEXT: 'production'
        }
      });
      assert.equal(run.error, undefined, scenario + ': isolated runner must complete');
      assert.equal(run.status, expected, scenario + ': no false green after uncertain cleanup');
      const calls = readFileSync(log, 'utf8').trim().split(/\r?\n/u).map(JSON.parse);
      if (scenario === 'zero-write') {
        assert.equal(calls.some((args) => args[0] === 'run'), false,
          'incomplete receipt write must block Docker mutation');
        continue;
      }
      assert.equal(calls.some((args) => args[0] === 'run'), true, scenario + ': must simulate start');
      assert.equal(calls.some((args) => args[0] === 'inspect'), true, scenario + ': must inspect');
      assert.equal(calls.some((args) => args[0] === 'rm'), expectedRemoval,
        scenario + ': never delete an unverified object');
      const created = readdirSync(receiptDir).filter((entry) => !before.has(entry));
      assert.equal(created.length, 1, scenario + ': one durable owner receipt');
      const journal = readFileSync(join(receiptDir, created[0]), 'utf8')
        .trim().split(/\r?\n/u).map(JSON.parse);
      assert.equal(journal[0].stage, 'RUN_PENDING', scenario);
      if (scenario === 'late-create') {
        assert.match(journal.at(-1).stage, /^RECONCILIATION_REQUIRED:/u);
        assert.match(run.stderr, /reconcile.*\.jsonl/u);
      }
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
