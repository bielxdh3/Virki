import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createAdmittedOidcDockerClient } from './lib/disposable-docker-session.mjs';

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
      'disposable-docker-mutation-policy.mjs', 'production-boundary-assertion.mjs'
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
    const patched = original.replace('import { spawnSync } from "node:child_process";',
      'import { spawnSync } from "./mock-child.mjs";');
    assert.notEqual(patched, original, 'fixture must replace child launcher to prevent DB access');
    writeFileSync(runner, patched);
    writeFileSync(join(root, 'package.json'), '{"type":"module"}\n');
    writeFileSync(mockChild, `
      export function spawnSync() { return { status: 0 }; }
    `);
    // This private stub cannot launch Docker or connect to any daemon.
    writeFileSync(mockDocker, `
      import { appendFileSync } from 'node:fs';
      export function createAdmittedOidcDockerClient() {
        let owner = null;
        const record = (args) => appendFileSync(process.env.VIRKI_FAKE_DOCKER_LOG, JSON.stringify(args) + '\\n');
        return {
          subprocessEnv: { DOCKER_HOST: 'npipe:////./pipe/dockerDesktopLinuxEngine',
            VIRKI_OIDC_DOCKER_BINARY: 'nonexistent-test-only' },
          invoke(args) {
            record(args);
            const ok = (stdout = 'ok') => ({ status: 0, stdout });
            if (args[0] === 'run') {
              owner = args[args.indexOf('--label') + 1].split('=').at(-1);
              return ok('fake-container');
            }
            if (args[0] === 'port') return ok('127.0.0.1:5432');
            if (args[0] === 'exec' && args.includes('SHOW server_version')) return ok('18.6');
            if (args[0] === 'inspect') {
              const scenario = process.env.VIRKI_FAKE_CLEANUP_SCENARIO;
              if (scenario === 'absent') return {
                status: 1, stderr: 'Error: No such object: ' + args.at(-1) + '\\n'
              };
              if (scenario === 'denied') return {
                status: 1, stderr: 'permission denied by daemon\\n'
              };
              if (scenario === 'timeout') return {
                status: null, error: { code: 'ETIMEDOUT' }, stderr: ''
              };
              if (scenario === 'wrong-owner') return ok('foreign-owner');
              return ok(owner);
            }
            if (args[0] === 'rm' && process.env.VIRKI_FAKE_CLEANUP_SCENARIO === 'rm-denied') {
              return { status: 1, stderr: 'permission denied' };
            }
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
      ['owned', 0, true]
    ]) {
      const log = join(root, 'scenario-' + scenario + '.jsonl');
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
      assert.equal(calls.some((args) => args[0] === 'run'), true, scenario + ': must simulate start');
      assert.equal(calls.some((args) => args[0] === 'inspect'), true, scenario + ': must inspect');
      assert.equal(calls.some((args) => args[0] === 'rm'), expectedRemoval,
        scenario + ': never delete an unverified object');
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
