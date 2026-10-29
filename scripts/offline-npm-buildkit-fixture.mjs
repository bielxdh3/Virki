import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Explicitly disposable BuildKit proof: local HTTP mock only for prewarm,
// then --network=none for the actual Linux image build. No production image.
const ENABLED = process.env.VIRKI_NPM_BUILDKIT_DEV_FIXTURE === '1';
const BASE_DIGEST = '69a5713e7f4997e96d579aafd78734810e0dac0dd5ee4621d72c27a2891a4088';
const NODE_BASE = `node@sha256:${BASE_DIGEST}`; // Immutable cached fixture, not a release base.
const BASE_IMAGE_ID = 'sha256:376ec2cd9cc228f1204012b2aea04b648234ab52f70997914c631876c7ebb388';

function execute(binary, args, { cwd, env = process.env, timeout = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { cwd, env, windowsHide: true, shell: false });
    let output = '';
    let timer;
    child.stdout.on('data', chunk => { output += chunk.toString(); output = output.slice(-8192); });
    child.stderr.on('data', chunk => { output += chunk.toString(); output = output.slice(-8192); });
    child.on('error', reject);
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0) resolve(output);
      else reject(Error(`command failed (${code}): ${output}`));
    });
    timer = setTimeout(() => child.kill(), timeout);
  });
}

async function run() {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    throw Error('disposable Windows Docker Desktop fixture requires Windows x64; WSL is unsupported');
  }
  if (!ENABLED) throw Error('VIRKI_NPM_BUILDKIT_DEV_FIXTURE=1 must explicitly opt in');
  // Before creating a temporary fixture, prove its exact source image is
  // already stored by immutable Docker Hub RepoDigest with required platform.
  const inspected = JSON.parse(await execute('docker', [
    'image', 'inspect', NODE_BASE, '--format', '{{json .}}',
  ]));
  if (inspected.Id !== BASE_IMAGE_ID || inspected.Os !== 'linux' ||
    inspected.Architecture !== 'amd64' ||
    !Array.isArray(inspected.RepoDigests) || !inspected.RepoDigests.includes(NODE_BASE)) {
    throw Error('exact cached Docker Hub fixture image/platform missing or altered');
  }
  const staging = mkdtempSync(path.join(os.tmpdir(), 'virki-buildkit-cache-fixture-'));
  const packageParent = path.join(staging, 'package-src');
  const packageDirectory = path.join(packageParent, 'package');
  const buildContext = path.join(staging, 'build-context');
  const cache = path.join(staging, 'cache');
  const tag = `virki-offline-fixture-${randomBytes(8).toString('hex')}:dev`;
  mkdirSync(packageDirectory, { recursive: true });
  mkdirSync(buildContext);
  mkdirSync(cache);
  writeFileSync(path.join(packageDirectory, 'package.json'), JSON.stringify({
    name: 'virki-offline-cache-test-pkg', version: '1.0.0', main: 'index.js',
  }));
  writeFileSync(path.join(packageDirectory, 'index.js'), 'module.exports = 339;\n');
  const tarball = path.join(staging, 'fixture.tgz');
  await execute('tar', ['-czf', tarball, '-C', packageParent, 'package']);
  const tarContents = readFileSync(tarball);
  const integrity = 'sha512-' + createHash('sha512').update(tarContents).digest('base64');
  let requests = 0;
  const mock = createServer((req, res) => {
    ++requests;
    if (req.url !== '/virki-offline-cache-test-pkg-1.0.0.tgz') {
      res.writeHead(404).end(); return;
    }
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': tarContents.length });
    res.end(tarContents);
  });
  await new Promise(resolve => mock.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${mock.address().port}/virki-offline-cache-test-pkg-1.0.0.tgz`;
  const npmCli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  const config = path.join(staging, 'empty-npmrc');
  writeFileSync(config, '', { flag: 'wx' });
  const globalConfig = path.join(staging, 'empty-global-npmrc');
  writeFileSync(globalConfig, '', { flag: 'wx' });
  try {
    const lock = { name: 'virki-npm-cache-fixture', version: '1.0.0', lockfileVersion: 3,
      requires: true, packages: {
        '': { name: 'virki-npm-cache-fixture', version: '1.0.0', dependencies: {
          'virki-offline-cache-test-pkg': '1.0.0',
        } },
        'node_modules/virki-offline-cache-test-pkg': { version: '1.0.0', resolved: url, integrity },
      },
    };
    writeFileSync(path.join(buildContext, 'package.json'), JSON.stringify({
      name: 'virki-npm-cache-fixture', version: '1.0.0', private: true,
      dependencies: { 'virki-offline-cache-test-pkg': '1.0.0' },
    }));
    writeFileSync(path.join(buildContext, 'package-lock.json'), JSON.stringify(lock));
    await execute(process.execPath, [npmCli, 'cache', 'add', url,
      '--cache', cache, '--userconfig', config, '--globalconfig', globalConfig, '--no-audit', '--ignore-scripts'],
    { cwd: staging });
    if (requests < 1) throw Error('local prewarm did not fetch the tarball');
    mock.close();
    const countAtNetworkShutdown = requests;
    writeFileSync(path.join(buildContext, 'Dockerfile'), `FROM ${NODE_BASE}\n` +
      'WORKDIR /app\nCOPY package*.json ./\n' +
      'RUN --mount=type=bind,from=offline-npm-cacache,target=/prefetched-npm-cacache,readonly set -eu; mkdir -p /tmp/virki-npm-cache/_cacache; cp -a /prefetched-npm-cacache/. /tmp/virki-npm-cache/_cacache/; npm ci --offline --ignore-scripts --no-audit --cache=/tmp/virki-npm-cache; rm -rf /tmp/virki-npm-cache; node -e "if(require(\'virki-offline-cache-test-pkg\')!==339)process.exit(1)"\n');
    // A missing cache must actually fail with network disabled; prove this
    // before trying the populated BuildKit named context.
    const absent = path.join(staging, 'absent-cacache');
    mkdirSync(absent);
    let missingCacheFailed = false;
    try {
      await execute('docker', ['build', '--no-cache', '--pull=false', '--network=none',
        '--build-context', `offline-npm-cacache=${absent}`, '--tag', `${tag}-missing`, buildContext],
      { cwd: staging, timeout: 300000 });
    } catch (error) {
      if (!/ENOTCACHED|cache mode|npm error|cannot read|no such file|not found/iu.test(error.message)) throw error;
      missingCacheFailed = true;
    }
    if (!missingCacheFailed) throw Error('missing-cache adversarial Docker build did not fail');
    await execute('docker', ['build', '--no-cache', '--pull=false', '--network=none', '--progress=plain',
      '--build-context', `offline-npm-cacache=${path.join(cache, '_cacache')}`,
      '--tag', tag, buildContext], { cwd: staging, timeout: 300000 });
    if (requests !== countAtNetworkShutdown) throw Error('unplanned mock registry request during offline build');
    const id = (await execute('docker', ['image', 'inspect', tag, '--format', '{{.Id}}'])).trim();
    process.stdout.write(JSON.stringify({ status: 'DEV_BUILD_KIT_OFFLINE_FIXTURE_PASS',
      imageId: id, base: NODE_BASE, pinnedBaseImageId: BASE_IMAGE_ID,
      dockerBuildNoCache: true, network: 'none', mockRequestsBeforeBuild: requests,
      productionBaseUsed: false, missingCacheRejected: true, packageIntegrity: integrity }) + '\n');
    await execute('docker', ['image', 'rm', tag]); // Only this uniquely generated disposable tag.
  } finally {
    mock.close();
    rmSync(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(error => { process.stderr.write(`DEV offline BuildKit fixture FAIL: ${error.message}\n`); process.exitCode = 1; });
}
