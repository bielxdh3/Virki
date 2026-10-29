import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { Agent as HttpsAgent, get as directHttpsGet } from 'node:https';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertPinnedOfflineDockerfileText, requirePrivateWindowsStagingParent } from './offline-manual-image-build.mjs';

// Owner-scoped offline cache preparation for an opt-in DEV image build.
// Does not authorize production transfer, installation, deployment or release.
const FULL_SHA512 = /^sha512-([A-Za-z0-9+/]{86}==)$/u;
const OFFICIAL_REGISTRY = 'registry.npmjs.org';
const EXPECTED_LOCK_TARBALLS = 339;
const MAX_TARBALL_BYTES = 256 * 1024 * 1024;
// Never route pinned registry bytes through ambient NODE_USE_ENV_PROXY proxies.
// A dedicated agent with an empty proxy environment is required even on Node24.
const OFFICIAL_DIRECT_AGENT = new HttpsAgent({ proxyEnv: {} });
const WORKSPACES = Object.freeze({
  '': 'virki',
  'apps/hub': '@virki/hub',
  'apps/issuer': '@virki/issuer',
  'apps/public-site': '@virki/public-site',
  'packages/auth': '@virki/auth',
  'packages/database': '@virki/database',
  'packages/oidc-node': '@virki/oidc-node',
});
const WORKSPACE_LINKS = Object.freeze(Object.fromEntries(
  Object.entries(WORKSPACES).filter(([key]) => key !== '')
    .map(([key, name]) => [`node_modules/${name}`, key]),
));

function requireIt(condition, message) {
  if (!condition) throw Error('Offline npm cache blocked: ' + message);
}

/** Every tarball (including incompatible-platform optional packages) is required. */
export function officialTarballPlan(lock) {
  requireIt(lock && lock.lockfileVersion === 3 && lock.packages &&
    typeof lock.packages === 'object' && !Array.isArray(lock.packages), 'unexpected npm lockfile shape');
  const urls = new Map();
  const local = new Set();
  const links = new Set();
  for (const [packageName, packageRecord] of Object.entries(lock.packages)) {
    requireIt(packageRecord && typeof packageRecord === 'object' && !Array.isArray(packageRecord),
      'malformed package record');
    const url = packageRecord.resolved;
    if (packageRecord.link === true) {
      requireIt(Object.hasOwn(WORKSPACE_LINKS, packageName) &&
        url === WORKSPACE_LINKS[packageName] && packageRecord.integrity === undefined,
      'unexpected workspace link mapping');
      links.add(packageName);
      continue;
    }
    if (url === undefined) {
      requireIt(Object.hasOwn(WORKSPACES, packageName) &&
        packageRecord.name === WORKSPACES[packageName] &&
        packageRecord.version === '0.1.0' && packageRecord.integrity === undefined,
      'unknown unresolved or malformed local workspace record');
      local.add(packageName);
      continue;
    }
    requireIt(typeof url === 'string' && url.length < 2048 &&
      /^https:\/\/registry\.npmjs\.org\/[A-Za-z0-9@%._/+~-]+\.tgz$/u.test(url),
    'noncanonical or nonofficial registry tarball');
    const parsed = new URL(url);
    requireIt(parsed.protocol === 'https:' && parsed.hostname === OFFICIAL_REGISTRY &&
      parsed.host === OFFICIAL_REGISTRY && !parsed.username && !parsed.password &&
      !parsed.search && !parsed.hash && parsed.href === url &&
      parsed.pathname.includes('/-/') && !parsed.pathname.includes('//') &&
      !/%2f|%5c|%2e|%00/iu.test(parsed.pathname),
    'registry URL must be strict official HTTPS tarball');
    const m = FULL_SHA512.exec(packageRecord.integrity ?? '');
    requireIt(m, 'missing canonical SHA512 Subresource Integrity');
    const digest = Buffer.from(m[1], 'base64');
    requireIt(digest.length === 64 && digest.toString('base64') === m[1], 'invalid SHA512 base64');
    const entry = Object.freeze({ url, integrity: packageRecord.integrity,
      hex: digest.toString('hex'), packageName, optional: packageRecord.optional === true });
    const existing = urls.get(url);
    requireIt(!existing || existing.integrity === entry.integrity, 'conflicting tarball integrity for one URL');
    urls.set(url, entry);
  }
  requireIt(local.size === Object.keys(WORKSPACES).length &&
    links.size === Object.keys(WORKSPACE_LINKS).length,
  'incomplete exact local workspace and link closure');
  requireIt(urls.size > 0, 'no official tarballs to cache');
  return Object.freeze([...urls.values()].sort((a, b) => a.url.localeCompare(b.url)));
}

// HTTPS Node core client has no redirect-following behavior. A 3xx response
// must be rejected immediately, before any other host could be contacted.
export async function fetchAndCacheOfficialTarball(entry, {
  cacheDirectory, request = directHttpsGet, cacache = loadPinnedNpmCacache(),
} = {}) {
  requireIt(entry && typeof entry.url === 'string' && typeof entry.integrity === 'string' &&
    /^[a-f0-9]{128}$/u.test(entry.hex ?? '') &&
    createHash('sha512').update(Buffer.alloc(0)).digest('hex').length === 128,
  'invalid tarball cache entry');
  const url = new URL(entry.url);
  requireIt(url.protocol === 'https:' && url.hostname === OFFICIAL_REGISTRY &&
    url.host === OFFICIAL_REGISTRY && url.username === '' && url.password === '' &&
    url.hash === '' && url.search === '' &&
    entry.integrity === `sha512-${Buffer.from(entry.hex, 'hex').toString('base64')}`,
  'invalid official URL or SHA512 integrity');
  const response = await new Promise((resolve, reject) => {
    const req = request(url, { protocol: 'https:', hostname: OFFICIAL_REGISTRY,
      port: 443, servername: OFFICIAL_REGISTRY, rejectUnauthorized: true,
      agent: OFFICIAL_DIRECT_AGENT,
      timeout: 60000, headers: { Accept: 'application/octet-stream' } }, resolve);
    req.on('error', reject);
    req.setTimeout?.(60000, () => req.destroy(Error('npm registry HTTPS timeout')));
  });
  // Do not inspect Location or follow HTTP 3xx, even redirects back to npm.
  if (response.statusCode !== 200) {
    response.destroy();
    throw Error(`Offline npm cache blocked: unexpected registry HTTP ${response.statusCode}`);
  }
  const header = response.headers?.['content-length'];
  const expectedLength = header === undefined ? null : Number(header);
  requireIt(expectedLength === null || (Number.isSafeInteger(expectedLength) &&
    expectedLength > 0 && expectedLength <= MAX_TARBALL_BYTES), 'invalid Content-Length');
  const chunks = [];
  const hasher = createHash('sha512');
  let length = 0;
  for await (const chunk of response) {
    length += chunk.length;
    requireIt(length <= MAX_TARBALL_BYTES && (expectedLength === null || length <= expectedLength),
      'tarball exceeds approved length');
    chunks.push(chunk);
    hasher.update(chunk);
  }
  requireIt(response.complete === true && length > 0 &&
    (expectedLength === null || length === expectedLength), 'partial registry response');
  requireIt(hasher.digest('hex') === entry.hex, 'HTTP tarball SHA512 integrity mismatch');
  const cacheRoot = path.join(cacheDirectory, '_cacache');
  const result = await cacache.put(cacheRoot, entry.url, Buffer.concat(chunks, length),
    { integrity: entry.integrity });
  requireIt(String(result) === entry.integrity, 'npm cacache put integrity mismatch');
  return Object.freeze({ url: entry.url, bytes: length });
}

// Resolve exclusively from the trusted Node/npm installation, never an npm
// module from the repository, package tarball, WSL or the current directory.
export function loadPinnedNpmCacache() {
  requireIt(process.platform === 'win32' && process.arch === 'x64',
    'trusted npm cacache requires Windows x64 operator');
  const npmRoot = path.join(path.dirname(process.execPath), 'node_modules', 'npm');
  const loader = createRequire(import.meta.url);
  const pkg = loader(path.join(npmRoot, 'node_modules', 'cacache', 'package.json'));
  requireIt(pkg.version === '20.0.3', 'trusted npm cacache version mismatch');
  return loader(path.join(npmRoot, 'node_modules', 'cacache'));
}

export async function verifyNpmCacacheIndex(cacheDirectory, entries, cacache = loadPinnedNpmCacache()) {
  const root = path.join(cacheDirectory, '_cacache');
  const content = verifyNpmCacacheContent(cacheDirectory, entries);
  for (const item of entries) {
    const info = await cacache.get.info(root, item.url);
    requireIt(info && info.key === item.url && String(info.integrity) === item.integrity &&
      info.size > 0 && info.size <= MAX_TARBALL_BYTES,
    'missing or mismatched npm cache index entry');
  }
  return content;
}

/** Verify npm's content-addressed store against the *lockfile*, not npm's index alone. */
export function verifyNpmCacacheContent(cacheDirectory, entries) {
  requireIt(Array.isArray(entries) && entries.length > 0, 'empty cache inventory');
  let sizeBytes = 0;
  for (const { url, hex } of entries) {
    requireIt(typeof url === 'string' && /^[a-f0-9]{128}$/u.test(hex ?? ''), 'invalid cache entry');
    const file = path.join(cacheDirectory, '_cacache', 'content-v2', 'sha512',
      hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
    requireIt(existsSync(file), 'missing lockfile tarball in npm cache');
    const before = lstatSync(file, { bigint: true });
    requireIt(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
      before.size > 0n && before.size < 256n * 1024n * 1024n, 'unsafe cached tarball file');
    const bytes = readFileSync(file);
    const actual = createHash('sha512').update(bytes).digest('hex');
    const after = lstatSync(file, { bigint: true });
    requireIt(actual === hex &&
      ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every((key) => before[key] === after[key]),
    'cached tarball integrity mismatch or concurrent mutation');
    sizeBytes += bytes.length;
  }
  return Object.freeze({ verified: entries.length, totalBytes: sizeBytes });
}

/**
 * Private ephemeral Dockerfile: canonical Git Dockerfile is left untouched and
 * independently pinned; only the two reviewed RUN npm ci lines may change.
 * BuildKit must receive `_cacache` as `offline-npm-cacache` named context.
 * Cache is copied into an ephemeral directory, removed in the same build layer.
 */
export function derivePinnedOfflineDockerfile(contents) {
  assertPinnedOfflineDockerfileText(contents);
  const replacements = [
    ['RUN npm ci\n', 'npm ci --offline'],
    ['RUN npm ci --omit=dev --omit=peer --omit=optional --ignore-scripts --no-audit\n',
      'npm ci --offline --omit=dev --omit=peer --omit=optional --ignore-scripts --no-audit'],
  ];
  let result = contents;
  for (const [oldLine, npmCommand] of replacements) {
    requireIt(result.split(oldLine).length === 2, 'canonical Dockerfile npm command count changed');
    const newLine = `RUN --mount=type=bind,from=offline-npm-cacache,target=/prefetched-npm-cacache,readonly set -eu; mkdir -p /tmp/virki-npm-cache/_cacache; cp -a /prefetched-npm-cacache/. /tmp/virki-npm-cache/_cacache/; ${npmCommand} --cache=/tmp/virki-npm-cache; rm -rf /tmp/virki-npm-cache\n`;
    result = result.replace(oldLine, newLine);
  }
  return result;
}

/** Online preparation is always a separate opt-in; build can stay network=none. */
export async function warmOfficialNpmCache({ repositoryRoot, ownerPrivateParent } = {}) {
  requireIt(process.platform === 'win32' && process.arch === 'x64', 'reviewed preparation host must be Windows x64');
  requireIt(process.env.VIRKI_OFFLINE_NPM_CACHE_WARM === '1', 'explicit cache prewarm opt-in missing');
  requireIt(typeof repositoryRoot === 'string' && path.isAbsolute(repositoryRoot) &&
    typeof ownerPrivateParent === 'string' && path.isAbsolute(ownerPrivateParent), 'absolute paths required');
  const parent = path.resolve(ownerPrivateParent);
  const repo = path.resolve(repositoryRoot);
  requireIt(parent === ownerPrivateParent && repo === repositoryRoot &&
    parent !== repo && !parent.startsWith(repo + path.sep) &&
    !repo.startsWith(parent + path.sep), 'staging and source directories overlap');
  requireIt(realpathSync.native(parent) === parent && realpathSync.native(repo) === repo,
    'noncanonical parent or repository path');
  requirePrivateWindowsStagingParent(parent);
  const git = (args) => spawnSync('git', args, { cwd: repo, encoding: null,
    windowsHide: true, shell: false, timeout: 30000, maxBuffer: 8 * 1024 * 1024 });
  const head = git(['rev-parse', '--verify', 'HEAD']);
  requireIt(head.status === 0 && /^[a-f0-9]{40}$/u.test(head.stdout?.toString('utf8').trim() ?? ''),
    'repository must point to one exact Git commit');
  const sourceSha = head.stdout.toString('utf8').trim();
  const status = git(['status', '--porcelain', '--untracked-files=normal']);
  requireIt(status.status === 0 && status.stdout.length === 0, 'repository has uncommitted files');
  // Git blob is canonical; a Windows checkout may have autocrlf transformations.
  const committedLock = git(['show', `${sourceSha}:package-lock.json`]);
  requireIt(committedLock.status === 0 && committedLock.stdout?.length > 0,
    'exact Git commit has no readable package-lock');
  const rawLock = committedLock.stdout;
  const plan = officialTarballPlan(JSON.parse(rawLock.toString('utf8')));
  requireIt(plan.length === EXPECTED_LOCK_TARBALLS, 'unexpected package-lock registry tarball count');
  const directory = mkdtempSync(path.join(parent, 'npm-offline-'));
  // A new, empty configuration stops a user-level .npmrc / credential leak.
  const cache = path.join(directory, 'cache');
  mkdirSync(cache);
  const cacache = loadPinnedNpmCacache();
  for (const item of plan) {
    await fetchAndCacheOfficialTarball(item, { cacheDirectory: cache, cacache });
    verifyNpmCacacheContent(cache, [item]);
    await verifyNpmCacacheIndex(cache, [item], cacache);
  }
  const verified = await verifyNpmCacacheIndex(cache, plan, cacache);
  const sha256 = createHash('sha256').update(rawLock).digest('hex');
  const receipt = Object.freeze({ status: 'DEV_CACHE_VERIFIED_ONLY', sourceSha,
    packageLockSha256: sha256,
    packages: verified.verified, totalBytes: verified.totalBytes,
    cacheDirectory: path.join(cache, '_cacache'),
    buildNetwork: 'none', ghcr: 'NOT_USED', ownerSignatureVerified: false, deployAuthorized: false });
  writeFileSync(path.join(directory, 'npm-offline-cache-receipt.json'), JSON.stringify(receipt) + '\n',
    { flag: 'wx', mode: 0o600 });
  return receipt;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireIt(process.argv.length === 6 && process.argv[2] === '--repository' &&
      process.argv[4] === '--staging-parent', 'usage: --repository <absolute> --staging-parent <owner-private>');
    process.stdout.write(JSON.stringify(await warmOfficialNpmCache({ repositoryRoot: process.argv[3],
      ownerPrivateParent: process.argv[5] })) + '\n');
  } catch (error) {
    process.stderr.write(`Offline npm cache NOT_READY: ${error.message}\n`);
    process.exitCode = 1;
  }
}
