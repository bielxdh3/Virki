import { createHash, randomBytes } from 'node:crypto';
import { Agent as HttpsAgent, request as directHttpsRequest } from 'node:https';
import { lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { requirePrivateWindowsStagingParent } from './offline-manual-image-build.mjs';
import { derivePinnedOfflineDockerfile } from './offline-npm-cache.mjs';

// Only these Prisma 6.19.3 engine-commit + linux/amd64-musl artifacts may be
// used by a DEV-only, disconnected Docker build. Both compressed and inflated
// hashes are independently pinned, not accepted from a downloaded checksum.
const ENGINE_COMMIT = 'c2990dca591cba766e3b7ef5d9e8a84796e47ab7';
const TARGET = 'linux-musl-openssl-3.0.x';
const BASE = `https://binaries.prisma.sh/all_commits/${ENGINE_COMMIT}/${TARGET}/`;
const MAX_GZIP = 30 * 1024 * 1024;
const MAX_ENGINE = 40 * 1024 * 1024;
// Do not inherit Node24 NODE_USE_ENV_PROXY / HTTPS_PROXY into official CDN egress.
const OFFICIAL_DIRECT_AGENT = new HttpsAgent({ proxyEnv: {} });
export const PINNED_PRISMA_ENGINES = Object.freeze([
  Object.freeze({ remote: 'libquery_engine.so.node.gz',
    filename: `libquery_engine-${TARGET}.so.node`,
    gzipSha256: '00b82195745fa317411a0a7793769b3a53e631a30d82e27772ca13622b0b7a8e',
    binarySha256: '28abc36457335e1a45fe2fe79a4c781b55347e696d6f4410c83bf232d92a726c',
    length: 17556136 }),
  Object.freeze({ remote: 'schema-engine.gz', filename: `schema-engine-${TARGET}`,
    gzipSha256: 'cf5f99b0e589976a814655f4ed9c2f11f8e124a3ac2dabb8be8142c7784695d4',
    binarySha256: '955e3bff1be23248a0922a219f7c4e200acc8fdd1fc72479557c0a9d782bd64a',
    length: 19644784 }),
]);
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const need = (ok, why) => { if (!ok) throw Error('Offline Prisma engines NOT_READY: ' + why); };

export function assertPinnedPrismaEngineBytes(filename, bytes) {
  const expected = PINNED_PRISMA_ENGINES.find((item) => item.filename === filename);
  need(expected && Buffer.isBuffer(bytes) && bytes.length === expected.length &&
    bytes.length <= MAX_ENGINE && digest(bytes) === expected.binarySha256 &&
    bytes.readUInt32BE(0) === 0x7f454c46 && bytes[4] === 2 &&
    bytes.readUInt16LE(18) === 62, 'ELF byte identity, size or Linux x86_64 target mismatch');
  return Object.freeze({ filename, sha256: expected.binarySha256, bytes: expected.length });
}

export function verifyOfflinePrismaEngineDirectory(dirname) {
  need(process.platform === 'win32' && path.isAbsolute(dirname) &&
    path.normalize(dirname) === dirname && realpathSync.native(dirname) === dirname,
  'engine sidecar must be an absolute canonical Windows directory');
  const st = lstatSync(dirname);
  need(st.isDirectory() && !st.isSymbolicLink(), 'engine directory is a symlink or alias');
  need(JSON.stringify(readdirSync(dirname).sort()) === JSON.stringify(
    PINNED_PRISMA_ENGINES.map((item) => item.filename).sort()),
  'engine sidecar must contain exactly two reviewed files');
  for (const item of PINNED_PRISMA_ENGINES) {
    const file = path.join(dirname, item.filename);
    const before = lstatSync(file, { bigint: true });
    need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
      before.size === BigInt(item.length), 'unsafe engine inode');
    assertPinnedPrismaEngineBytes(item.filename, readFileSync(file));
    const after = lstatSync(file, { bigint: true });
    need(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every((key) =>
      before[key] === after[key]), 'engine changed during at-use SHA verification');
  }
  return Object.freeze({ status: 'PRISMA_6_ENGINE_BYTES_VERIFIED_DEV_ONLY',
    engineCommit: ENGINE_COMMIT, target: TARGET, count: 2,
    ownerSignatureVerified: false, deployAuthorized: false });
}

export function derivePinnedOfflineDockerfileWithPrismaEngines(canonicalText) {
  const npmDerived = derivePinnedOfflineDockerfile(canonicalText);
  const first = 'FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build';
  need(npmDerived.startsWith(first + '\n') && npmDerived.split(first).length === 2,
  'canonical build stage identity changed');
  const [query, schema] = PINNED_PRISMA_ENGINES;
  const insertion = [
    `COPY --from=offline-prisma-engines /${query.filename} /opt/virki-prisma/${query.filename}`,
    `COPY --from=offline-prisma-engines /${schema.filename} /opt/virki-prisma/${schema.filename}`,
    `RUN chmod 0555 /opt/virki-prisma/${schema.filename}`,
    `ENV PRISMA_QUERY_ENGINE_LIBRARY=/opt/virki-prisma/${query.filename}`,
    `ENV PRISMA_SCHEMA_ENGINE_BINARY=/opt/virki-prisma/${schema.filename}`,
  ].join('\n');
  return npmDerived.replace(first + '\n', first + '\n' + insertion + '\n');
}

export async function downloadExactOfficialPrismaAsset(asset, { request = directHttpsRequest } = {}) {
  need(PINNED_PRISMA_ENGINES.includes(asset), 'unreviewed engine asset');
  const url = new URL(asset.remote, BASE);
  need(url.href === BASE + asset.remote && url.protocol === 'https:' &&
    url.hostname === 'binaries.prisma.sh' && url.host === 'binaries.prisma.sh' &&
    !url.username && !url.password && !url.search && !url.hash,
  'unreviewed Prisma CDN origin');
  const response = await new Promise((resolve, reject) => {
    const req = request(url, { protocol: 'https:', hostname: 'binaries.prisma.sh',
      port: 443, rejectUnauthorized: true, servername: 'binaries.prisma.sh',
      agent: OFFICIAL_DIRECT_AGENT,
      timeout: 60000 }, resolve);
    req.on('error', reject);
    req.setTimeout(60000, () => req.destroy(Error('Prisma CDN timeout')));
    req.end();
  });
  if (response.statusCode !== 200) {
    response.destroy();
    throw Error('Offline Prisma engines NOT_READY: direct Prisma CDN HTTP non-200 (no redirects)');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of response) {
    size += chunk.length;
    need(size > 0 && size <= MAX_GZIP, 'compressed Prisma engine exceeds limit');
    chunks.push(chunk);
  }
  need(response.complete === true, 'Prisma CDN response incomplete');
  const gz = Buffer.concat(chunks, size);
  need(digest(gz) === asset.gzipSha256, 'Prisma CDN engine compressed digest changed');
  const unpacked = gunzipSync(gz, { maxOutputLength: MAX_ENGINE });
  assertPinnedPrismaEngineBytes(asset.filename, unpacked);
  return unpacked;
}

export async function warmPinnedOfflinePrismaEngines({ stagingParent } = {}) {
  need(process.platform === 'win32' && process.arch === 'x64' &&
    process.env.VIRKI_OFFLINE_PRISMA_ENGINES_WARM === '1',
  'explicit Windows local engine prewarm opt-in missing');
  need(typeof stagingParent === 'string' && path.isAbsolute(stagingParent) &&
    path.normalize(stagingParent) === stagingParent &&
    realpathSync.native(stagingParent) === stagingParent,
  'noncanonical private staging parent');
  requirePrivateWindowsStagingParent(stagingParent);
  const dir = path.join(stagingParent, 'prisma-engines-' + randomBytes(12).toString('hex'));
  mkdirSync(dir, { mode: 0o700 });
  const engineDirectory = path.join(dir, 'context');
  mkdirSync(engineDirectory, { mode: 0o700 });
  for (const asset of PINNED_PRISMA_ENGINES) {
    const binary = await downloadExactOfficialPrismaAsset(asset);
    writeFileSync(path.join(engineDirectory, asset.filename), binary,
      { flag: 'wx', mode: 0o600 });
  }
  verifyOfflinePrismaEngineDirectory(engineDirectory);
  const receipt = Object.freeze({ status: 'PRISMA_6_ENGINE_BYTES_VERIFIED_DEV_ONLY',
    directory: engineDirectory, engineCommit: ENGINE_COMMIT, target: TARGET,
    artifacts: PINNED_PRISMA_ENGINES.map(({ filename, binarySha256 }) =>
      ({ filename, sha256: binarySha256 })),
    ownerSignatureVerified: false, deployAuthorized: false });
  writeFileSync(path.join(dir, 'prisma-engine-receipt.json'),
    JSON.stringify(receipt) + '\n', { flag: 'wx', mode: 0o600 });
  return receipt;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    need(process.argv.length === 4 && process.argv[2] === '--staging-parent',
      'usage: --staging-parent <owner-private>');
    process.stdout.write(JSON.stringify(await warmPinnedOfflinePrismaEngines({
      stagingParent: process.argv[3],
    })) + '\n');
  } catch {
    process.stderr.write('Offline Prisma engines NOT_READY; no release or deployment authorized.\n');
    process.exitCode = 1;
  }
}
