import { createHash } from 'node:crypto';

// DEV-ONLY executable model for an eventual owner-installed broker that sends
// verified bytes through an already controlled handle/pipe. The receiver
// hashes ACTUAL CONTENT, not a reported JSON hash. No Windows SID separation,
// authenticated daemon, OS-sealed memfd, Docker context protocol, owner trust
// or production use exists here. Never lift the current Docker build hold on
// the strength of this module or its passing tests.
const PREFIX = Buffer.from('VIRKI_DEV_FOUR_CONTEXT_BYTES_V1\n');
const KINDS = Object.freeze(['source', 'dockerfile', 'npm', 'prisma']);
const MAX_BYTES = 64 * 1024; // intentionally not a real 339-tarball npm cache
const HEX40 = /^[a-f0-9]{40}$/u;
const HEX64 = /^[a-f0-9]{64}$/u;
const HEX32 = /^[a-f0-9]{32}$/u;
const deny = (msg) => { throw Error('Unsigned DEV four-context byte snapshot denied: ' + msg); };
const need = (ok, why) => { if (!ok) deny(why); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}
function validatePins(expected) {
  need(exact(expected, ['revision', 'role', 'nonce', 'inputs']) &&
    HEX40.test(expected.revision) &&
    ['runtime', 'migrator'].includes(expected.role) &&
    HEX32.test(expected.nonce) && exact(expected.inputs, KINDS),
  'invalid receiver-owned development byte pins');
  for (const kind of KINDS) {
    const entry = expected.inputs[kind];
    need(exact(entry, ['sha256', 'bytes']) && HEX64.test(entry.sha256) &&
      Number.isSafeInteger(entry.bytes) && entry.bytes > 0 &&
      entry.bytes <= MAX_BYTES,
    'invalid ' + kind + ' byte pin');
  }
}

/** Encode bounded copied bytes. No paths, Docker socket or privilege input. */
export function encodeUnsignedDevFourContextFrame(inputs, expected) {
  validatePins(expected);
  need(exact(inputs, KINDS), 'missing four payload buffers');
  const pieces = [];
  for (const kind of KINDS) {
    const bytes = inputs[kind];
    need(Buffer.isBuffer(bytes) && bytes.length === expected.inputs[kind].bytes &&
      sha256(bytes) === expected.inputs[kind].sha256,
    'source-to-frame digest mismatch for ' + kind);
    pieces.push(Buffer.from(bytes));
  }
  const header = {
    status: 'DEV_ONLY_UNSIGNED_BYTES_NOT_AUTHORIZED',
    revision: expected.revision, role: expected.role, nonce: expected.nonce,
    inputs: expected.inputs,
    ownerSignatureVerified: false, daemonIdentityVerified: false,
    dockerBuildAuthorized: false, deployAuthorized: false,
  };
  const serialized = Buffer.from(JSON.stringify(header), 'utf8');
  need(serialized.length <= 2048, 'oversized byte header');
  const size = Buffer.alloc(4);
  size.writeUInt32BE(serialized.length);
  return Buffer.concat([PREFIX, size, serialized, ...pieces]);
}

/** Verify actual incoming bytes against separately supplied pins, not readout. */
export function consumeUnsignedDevFourContextFrame(frame, expected) {
  validatePins(expected);
  need(Buffer.isBuffer(frame) && frame.length >= PREFIX.length + 4 &&
    frame.subarray(0, PREFIX.length).equals(PREFIX), 'invalid byte frame prefix');
  const headerSize = frame.readUInt32BE(PREFIX.length);
  const start = PREFIX.length + 4;
  need(headerSize > 0 && headerSize <= 2048 && headerSize <= frame.length - start,
    'invalid byte header bounds');
  let header;
  try { header = JSON.parse(frame.subarray(start, start + headerSize).toString('utf8')); }
  catch { deny('malformed byte header'); }
  need(exact(header, [
    'status', 'revision', 'role', 'nonce', 'inputs', 'ownerSignatureVerified',
    'daemonIdentityVerified', 'dockerBuildAuthorized', 'deployAuthorized',
  ]) && header.status === 'DEV_ONLY_UNSIGNED_BYTES_NOT_AUTHORIZED' &&
    header.revision === expected.revision && header.role === expected.role &&
    header.nonce === expected.nonce && header.ownerSignatureVerified === false &&
    header.daemonIdentityVerified === false && header.dockerBuildAuthorized === false &&
    header.deployAuthorized === false && exact(header.inputs, KINDS),
  'wrong unsigned frame identity or false authorization');
  const result = {};
  let offset = start + headerSize;
  for (const kind of KINDS) {
    const pinned = expected.inputs[kind];
    const declared = header.inputs[kind];
    need(exact(declared, ['sha256', 'bytes']) &&
      declared.sha256 === pinned.sha256 && declared.bytes === pinned.bytes,
    'untrusted frame digest header does not match receiver pins');
    need(pinned.bytes <= frame.length - offset, 'incomplete byte payload');
    const actual = Buffer.from(frame.subarray(offset, offset + pinned.bytes));
    offset += pinned.bytes;
    need(sha256(actual) === pinned.sha256, 'byte snapshot digest mismatch for ' + kind);
    result[kind] = actual;
  }
  need(offset === frame.length, 'trailing unsigned frame bytes');
  return Object.freeze({
    status: 'DEV_ONLY_UNSIGNED_BYTE_SNAPSHOT_NO_AUTHORITY',
    bytes: Object.freeze(result),
    ownerSignatureVerified: false, daemonIdentityVerified: false,
    dockerBuildAuthorized: false, deployAuthorized: false,
  });
}

/**
 * Bounded DEV-only stream adapter: receive byte payloads, not pathnames or
 * self-reported readout JSON. The limit applies to accepted aggregate chunks;
 * the Node stream implementation itself is not a hardened native receiver.
 * An independent installed owner/daemon identity is STILL ABSENT.
 */
export async function consumeUnsignedDevFourContextStream(stream, expected) {
  validatePins(expected);
  need(stream && typeof stream[Symbol.asyncIterator] === 'function',
    'missing async byte stream');
  const max = PREFIX.length + 4 + 2048 +
    KINDS.reduce((sum, kind) => sum + expected.inputs[kind].bytes, 0);
  let size = 0;
  const parts = [];
  for await (const chunk of stream) {
    need(Buffer.isBuffer(chunk) || chunk instanceof Uint8Array,
      'nonbinary stdin byte chunk');
    need(chunk.length <= max - size, 'oversized stdin byte frame');
    parts.push(Buffer.from(chunk));
    size += chunk.length;
  }
  return consumeUnsignedDevFourContextFrame(Buffer.concat(parts, size), expected);
}
