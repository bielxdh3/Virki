import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { rootCertificates } from "node:tls";
import { fileURLToPath } from "node:url";

const proof = fileURLToPath(new URL("./staging-prisma-ca-archive-proof.mjs", import.meta.url));
const proofSource = readFileSync(proof, "utf8");
const PEM = Buffer.from(rootCertificates[0].trimEnd().replace(/\r\n/gu, "\n") + "\n");
const SHA = createHash("sha256").update(PEM).digest("hex");
const PASS = "STAGING_PRISMA_CA_ARCHIVE=PASS\n";
const BLOCK = "BLOCK:STAGING_PRISMA_CA_ARCHIVE\n";
const RECORD_BYTES = 512;

function textField(header, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  assert.ok(bytes.length < length, "TAR fixture field too wide");
  bytes.copy(header, offset);
}

function octalField(header, offset, length, number) {
  const chars = number.toString(8).padStart(length - 1, "0") + "\0";
  assert.equal(Buffer.byteLength(chars), length);
  header.write(chars, offset, length, "ascii");
}

function checksum(header) {
  header.fill(32, 148, 156);
  let sum = 0;
  for (const byte of header) sum += byte;
  const encoded = sum.toString(8).padStart(6, "0") + "\0 ";
  assert.equal(encoded.length, 8);
  header.write(encoded, 148, 8, "ascii");
}

function tarHeader({
  name, size = 0, mode = 0o444, uid = 0, gid = 0, type = "0",
  linkname = "", uname = "root", gname = "root", prefix = "",
  magic = "ustar\0", version = "00", mtime = 0,
  mutateBeforeChecksum = () => {}
}) {
  const header = Buffer.alloc(RECORD_BYTES);
  textField(header, 0, 100, name);
  octalField(header, 100, 8, mode);
  octalField(header, 108, 8, uid);
  octalField(header, 116, 8, gid);
  octalField(header, 124, 12, size);
  octalField(header, 136, 12, mtime);
  header.write(type, 156, 1, "latin1");
  if (linkname) textField(header, 157, 100, linkname);
  header.write(magic, 257, 6, "latin1");
  header.write(version, 263, 2, "latin1");
  if (uname) textField(header, 265, 32, uname);
  if (gname) textField(header, 297, 32, gname);
  if (prefix) textField(header, 345, 155, prefix);
  mutateBeforeChecksum(header);
  checksum(header);
  return header;
}

function archiveEntry({
  name, content = Buffer.alloc(0), mode, type, uid, gid,
  linkname, uname, gname, prefix, magic, version, mtime,
  mutateBeforeChecksum
}) {
  const data = Buffer.from(content);
  const header = tarHeader({
    name, size: data.length, mode, type, uid, gid, linkname, uname,
    gname, prefix, magic, version, mtime, mutateBeforeChecksum
  });
  const padding = Buffer.alloc((RECORD_BYTES - data.length % RECORD_BYTES) % RECORD_BYTES);
  return Buffer.concat([header, data, padding]);
}

function directory(overrides = {}) {
  return {
    name: "ca/", mode: 0o755, type: "5",
    ...overrides
  };
}

function certificate(overrides = {}) {
  return {
    name: "ca/staging-db-root.pem", mode: 0o444, type: "0", content: PEM,
    ...overrides
  };
}

function tar(entries = [directory(), certificate()], { endBlocks = 2, extra = Buffer.alloc(0) } = {}) {
  return Buffer.concat([
    ...entries.map(archiveEntry),
    Buffer.alloc(endBlocks * RECORD_BYTES),
    extra
  ]);
}

function invoke(archive, args = [SHA]) {
  const result = spawnSync(process.execPath, [proof, ...args], {
    input: archive, maxBuffer: 32 * 1024, encoding: "utf8",
    timeout: 12000, windowsHide: true
  });
  // On Windows, spawnSync may report EOF while writing to a child that has
  // already correctly rejected a large or obviously invalid TAR header.
  // Accept that transport outcome ONLY when the child demonstrably emitted
  // the canonical BLOCK marker and exited unsuccessfully.
  if (result.error) {
    assert.equal(result.error.code, "EOF", "unexpected subprocess failure");
    assert.notEqual(result.status, 0, "early child termination is never success");
    assert.equal(result.stdout, BLOCK, "early termination must report the fail-closed token");
  }
  assert.equal(result.stderr, "", "no error messages or certificate content may go to stderr");
  assert.ok(result.stdout === PASS || result.stdout === BLOCK,
    "stdout is restricted to a single documented result marker");
  assert.equal(result.stdout.includes("CERTIFICATE"), false);
  assert.equal(result.stdout.includes(PEM.subarray(32, 48).toString("ascii")), false);
  return result;
}

function allows(archive, sha = SHA) {
  const result = invoke(archive, [sha]);
  assert.equal(result.status, 0, "accepted TAR must exit 0");
  assert.equal(result.stdout, PASS);
}

function blocks(archive, sha = SHA) {
  const result = invoke(archive, [sha]);
  assert.notEqual(result.status, 0, "invalid TAR must fail closed");
  assert.equal(result.stdout, BLOCK);
}

test("CLI uses only Node standard libraries, hard caps and two exact output tokens", () => {
  assert.match(proofSource, /for await \(const chunk of process\.stdin\)/u);
  assert.match(proofSource, /MAX_ARCHIVE_BYTES = 1024 \* 1024/u);
  assert.match(proofSource, /MAX_CA_BYTES = 128 \* 1024/u);
  const executableSource = proofSource.replace(/^\/\*[\s\S]*?\*\//u, "");
  assert.doesNotMatch(executableSource, /child_process|execSync|spawnSync|docker cp|import.*from ["'](?:tar|https|http)/u,
    "the proof must not launch Docker, execute image code or use the network");
  assert.ok(PEM.length > 0 && PEM.length < 128 * 1024);
  allows(tar());
  allows(tar(undefined, { endBlocks: 10 }), SHA);
});

test("CLI fail-closed argument validation never displays the approved CA", () => {
  for (const args of [
    [], ["F".repeat(64)], ["e".repeat(63)], ["e".repeat(65)],
    ["e".repeat(63) + "z"], [SHA, "surplus"], [""], ["--help"]
  ]) {
    const result = invoke(tar(), args);
    assert.equal(result.stdout, BLOCK);
    assert.notEqual(result.status, 0);
  }
  blocks(tar(), "f".repeat(64));
});

test("fail closed for owner/mode/type/links, alternate paths and extension headers", () => {
  const variations = [
    [directory({ uid: 1000 }), certificate()],
    [directory({ gid: 1 }), certificate()],
    [directory({ mode: 0o775 }), certificate()],
    [directory({ mode: 0o4755 }), certificate()],
    [directory({ uname: "someone" }), certificate()],
    [directory({ type: "2", linkname: "elsewhere" }), certificate()],
    [directory({ type: "1", linkname: "elsewhere" }), certificate()],
    [directory({ name: "./ca/" }), certificate()],
    [directory({ name: "ca" }), certificate()],
    [directory({ name: "/ca/" }), certificate()],
    [directory({ name: "../ca/" }), certificate()],
    [directory({ name: "ca/../ca/" }), certificate()],
    [directory({ prefix: "evil" }), certificate()],
    [directory({ magic: "ustar " }), certificate()],
    [directory({ version: "01" }), certificate()],
    [directory({ type: "x" }), certificate()],
    [directory({ type: "g" }), certificate()],
    [certificate(), directory()],
    [directory(), certificate({ uid: 1 })],
    [directory(), certificate({ gid: 1 })],
    [directory(), certificate({ mode: 0o644 })],
    [directory(), certificate({ mode: 0o1444 })],
    [directory(), certificate({ uname: "nobody" })],
    [directory(), certificate({ gname: "user" })],
    [directory(), certificate({ type: "2", linkname: "/app/secrets" })],
    [directory(), certificate({ type: "1", linkname: "ca/other" })],
    [directory(), certificate({ type: "x" })],
    [directory(), certificate({ type: "L" })],
    [directory(), certificate({ linkname: "secret" })],
    [directory(), certificate({ name: "ca/../staging-db-root.pem" })],
    [directory(), certificate({ name: "ca//staging-db-root.pem" })],
    [directory(), certificate({ name: "ca/staging-db-root.pem/" })],
    [directory(), certificate({ name: "/ca/staging-db-root.pem" })],
    [directory(), certificate({ prefix: "./" })],
    [directory(), certificate({ type: "7" })]
  ];
  for (const entries of variations) blocks(tar(entries));
});

test("rejects altered TAR checksums, malformed numeric fields, tampered file bytes and nonzero padding", () => {
  const good = tar();
  const headerTampered = Buffer.from(good);
  headerTampered[RECORD_BYTES + 3] ^= 1;
  blocks(headerTampered);

  const payloadTampered = Buffer.from(good);
  payloadTampered[RECORD_BYTES * 2 + 10] ^= 1;
  blocks(payloadTampered);

  for (const mutation of [
    header => { header[100] = 128; },
    header => { header[108] = 43; },
    header => { header[124] = 0xff; },
    header => { header[136] = 45; },
    header => { header[156] = 0x32; },
    header => { header[500] = 97; },
    header => { header[0] = 0; header[1] = 97; },
    header => { header[329] = 0x31; }
  ]) {
    blocks(tar([directory(), certificate({ mutateBeforeChecksum: mutation })]));
  }

  const badPadding = Buffer.from(good);
  const firstFilePad = RECORD_BYTES * 2 + PEM.length;
  assert.notEqual(PEM.length % RECORD_BYTES, 0, "fixture needs padding for tamper test");
  badPadding[firstFilePad] = 0x61;
  blocks(badPadding);
});

test("rejects missing/duplicate/unexpected entries and all malformed TAR EOF variants", () => {
  for (const archive of [
    Buffer.alloc(0),
    Buffer.alloc(2 * RECORD_BYTES),
    tar([directory()]),
    tar([certificate()]),
    tar([directory(), directory()]),
    tar([certificate(), certificate()]),
    tar([directory(), certificate(), directory()]),
    tar([directory(), certificate(), certificate()]),
    tar([directory(), certificate(), { name: "ca/private.txt", type: "0", mode: 0o444, content: PEM }]),
    tar(undefined, { endBlocks: 0 }),
    tar(undefined, { endBlocks: 1 }),
    tar(undefined, { extra: Buffer.from("TRAILER") }),
    tar(undefined, { extra: Buffer.alloc(1) }),
    tar(undefined, { extra: Buffer.from("malicious trailing text") }),
    tar(undefined, { endBlocks: 2, extra: archiveEntry(certificate()) }),
    tar().subarray(0, 123),
    tar().subarray(0, RECORD_BYTES + 211),
    tar().subarray(0, tar().length - 1)
  ]) blocks(archive);

  const nonzeroEof = tar();
  nonzeroEof[nonzeroEof.length - 1] = 1;
  blocks(nonzeroEof);
});

test("archive size and file length caps are enforced before acceptance", () => {
  blocks(tar([directory(), certificate({ content: Buffer.alloc(128 * 1024 + 1, 0x41) })]));
  blocks(tar([directory(), certificate({ content: Buffer.alloc(0) })]));
  blocks(tar(undefined, { extra: Buffer.alloc(1024 * 1024) }));
  const oversizedDirectory = tar([directory({ content: Buffer.from("not-empty") }), certificate()]);
  blocks(oversizedDirectory);
});

test("rejected TAR does not leak PEM or any archive content in stdout or stderr", () => {
  const sensitiveMarker = "CERTIFICATE_CONTENT_MUST_NOT_PRINT";
  const withMarker = tar([directory(), certificate({ content: Buffer.from(sensitiveMarker) })]);
  const result = invoke(withMarker);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, BLOCK);
  assert.equal(result.stdout.includes(sensitiveMarker), false);
  assert.equal(result.stderr.includes(sensitiveMarker), false);
});
