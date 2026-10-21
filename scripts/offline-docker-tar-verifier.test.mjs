import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { linkSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyOfflineDockerSaveTar } from "./lib/offline-docker-tar-verifier.mjs";

const REVISION = "fbac177b91414ff8d047cef40cc9920d0ba882cd";
const SOURCE = "https://github.com/bielxdh3/Virki";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const json = (value) => Buffer.from(JSON.stringify(value));
const pad = (bytes) => (512 - bytes % 512) % 512;

function octal(buffer, start, width, value) {
  const digits = value.toString(8).padStart(width - 1, "0");
  buffer.write(digits, start, "ascii");
  buffer[start + width - 1] = 0;
}

function tar(entries) {
  const blocks = [];
  for (const { name, bytes = Buffer.alloc(0), type = "0", link = "", uid = 0, gid = 0 } of entries) {
    const data = Buffer.from(bytes);
    const header = Buffer.alloc(512);
    header.write(name, 0, "ascii");
    octal(header, 100, 8, 0o644);
    octal(header, 108, 8, uid);
    octal(header, 116, 8, gid);
    octal(header, 124, 12, data.length);
    octal(header, 136, 12, 0);
    header.fill(32, 148, 156);
    header.write(type, 156, "ascii");
    header.write(link, 157, "ascii");
    header.write("ustar", 257, "ascii");
    header.write("00", 263, "ascii");
    octal(header, 148, 8, header.reduce((sum, digit) => sum + digit, 0));
    blocks.push(header, data, Buffer.alloc(pad(data.length)));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function setup(t, options = {}) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-docker-tar-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const archivePath = path.join(directory, "runtime.tar");
  const layerBytes = options.layerBytes ?? tar([{ name: "app.txt", bytes: Buffer.from("ok") }]);
  const diffId = sha256(layerBytes);
  const layerPath = `${"a".repeat(64)}/layer.tar`;
  const config = {
    architecture: options.architecture ?? "amd64",
    os: options.os ?? "linux",
    config: {
      User: options.user ?? "node:node",
      Labels: {
        "org.opencontainers.image.revision": options.revision ?? REVISION,
        "org.opencontainers.image.source": options.source ?? SOURCE,
      },
    },
    rootfs: { type: "layers", diff_ids: [`sha256:${options.diffId ?? diffId}`] },
  };
  const configBytes = options.configBytes ?? json(config);
  const configId = sha256(configBytes);
  const manifest = options.manifestBytes ?? json([{
    Config: `${configId}.json`, RepoTags: options.tags ?? null, Layers: [layerPath],
  }]);
  const files = options.entries ?? [
    { name: `${configId}.json`, bytes: configBytes },
    { name: layerPath, bytes: layerBytes },
    { name: "manifest.json", bytes: manifest },
  ];
  const archiveBytes = tar(files);
  writeFileSync(archivePath, archiveBytes);
  const args = {
    archivePath,
    expectedImageId: `sha256:${options.imageId ?? configId}`,
    expectedRevision: REVISION,
    expectedArchiveSha256: sha256(archiveBytes),
    expectedArchiveSizeBytes: archiveBytes.length,
    role: "runtime",
  };
  return { args, files, config, configBytes, configId, layerBytes, layerPath, directory, archiveBytes };
}

test("verifies a real Docker-save-shaped TAR without extracting or running Docker", async (t) => {
  const fixture = setup(t);
  const proof = await verifyOfflineDockerSaveTar(fixture.args);
  assert.deepEqual(proof, {
    role: "runtime",
    imageId: `sha256:${fixture.configId}`,
    revision: REVISION,
    source: SOURCE,
    platform: "linux/amd64",
    user: "node:node",
    archiveSha256: fixture.args.expectedArchiveSha256,
    archiveSizeBytes: fixture.archiveBytes.length,
    layerCount: 1,
  });
  assert.equal(Object.isFrozen(proof), true);
});

for (const [label, change] of [
  ["wrong platform", { architecture: "arm64" }],
  ["wrong operating system", { os: "windows" }],
  ["root runtime", { user: "0:0" }],
  ["missing runtime user", { user: "" }],
  ["wrong revision label", { revision: "f".repeat(40) }],
  ["wrong source label", { source: "https://example.invalid/forged" }],
  ["layer content changed versus immutable diff_id", { diffId: "b".repeat(64) }],
  ["image ID differs from the content-hashed config", { imageId: "c".repeat(64) }],
  ["repository tags can alter unrelated images on load", { tags: ["demanage:latest"] }],
]) {
  test(`refuses ${label}`, async (t) => {
    const fixture = setup(t, change);
    await assert.rejects(verifyOfflineDockerSaveTar(fixture.args), /rejected/u);
  });
}

test("rejects forged archive SHA and length even for a structurally valid TAR", async (t) => {
  const fixture = setup(t);
  await assert.rejects(verifyOfflineDockerSaveTar({
    ...fixture.args, expectedArchiveSha256: "0".repeat(64),
  }), /rejected/u);
  await assert.rejects(verifyOfflineDockerSaveTar({
    ...fixture.args, expectedArchiveSizeBytes: fixture.args.expectedArchiveSizeBytes + 512,
  }), /rejected/u);
});

test("rejects forged JSON duplicate keys in image config and manifest", async (t) => {
  const dupConfig = Buffer.from(`{"os":"linux","os":"windows","architecture":"amd64","config":{"User":"node:node","Labels":{}},"rootfs":{"type":"layers","diff_ids":[]}}`);
  const a = setup(t, { configBytes: dupConfig });
  await assert.rejects(verifyOfflineDockerSaveTar(a.args), /rejected/u);

  const b = setup(t);
  const duplicateManifest = Buffer.from(`[{"Config":"${b.configId}.json","Config":"${b.configId}.json","RepoTags":null,"Layers":["${b.layerPath}"]}]`);
  const c = setup(t, { manifestBytes: duplicateManifest });
  await assert.rejects(verifyOfflineDockerSaveTar(c.args), /rejected/u);
});

test("fails closed for OCI-layout docker-save variants and unrecognized manifest metadata", async (t) => {
  const legacy = setup(t);
  const ociLayout = setup(t, { entries: [
    ...legacy.files,
    { name: "oci-layout", bytes: Buffer.from('{"imageLayoutVersion":"1.0.0"}') },
    { name: "index.json", bytes: json({ schemaVersion: 2, manifests: [] }) },
  ] });
  await assert.rejects(verifyOfflineDockerSaveTar(ociLayout.args), /rejected/u);
  const foreignManifest = setup(t, { manifestBytes: json([{
    Config: `${legacy.configId}.json`, RepoTags: null, Layers: [legacy.layerPath],
    LayerSources: { malicious: "unvalidated" },
  }]) });
  await assert.rejects(verifyOfflineDockerSaveTar(foreignManifest.args), /rejected/u);
});

test("rejects traversal, absolute, symlink, hardlink, PAX and duplicate outer members", async (t) => {
  const seed = setup(t);
  for (const extra of [
    { name: "../escape", bytes: Buffer.from("evil") },
    { name: "/root/escape", bytes: Buffer.from("evil") },
    { name: "symlink", type: "2", link: "../../etc/passwd" },
    { name: "hardlink", type: "1", link: "manifest.json" },
    { name: "PaxHeaders.0/a", type: "x", bytes: Buffer.from("hi") },
    { name: "manifest.json", bytes: json([]) },
    { name: "foreign.tar", bytes: Buffer.from("unknown") },
    { name: "rogue.json", bytes: Buffer.from("{}"), uid: 1234 },
  ]) {
    const fixture = setup(t, { entries: [...seed.files, extra] });
    await assert.rejects(verifyOfflineDockerSaveTar(fixture.args), /rejected/u, extra.name);
  }
});

test("rejects malformed outer header checksum, truncated records and trailing bytes", async (t) => {
  const fixture = setup(t);
  const corrupt = Buffer.from(fixture.archiveBytes);
  corrupt[0] ^= 1;
  writeFileSync(fixture.args.archivePath, corrupt);
  await assert.rejects(verifyOfflineDockerSaveTar({
    ...fixture.args, expectedArchiveSha256: sha256(corrupt),
  }), /rejected/u);
  const truncated = fixture.archiveBytes.subarray(0, fixture.archiveBytes.length - 1024);
  writeFileSync(fixture.args.archivePath, truncated);
  await assert.rejects(verifyOfflineDockerSaveTar({
    ...fixture.args, expectedArchiveSha256: sha256(truncated),
    expectedArchiveSizeBytes: truncated.length,
  }), /rejected/u);
  const trailing = Buffer.concat([fixture.archiveBytes, Buffer.from("attack")]);
  writeFileSync(fixture.args.archivePath, trailing);
  await assert.rejects(verifyOfflineDockerSaveTar({
    ...fixture.args, expectedArchiveSha256: sha256(trailing),
    expectedArchiveSizeBytes: trailing.length,
  }), /rejected/u);
});

test("rejects symlink and hardlinked input even when contents match the expected digest", async (t) => {
  const fixture = setup(t);
  const original = fixture.args.archivePath;
  const alias = path.join(fixture.directory, "alias.tar");
  symlinkSync(original, alias);
  await assert.rejects(verifyOfflineDockerSaveTar({ ...fixture.args, archivePath: alias }), /rejected/u);
  rmSync(alias);
  linkSync(original, alias);
  await assert.rejects(verifyOfflineDockerSaveTar(fixture.args), /rejected/u);
});
