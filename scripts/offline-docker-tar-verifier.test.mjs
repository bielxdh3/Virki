import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants, linkSync, mkdtempSync, readSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyOfflineDockerSaveTar, verifyOfflineDockerSaveTarFromHandle } from "./lib/offline-docker-tar-verifier.mjs";

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

// Containerd-backed Docker 29 exports a Docker manifest.json AND an OCI
// index/manifest/config/layer descriptor graph in the same tarball.
function setupOci(t, changes = {}) {
  const layerBytes = changes.layerBytes ?? tar([{ name: "usr/local/bin/app", bytes: Buffer.from("hello") }]);
  const layerDigest = sha256(layerBytes);
  const layerPath = `blobs/sha256/${layerDigest}`;
  const config = {
    os: changes.os ?? "linux", architecture: changes.architecture ?? "amd64",
    config: {
      User: changes.user ?? "node:node",
      Labels: {
        "org.opencontainers.image.revision": changes.revision ?? REVISION,
        "org.opencontainers.image.source": changes.source ?? SOURCE,
      },
    },
    rootfs: { type: "layers", diff_ids: [`sha256:${changes.diffId ?? layerDigest}`] },
  };
  const configBytes = changes.configBytes ?? json(config);
  const configId = sha256(configBytes);
  const configPath = `blobs/sha256/${configId}`;
  const ociManifest = {
    schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: `sha256:${configId}`, size: configBytes.length },
    layers: [{
      mediaType: "application/vnd.oci.image.layer.v1.tar",
      digest: `sha256:${layerDigest}`, size: layerBytes.length,
    }],
  };
  const ociManifestBytes = changes.ociManifestBytes ?? json(ociManifest);
  const manifestId = sha256(ociManifestBytes);
  const ociIndex = {
    schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [{
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      digest: `sha256:${manifestId}`,
      size: ociManifestBytes.length,
      ...(changes.platform ? { platform: changes.platform } : {}),
    }],
  };
  const classicManifest = [{
    Config: configPath, RepoTags: changes.tags ?? null,
    Layers: [layerPath],
    LayerSources: {
      [`sha256:${layerDigest}`]: {
        mediaType: "application/vnd.oci.image.layer.v1.tar",
        size: layerBytes.length, digest: `sha256:${layerDigest}`,
      },
    },
  }];
  const files = [
    { name: "blobs/", type: "5" },
    { name: "blobs/sha256/", type: "5" },
    { name: configPath, bytes: configBytes },
    { name: layerPath, bytes: layerBytes },
    { name: `blobs/sha256/${manifestId}`, bytes: ociManifestBytes },
    { name: "index.json", bytes: changes.indexBytes ?? json(ociIndex) },
    { name: "manifest.json", bytes: changes.dockerManifestBytes ?? json(classicManifest) },
    { name: "oci-layout", bytes: changes.layoutBytes ?? json({ imageLayoutVersion: "1.0.0" }) },
    ...(changes.legacyMetadata ? (() => {
      const metadata = typeof changes.legacyMetadata === "object"
        ? changes.legacyMetadata
        : {
            id: "b".repeat(64), created: "2026-10-21T12:34:56.000000000Z",
            container_config: {}, os: "linux", architecture: "amd64",
            config: { User: config.config.User, Labels: config.config.Labels },
          };
      const bytes = json(metadata);
      return [{ name: `blobs/sha256/${sha256(bytes)}`, bytes }];
    })() : []),
    ...(changes.extraFiles ?? []),
  ];
  const fixture = setup(t, {
    entries: files,
    imageId: changes.imageId ?? configId,
  });
  return {
    ...fixture, files, config, configId, configPath, layerPath, layerDigest,
    ociIndex, ociManifest, classicManifest, manifestId,
  };
}

test("verifies actual Docker 29 OCI layout image graph, layer bytes and source identity", async (t) => {
  const fixture = setupOci(t);
  const proof = await verifyOfflineDockerSaveTar(fixture.args);
  assert.equal(proof.imageId, `sha256:${fixture.configId}`);
  assert.equal(proof.platform, "linux/amd64");
  assert.equal(proof.archiveSha256, fixture.args.expectedArchiveSha256);
  assert.equal(proof.layerCount, 1);
  assert.equal(proof.user, "node:node");
});

test("verifies Docker 29's content-addressed legacy layer history for one layer", async (t) => {
  const fixture = setupOci(t, { legacyMetadata: true });
  const proof = await verifyOfflineDockerSaveTar(fixture.args);
  assert.equal(proof.imageId, `sha256:${fixture.configId}`);
  assert.equal(proof.layerCount, 1);
});

for (const [name, legacyMetadata] of [
  ["noncanonical legacy image ID", { id: "../escape", created: "2026-10-21T12:34:56Z", container_config: {}, os: "linux", architecture: "amd64", config: { User: "node:node", Labels: { "org.opencontainers.image.revision": REVISION, "org.opencontainers.image.source": SOURCE } } }],
  ["orphan parent", { id: "b".repeat(64), parent: "a".repeat(64), created: "2026-10-21T12:34:56Z", container_config: {}, os: "linux", architecture: "amd64", config: { User: "node:node", Labels: { "org.opencontainers.image.revision": REVISION, "org.opencontainers.image.source": SOURCE } } }],
  ["wrong legacy user", { id: "b".repeat(64), created: "2026-10-21T12:34:56Z", container_config: {}, os: "linux", architecture: "amd64", config: { User: "root", Labels: { "org.opencontainers.image.revision": REVISION, "org.opencontainers.image.source": SOURCE } } }],
  ["wrong legacy revision", { id: "b".repeat(64), created: "2026-10-21T12:34:56Z", container_config: {}, os: "linux", architecture: "amd64", config: { User: "node:node", Labels: { "org.opencontainers.image.revision": "f".repeat(40), "org.opencontainers.image.source": SOURCE } } }],
  ["unexpected legacy commands", { id: "b".repeat(64), created: "2026-10-21T12:34:56Z", container_config: {}, os: "linux", architecture: "amd64", config: { User: "node:node", Labels: { "org.opencontainers.image.revision": REVISION, "org.opencontainers.image.source": SOURCE } }, bogus: true }],
]) {
  test(`rejects forged Docker legacy metadata: ${name}`, async (t) => {
    const fixture = setupOci(t, { legacyMetadata });
    await assert.rejects(verifyOfflineDockerSaveTar(fixture.args), /rejected/u);
  });
}

for (const [name, change] of [
  ["wrong revision", { revision: "f".repeat(40) }],
  ["wrong source", { source: "https://attacker.invalid/repo" }],
  ["wrong OS", { os: "windows" }],
  ["wrong architecture", { architecture: "arm64" }],
  ["root", { user: "root" }],
  ["bad image ID", { imageId: "f".repeat(64) }],
  ["config diff_id mismatch", { diffId: "f".repeat(64) }],
  ["mismatched descriptor platform", { platform: { os: "linux", architecture: "arm64" } }],
  ["unreferenced foreign blobs", { extraFiles: [{ name: `blobs/sha256/${"a".repeat(64)}`, bytes: Buffer.from("evil") }] }],
  ["unexpected PAX", { extraFiles: [{ name: "PaxHeader", type: "x", bytes: Buffer.from("bad") }] }],
  ["OCI layout version changed", { layoutBytes: json({ imageLayoutVersion: "1.0.1" }) }],
  ["OCI index descriptor size forged", { indexBytes: json({ schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: [{ mediaType: "application/vnd.oci.image.manifest.v1+json", digest: `sha256:${"a".repeat(64)}`, size: 1 }] }) }],
  ["OCI index has no manifest", { indexBytes: json({ schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: [] }) }],
  ["duplicate index key", { indexBytes: Buffer.from('{"schemaVersion":2,"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}') }],
]) {
  test(`rejects forged OCI layout: ${name}`, async (t) => {
    const fixture = setupOci(t, change);
    await assert.rejects(verifyOfflineDockerSaveTar(fixture.args), /rejected/u);
  });
}

test("rejects descriptor graph tampering even with a rehashed outer archive", async (t) => {
  const base = setupOci(t);
  const badLayer = {
    ...base.ociManifest,
    layers: [{ ...base.ociManifest.layers[0], size: base.ociManifest.layers[0].size + 1 }],
  };
  const wrongLayerSize = setupOci(t, { ociManifestBytes: json(badLayer) });
  await assert.rejects(verifyOfflineDockerSaveTar(wrongLayerSize.args), /rejected/u);
  const badMediaType = {
    ...base.ociManifest,
    layers: [{ ...base.ociManifest.layers[0], mediaType: "application/vnd.oci.image.layer.v1.tar+gzip" }],
  };
  const compressed = setupOci(t, { ociManifestBytes: json(badMediaType) });
  await assert.rejects(verifyOfflineDockerSaveTar(compressed.args), /rejected/u);
  const replacementLayer = setupOci(t, {
    extraFiles: [{ name: "blobs/sha256/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", bytes: Buffer.from("forged blob") }],
  });
  await assert.rejects(verifyOfflineDockerSaveTar(replacementLayer.args), /rejected/u);
});

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

test("borrowed FileHandle authenticates classic and OCI TARs without consuming or closing descriptor", async (t) => {
  for (const fixture of [setup(t), setupOci(t, { legacyMetadata: true })]) {
    const fileHandle = await open(fixture.args.archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const { archivePath: _unused, ...expected } = fixture.args;
      const proof = await verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle });
      assert.equal(proof.imageId, fixture.args.expectedImageId);
      assert.equal(proof.archiveSha256, fixture.args.expectedArchiveSha256);
      assert.equal(proof.layerCount, 1);
      // The FD remains owned by the caller and positional reads preserve its cursor.
      const first = Buffer.alloc(512);
      assert.equal(readSync(fileHandle.fd, first, 0, 512, null), 512);
      assert.ok(first.equals(fixture.archiveBytes.subarray(0, 512)));
      assert.equal((await verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle })).archiveSha256,
        fixture.args.expectedArchiveSha256);
    } finally {
      await fileHandle.close();
    }
  }
});

test("renaming original and installing a different valid TAR cannot redirect borrowed FileHandle", async (t) => {
  const original = setup(t);
  const replacement = setup(t, { source: "https://attacker.invalid/other" });
  const fileHandle = await open(original.args.archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const { archivePath: _unused, ...expected } = original.args;
    renameSync(original.args.archivePath, path.join(original.directory, "retired.tar"));
    renameSync(replacement.args.archivePath, original.args.archivePath);
    assert.equal((await verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle })).archiveSha256,
      original.args.expectedArchiveSha256);
    await assert.rejects(verifyOfflineDockerSaveTar(original.args), /rejected/u);
  } finally {
    await fileHandle.close();
  }
});

test("borrowed FileHandle rejects in-place mutation, truncated content and wrong pin", async (t) => {
  const fixture = setup(t);
  const fileHandle = await open(fixture.args.archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  const { archivePath: _unused, ...expected } = fixture.args;
  try {
    await assert.rejects(verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle,
      expectedArchiveSha256: "f".repeat(64) }), /rejected/u);
    const changed = Buffer.from(fixture.archiveBytes);
    changed[changed.length - 1] = 1;
    writeFileSync(fixture.args.archivePath, changed);
    await assert.rejects(verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle }), /rejected/u);
    writeFileSync(fixture.args.archivePath, changed.subarray(0, changed.length - 512));
    await assert.rejects(verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle }), /rejected/u);
  } finally {
    await fileHandle.close();
  }
  await assert.rejects(verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle }), /rejected|EBADF/u);
  await assert.rejects(verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle: -1 }), /rejected/u);
  await assert.rejects(verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle: fixture.args.archivePath }), /rejected/u);
  await assert.rejects(verifyOfflineDockerSaveTarFromHandle({ ...expected, fileHandle: { fd: 1 } }), /rejected/u);
});
