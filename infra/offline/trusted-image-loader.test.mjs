import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, copyFileSync, linkSync, mkdtempSync, renameSync, rmSync,
  symlinkSync, writeFileSync,
} from "node:fs";
import fsPromises from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  compareUntrustedLoadedImageForPreview, inspectUntrustedPinnedImageForPreview, loadTrustedOfflineImage,
  previewTrustedOfflineImageLoad, TRUSTED_OFFLINE_STAGING_PATH,
} from "./trusted-image-loader.mjs";

test("native offline candidate staging remains disjoint from exclusive replay ledger and source-Git roots", () => {
  const roots = ["/var/lib/virki/offline-release", "/var/lib/virki/offline-source"];
  assert.equal(path.posix.isAbsolute(TRUSTED_OFFLINE_STAGING_PATH), true);
  for (const root of roots) {
    const relative = path.posix.relative(root, TRUSTED_OFFLINE_STAGING_PATH);
    assert.equal(relative === ".." || relative.startsWith("../"), true,
      `staging ${TRUSTED_OFFLINE_STAGING_PATH} must be outside exclusive root ${root}`);
  }
});

const REVISION = "fbac177b91414ff8d047cef40cc9920d0ba882cd";
const SOURCE = "https://github.com/bielxdh3/Virki";
const sha = (data) => createHash("sha256").update(data).digest("hex");
function octal(header, start, size, value) {
  header.write(value.toString(8).padStart(size - 1, "0"), start, "ascii");
}
function tar(entries) {
  const blocks = [];
  for (const [name, contents] of entries) {
    const data = Buffer.from(contents);
    const hdr = Buffer.alloc(512);
    hdr.write(name, 0, "ascii");
    octal(hdr, 100, 8, 0o644);
    octal(hdr, 108, 8, 0);
    octal(hdr, 116, 8, 0);
    octal(hdr, 124, 12, data.length);
    octal(hdr, 136, 12, 0);
    hdr.fill(32, 148, 156);
    hdr.write("0", 156, "ascii");
    hdr.write("ustar", 257, "ascii");
    hdr.write("00", 263, "ascii");
    octal(hdr, 148, 8, hdr.reduce((sum, value) => sum + value, 0));
    blocks.push(hdr, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}
function fixture(t) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-image-loader-"));
  chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const layer = tar([["one.txt", "safe"]]);
  const config = Buffer.from(JSON.stringify({
    architecture: "amd64", os: "linux",
    config: {
      User: "node:node",
      Labels: {
        "org.opencontainers.image.revision": REVISION,
        "org.opencontainers.image.source": SOURCE,
      },
    },
    rootfs: { type: "layers", diff_ids: [`sha256:${sha(layer)}`] },
  }));
  const imageId = `sha256:${sha(config)}`;
  const archive = tar([
    [`${sha(config)}.json`, config],
    [`${"a".repeat(64)}/layer.tar`, layer],
    ["manifest.json", Buffer.from(JSON.stringify([{
      Config: `${sha(config)}.json`, RepoTags: null,
      Layers: [`${"a".repeat(64)}/layer.tar`],
    }]))],
  ]);
  const archivePath = path.join(dir, "runtime.tar");
  writeFileSync(archivePath, archive, { mode: 0o400 });
  return {
    dir, archivePath, archive, imageId,
    inputs: Object.freeze({
      archivePath,
      role: "runtime",
      expectedImageId: imageId,
      expectedRevision: REVISION,
      expectedArchiveSha256: sha(archive),
      expectedArchiveSizeBytes: archive.length,
    }),
  };
}

test("read-only pinned preview validates original archive, returns no Docker authorization or token", async (t) => {
  const f = fixture(t);
  const preview = await inspectUntrustedPinnedImageForPreview(f.inputs);
  assert.deepEqual(preview, {
    status: "UNTRUSTED_PINNED_ARCHIVE_PREVIEW_ONLY",
    deployAuthorized: false,
    dockerLoadAuthorized: false,
    role: "runtime",
    imageId: f.imageId,
    archiveSha256: sha(f.archive),
    archiveSizeBytes: f.archive.length,
    platform: "linux/amd64",
    user: "node:node",
    stdinDesign: "inherit pinned verified regular-file FD as child stdin; never reopen archive filename",
  });
  assert.equal(Object.isFrozen(preview), true);
  assert.equal(Object.hasOwn(preview, "fd"), false);
  assert.equal(Object.hasOwn(preview, "authorizationToken"), false);
});

test("preview opens TAR exactly once and parses through the original pinned descriptor", async (t) => {
  const f = fixture(t);
  const originalOpen = fsPromises.open;
  const opened = [];
  fsPromises.open = async (...args) => {
    opened.push(args[0]);
    if (opened.length > 1) throw new Error("second filesystem open forbidden by test");
    return originalOpen(...args);
  };
  syncBuiltinESMExports();
  try {
    const result = await inspectUntrustedPinnedImageForPreview(f.inputs);
    assert.equal(result.archiveSha256, sha(f.archive));
    assert.deepEqual(opened, [f.archivePath]);
  } finally {
    fsPromises.open = originalOpen;
    syncBuiltinESMExports();
  }
});

test("rejects path swap after no-follow FD pinning even with a valid replacement image", async (t) => {
  const f = fixture(t);
  const original = path.join(f.dir, "original.tar");
  const replacement = path.join(f.dir, "replacement.tar");
  copyFileSync(f.archivePath, replacement);
  await assert.rejects(inspectUntrustedPinnedImageForPreview({
    ...f.inputs,
    // This callback is part of a read-only test probe only.
    afterPinnedOpen: () => {
      renameSync(f.archivePath, original);
      renameSync(replacement, f.archivePath);
    },
  }), /refused/u);
});

test("pinned FD itself reads original bytes after a filename swap (no Docker daemon)", async (t) => {
  const f = fixture(t);
  const replacement = path.join(f.dir, "replacement.tar");
  writeFileSync(replacement, Buffer.alloc(f.archive.length, 0x78));
  const result = await inspectUntrustedPinnedImageForPreview({
    ...f.inputs,
    afterPinnedOpen: ({ pinnedFd }) => {
      const previous = path.join(f.dir, "retired.tar");
      renameSync(f.archivePath, previous);
      renameSync(replacement, f.archivePath);
      // Child inherits the already-open file description as fd 0, which is
      // exactly how a future trusted implementation must pass Docker stdin.
      const child = spawnSync(process.execPath, ["-e",
        "const fs=require('node:fs');let h=require('node:crypto').createHash('sha256');let b=Buffer.alloc(4096),n;while((n=fs.readSync(0,b))>0)h.update(b.subarray(0,n));process.stdout.write(h.digest('hex'))"],
      { stdio: [pinnedFd, "pipe", "pipe"], encoding: "utf8" });
      assert.equal(child.status, 0, child.stderr);
      assert.equal(child.stdout, sha(f.archive));
    },
  }).then(() => "unsafe").catch((error) => error);
  assert.notEqual(result, "unsafe");
  assert.match(result.message, /refused/u);
});

test("in-place TAR replacement during pinned inspection also fails closed", async (t) => {
  const f = fixture(t);
  await assert.rejects(inspectUntrustedPinnedImageForPreview({
    ...f.inputs,
    afterPinnedOpen: () => {
      const altered = Buffer.from(f.archive);
      altered[altered.length - 1] = 1;
      writeFileSync(f.archivePath, altered);
    },
  }), /refused/u);
});

test("unsafe symlink, hardlink, changed contents, wrong revision and invalid caller fields reject", async (t) => {
  const f = fixture(t);
  await assert.rejects(inspectUntrustedPinnedImageForPreview({
    ...f.inputs, expectedArchiveSha256: "f".repeat(64),
  }), /refused/u);
  await assert.rejects(inspectUntrustedPinnedImageForPreview({
    ...f.inputs, expectedRevision: "0".repeat(40),
  }), /refused|rejected/u);
  await assert.rejects(inspectUntrustedPinnedImageForPreview({
    ...f.inputs, role: "foreign",
  }), /refused/u);
  const alias = path.join(f.dir, "alias.tar");
  symlinkSync(f.archivePath, alias);
  await assert.rejects(inspectUntrustedPinnedImageForPreview({
    ...f.inputs, archivePath: alias,
  }), /refused/u);
  rmSync(alias);
  linkSync(f.archivePath, alias);
  await assert.rejects(inspectUntrustedPinnedImageForPreview(f.inputs), /refused/u);
});

test("protected loader rejects user-claimed trust tokens and direct Docker load invocations", async () => {
  for (const request of [
    {},
    { role: "runtime", admissionToken: "APPROVED" },
    { candidateDirectory: TRUSTED_OFFLINE_STAGING_PATH, role: "runtime",
      trusted: true, deployAuthorized: true },
    { candidateDirectory: TRUSTED_OFFLINE_STAGING_PATH, role: "migrator" },
  ]) {
    await assert.rejects(loadTrustedOfflineImage(request), /refused/u);
  }
});

test("post-load image inspect must match ID, revision, source, OS/arch, user and no preexisting aliases", () => {
  const verifiedImage = Object.freeze({
    imageId: `sha256:${"a".repeat(64)}`, revision: REVISION,
    source: SOURCE, platform: "linux/amd64", user: "node:node",
  });
  const inspect = [{
    Id: verifiedImage.imageId, Os: "linux", Architecture: "amd64",
    Config: {
      User: "node:node",
      Labels: {
        "org.opencontainers.image.revision": REVISION,
        "org.opencontainers.image.source": SOURCE,
      },
    },
    RepoTags: null, RepoDigests: null,
  }];
  assert.deepEqual(compareUntrustedLoadedImageForPreview({ verifiedImage, imageInspect: inspect }), {
    status: "UNTRUSTED_POSTLOAD_COMPARISON_ONLY",
    dockerTagAuthorized: false, deployAuthorized: false, imageId: verifiedImage.imageId,
  });
  for (const mutate of [
    (image) => { image.Id = `sha256:${"b".repeat(64)}`; },
    (image) => { image.Os = "windows"; },
    (image) => { image.Architecture = "arm64"; },
    (image) => { image.Config.User = "root"; },
    (image) => { image.Config.Labels["org.opencontainers.image.revision"] = "f".repeat(40); },
    (image) => { image.Config.Labels["org.opencontainers.image.source"] = "https://evil.invalid"; },
    (image) => { image.RepoTags = ["demanage:latest"]; },
    (image) => { image.RepoDigests = ["ghcr.io/attacker/other@sha256:" + "f".repeat(64)]; },
  ]) {
    const bad = structuredClone(inspect);
    mutate(bad[0]);
    assert.throws(() => compareUntrustedLoadedImageForPreview({
      verifiedImage, imageInspect: bad,
    }), /refused/u);
  }
  assert.throws(() => compareUntrustedLoadedImageForPreview({
    verifiedImage, imageInspect: [...inspect, ...inspect],
  }), /refused/u);
  assert.throws(() => compareUntrustedLoadedImageForPreview({
    verifiedImage: { ...verifiedImage, source: "https://example.invalid" },
    imageInspect: inspect,
  }), /refused/u);
});

test("privileged preview requires native root and fixed owner-protected location", async () => {
  await assert.rejects(previewTrustedOfflineImageLoad({ archivePath: "/tmp/unsafe.tar" }), /refused/u);
  await assert.rejects(previewTrustedOfflineImageLoad({
    candidateDirectory: "/tmp/attacker", role: "runtime",
  }), /refused/u);
});
