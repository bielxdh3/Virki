import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AUDITED_VERIFIER_FILES } from "../infra/offline/trusted-host-installer.mjs";
import { createManualNativeHostReviewPackage, verifyManualNativeImageReceiptForReview,
  NATIVE_HOST_REVIEW_FILES } from "./offline-manual-native-host-package.mjs";

const SOURCE = "c3ea768956bc3522363b725c138086a3c3e1c399";
const TOOLING = "ce9d6a2b102747da0f353ee7098aafbde787a402";
const SHA = (v) => createHash("sha256").update(v).digest("hex");
test("actual existing Windows E: receipt converts to WSL without modifying owner data", {
  skip: process.env.VIRKI_NATIVE_REAL_IMAGE_RECEIPT ? false :
    "set VIRKI_NATIVE_REAL_IMAGE_RECEIPT to existing private receipt; no production writes",
}, () => {
  const filename = process.env.VIRKI_NATIVE_REAL_IMAGE_RECEIPT;
  const before = readFileSync(filename);
  const digest = SHA(before);
  const real = JSON.parse(before.toString("utf8"));
  const checked = verifyManualNativeImageReceiptForReview(real);
  assert.equal(checked.sourceSha, SOURCE);
  assert.notEqual(checked.sourceSha, TOOLING);
  assert.deepEqual(checked.images.map(({ role, archiveSizeBytes }) => ({ role, archiveSizeBytes })), [
    { role: "runtime", archiveSizeBytes: 959170560 },
    { role: "migrator", archiveSizeBytes: 1330946048 },
  ]);
  assert.ok(real.directory.startsWith("E:\\VirkiManualPrivate20261028\\manual-images-"));
  assert.equal(real.ownerSignatureVerified, false);
  assert.equal(real.deployAuthorized, false);
  assert.equal(SHA(readFileSync(filename)), digest, "actual receipt must remain byte-for-byte unchanged");
});
function receipt(root) {
  return {
    status: "LOCAL_SOURCE_AND_IMAGES_VERIFIED_ONLY", sourceSha: SOURCE,
    directory: root, sourceArchive: path.join(root, "source.tar"),
    sourceArchiveSha256: SHA("source"),
    images: {
      runtime: { role: "runtime", imageId: "sha256:" + "a".repeat(64),
        archiveSha256: SHA("runtime"), archiveSizeBytes: 8192,
        archivePath: path.join(root, "runtime.tar") },
      migrator: { role: "migrator", imageId: "sha256:" + "b".repeat(64),
        archiveSha256: SHA("migrator"), archiveSizeBytes: 9216,
        archivePath: path.join(root, "migrator.tar") },
    }, npmCacheLockSha256: SHA("lock"), npmCachePackagesVerified: 339,
    prismaEngineCommit: "f".repeat(40), prismaEngineTarget: "linux-musl-openssl-3.0.x",
    hostedCi: "NOT_RUN", codeql: "NOT_RUN", ghcr: "NOT_USED",
    ownerSignatureVerified: false, deployAuthorized: false, transferAuthorized: false,
  };
}
test("native host code review package uses a separate source ID and exact fixed audited files", async (t) => {
  const temp = mkdtempSync(path.join(os.tmpdir(), "virki-manual-host-review-"));
  const parent = path.join(temp, "private");
  const repository = path.join(temp, "source");
  const input = path.join(temp, "image-build");
  const { mkdirSync } = await import("node:fs");
  mkdirSync(parent, { mode: 0o700 });
  mkdirSync(repository, { mode: 0o700 });
  mkdirSync(input, { mode: 0o700 });
  chmodSync(parent, 0o700); chmodSync(repository, 0o700); chmodSync(input, 0o700);
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  for (const file of NATIVE_HOST_REVIEW_FILES) {
    const filename = path.join(repository, ...file.split("/"));
    mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    writeFileSync(filename, `reviewed source ${file}\n`, { mode: 0o600 });
  }
  const r = receipt(input);
  assert.equal(verifyManualNativeImageReceiptForReview(r).sourceSha, SOURCE);
  const windowsRoot = "E:\\VirkiManualPrivate20261028\\manual-images-IRh9ul";
  const windowsReceipt = {
    ...r, directory: windowsRoot,
    sourceArchive: `${windowsRoot}\\source.tar`,
    images: {
      runtime: { ...r.images.runtime, os: "linux", architecture: "amd64",
        labels: { "org.opencontainers.image.revision": SOURCE,
          "org.opencontainers.image.source": "https://github.com/bielxdh3/Virki" },
        archivePath: `${windowsRoot}\\runtime.tar` },
      migrator: { ...r.images.migrator, os: "linux", architecture: "amd64",
        labels: { "org.opencontainers.image.revision": SOURCE,
          "org.opencontainers.image.source": "https://github.com/bielxdh3/Virki" },
        archivePath: `${windowsRoot}\\migrator.tar` },
    },
  };
  assert.equal(verifyManualNativeImageReceiptForReview(windowsReceipt).sourceSha, SOURCE);
  assert.throws(() => verifyManualNativeImageReceiptForReview({ ...windowsReceipt,
    images: { ...windowsReceipt.images, runtime: {
      ...windowsReceipt.images.runtime,
      archivePath: "E:\\VirkiManualPrivate20261028\\..\\runtime.tar",
    } },
  }));
  const result = await createManualNativeHostReviewPackage({
    repositoryRoot: repository, stagingParent: parent,
    imageReceipt: windowsReceipt, builderRevision: TOOLING,
  });
  assert.equal(result.status, "NATIVE_HOST_OWNER_REVIEW_PACKAGE_UNSIGNED");
  assert.equal(result.ownerSignatureVerified, false);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.hostInstallAuthorized, false);
  assert.equal(result.sourceSha, SOURCE);
  assert.equal(result.builderRevision, TOOLING);
  assert.notEqual(result.sourceSha, result.builderRevision);
  const files = readdirSync(result.directory).sort();
  assert.deepEqual(files, ["inventory.json", "native", "verifier"].sort());
  assert.equal(lstatSync(result.directory).mode & 0o777, 0o700);
  const inventory = JSON.parse(readFileSync(path.join(result.directory, "inventory.json"), "utf8"));
  assert.equal(inventory.status, result.status);
  assert.equal(inventory.modules.length, AUDITED_VERIFIER_FILES.length);
  assert.equal(inventory.native.length, NATIVE_HOST_REVIEW_FILES.length - AUDITED_VERIFIER_FILES.length);
  for (const item of [...inventory.modules, ...inventory.native]) {
    const file = path.join(result.directory, item.group, ...item.path.split("/"));
    assert.equal(SHA(readFileSync(file)), item.sha256);
    assert.equal(lstatSync(file).mode & 0o777, 0o600);
  }
  assert.deepEqual(inventory.images.map((i) => i.role), ["runtime", "migrator"]);
  assert.deepEqual(inventory.images.map((i) => i.imageId),
    [r.images.runtime.imageId, r.images.migrator.imageId]);
  await assert.rejects(createManualNativeHostReviewPackage({
    repositoryRoot: result.directory, stagingParent: result.directory,
    imageReceipt: r, builderRevision: TOOLING,
  }));
  for (const mutant of [
    { ...r, sourceSha: "0".repeat(40) },
    { ...r, deployAuthorized: true },
    { ...r, images: { ...r.images, migrator: r.images.runtime } },
    { ...r, images: { ...r.images, runtime: { ...r.images.runtime, archiveSha256: "x".repeat(64) } } },
    { ...r, images: { ...r.images, migrator: { ...r.images.migrator, archivePath: path.join(input, "../migrator.tar") } } },
  ]) assert.throws(() => verifyManualNativeImageReceiptForReview(mutant));
});
