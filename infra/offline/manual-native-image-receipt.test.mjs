import assert from "node:assert/strict";
import test from "node:test";
import { verifyNativeManualImageBatchReceipt } from "./manual-native-image-receipt.mjs";

const REV = "b".repeat(40);
const IDs = ["sha256:" + "a".repeat(64), "sha256:" + "c".repeat(64)];
const SHAS = ["d".repeat(64), "e".repeat(64)];
const manifest = { sourceSha: REV, manifestSha256: "f".repeat(64),
  runtime: { imageId: IDs[0], archiveSha256: SHAS[0] },
  migrator: { imageId: IDs[1], archiveSha256: SHAS[1] } };
function inspect(id) {
  return Buffer.from(JSON.stringify({
    Id: id, Os: "linux", Architecture: "amd64", RepoTags: [], RepoDigests: [],
    Config: { User: "node:node", Labels: {
      "org.opencontainers.image.revision": REV,
      "org.opencontainers.image.source": "https://github.com/bielxdh3/Virki",
    } },
  })).toString("base64");
}
function batch() {
  return { status: "DISPOSABLE_NATIVE_BATCH_COMPLETE", sourceSha: REV,
    runtime: { role: "runtime", imageId: IDs[0], archiveSha256: SHAS[0],
      loadReceiptSha256: "1".repeat(64), inspectBase64: inspect(IDs[0]) },
    migrator: { role: "migrator", imageId: IDs[1], archiveSha256: SHAS[1],
      loadReceiptSha256: "2".repeat(64), inspectBase64: inspect(IDs[1]) },
    dockerLoadAuthorized: false, deployAuthorized: false };
}
test("complete two-image same-session observation maps to signed manifest without admission", () => {
  const result = verifyNativeManualImageBatchReceipt({ batch: batch(), expected: manifest });
  assert.equal(result.status, "DISPOSABLE_TWO_IMAGES_RECONCILED_NONAUTHORIZING");
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.dockerLoadAuthorized, false);
  assert.equal(result.manifestSha256, manifest.manifestSha256);
  assert.deepEqual(result.imageIds, IDs);
});
test("native batch receipts reject mutation, role mixups and untrusted claims", () => {
  for (const mutate of [
    (b) => { b.runtime.role = "migrator"; },
    (b) => { b.runtime.archiveSha256 = SHAS[1]; },
    (b) => { b.runtime.imageId = IDs[1]; },
    (b) => { b.runtime.loadReceiptSha256 = ""; },
    (b) => { b.runtime.inspectBase64 = Buffer.from("[]").toString("base64"); },
    (b) => { b.runtime.inspectBase64 = "a".repeat(400_000); },
    (b) => { b.runtime.inspectBase64 += "="; },
    (b) => { b.runtime.inspectBase64 = Buffer.from('{"x":0}').toString("base64"); },
    (b) => { b.runtime.inspectBase64 = inspect(IDs[1]); },
    (b) => { b.runtime.untrusted = true; },
    (b) => { b.migrator = b.runtime; },
    (b) => { b.sourceSha = "0".repeat(40); },
    (b) => { b.dockerLoadAuthorized = true; },
    (b) => { b.status = "IMPORTED"; },
  ]) {
    const data = batch(); mutate(data);
    assert.throws(() => verifyNativeManualImageBatchReceipt({ batch: data, expected: manifest }));
  }
  assert.throws(() => verifyNativeManualImageBatchReceipt({ batch: batch(), expected: {
    ...manifest, migrator: { ...manifest.runtime },
  } }));
});
