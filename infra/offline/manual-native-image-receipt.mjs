import { compareUntrustedLoadedImageForPreview } from "./trusted-image-loader.mjs";

// Reconcile a disposable, kernel-peer-checked native transport observation
// against identities supplied by the *separately* verified owner manifest.
// Neither caller-controlled data nor Docker's self-report grants admission.
const SHA = /^[a-f0-9]{64}$/u;
const IMAGE = /^sha256:[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const SOURCE = "https://github.com/bielxdh3/Virki";

function requireIt(ok) {
  if (!ok) throw new Error("Native manual image receipt refused");
}
function exact(object, fields) {
  requireIt(object && typeof object === "object" && !Array.isArray(object) &&
    Object.keys(object).length === fields.length &&
    fields.every((field, i) => Object.keys(object)[i] === field));
}
function verifyRole(role, observation, identity, revision) {
  exact(identity, ["imageId", "archiveSha256"]);
  exact(observation, ["role", "imageId", "archiveSha256", "loadReceiptSha256", "inspectBase64"]);
  requireIt(observation.role === role && IMAGE.test(identity.imageId) &&
    SHA.test(identity.archiveSha256) &&
    observation.imageId === identity.imageId &&
    observation.archiveSha256 === identity.archiveSha256 &&
    SHA.test(observation.loadReceiptSha256) &&
    typeof observation.inspectBase64 === "string" &&
    observation.inspectBase64.length > 0 &&
    observation.inspectBase64.length <= 349528 &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u
      .test(observation.inspectBase64));
  const raw = Buffer.from(observation.inspectBase64, "base64");
  requireIt(raw.length > 0 && raw.length <= 256 * 1024 &&
    raw.toString("base64") === observation.inspectBase64);
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch { requireIt(false); }
  const checked = compareUntrustedLoadedImageForPreview({
    // Native Docker HTTP /images/<id>/json returns ONE object; the legacy
    // Docker CLI `image inspect` returns an array. Require the native grammar.
    imageInspect: (parsed && typeof parsed === "object" && !Array.isArray(parsed)) ?
      [parsed] : [],
    verifiedImage: { imageId: identity.imageId, revision,
      source: SOURCE, platform: "linux/amd64", user: "node:node" },
  });
  requireIt(checked.status === "UNTRUSTED_POSTLOAD_COMPARISON_ONLY" &&
    checked.dockerTagAuthorized === false && checked.deployAuthorized === false);
  return identity.imageId;
}

/**
 * Transport receipts are advisory evidence. Installed owner/supervisor custody,
 * durable one-shot journal and off-host CAS are separate gates; this validator
 * neither writes receipts nor authorizes any Docker or production operation.
 */
export function verifyNativeManualImageBatchReceipt({ batch, expected } = {}) {
  exact(batch, ["status", "sourceSha", "runtime", "migrator",
    "dockerLoadAuthorized", "deployAuthorized"]);
  exact(expected, ["sourceSha", "manifestSha256", "runtime", "migrator"]);
  requireIt(batch.status === "DISPOSABLE_NATIVE_BATCH_COMPLETE" &&
    batch.dockerLoadAuthorized === false && batch.deployAuthorized === false &&
    COMMIT.test(expected.sourceSha) && SHA.test(expected.manifestSha256) &&
    batch.sourceSha === expected.sourceSha);
  const runtime = verifyRole("runtime", batch.runtime, expected.runtime, expected.sourceSha);
  const migrator = verifyRole("migrator", batch.migrator, expected.migrator, expected.sourceSha);
  requireIt(runtime !== migrator && expected.runtime.archiveSha256 !== expected.migrator.archiveSha256);
  return Object.freeze({
    status: "DISPOSABLE_TWO_IMAGES_RECONCILED_NONAUTHORIZING",
    sourceSha: expected.sourceSha,
    manifestSha256: expected.manifestSha256,
    imageIds: Object.freeze([runtime, migrator]),
    dockerLoadAuthorized: false,
    deployAuthorized: false,
  });
}
