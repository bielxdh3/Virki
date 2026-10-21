import { createHash, sign } from "node:crypto";
import { encodeCanonicalOfflineReleaseManifest } from "./offline-release-attestation.mjs";

// Manual, offline-only cryptographic primitive. These helpers neither read
// private keys from disk nor decide that release evidence is acceptable.
// The builder and release owner must invoke them in separate trust contexts.
const BUILDER_DOMAIN = Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0", "utf8");
const OWNER_DOMAIN = Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0", "utf8");
const SHA256 = /^[0-9a-f]{64}$/u;

function ensureCanonicalBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 8192) {
    throw new Error("Offline signing refused noncanonical or oversized manifest bytes.");
  }
  const input = Buffer.from(bytes);
  let document;
  try {
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input));
  } catch {
    throw new Error("Offline signing refused invalid UTF-8 or JSON.");
  }
  if (!encodeCanonicalOfflineReleaseManifest(document).equals(input)) {
    throw new Error("Offline signing refused noncanonical manifest bytes.");
  }
  return input;
}

function requirePrivateEd25519(key) {
  // The caller owns key custody. Never log or stringify key material.
  if (!key || typeof key !== "object" || key.type !== "private" ||
      key.asymmetricKeyType !== "ed25519") {
    throw new Error("Offline signing requires an independently protected Ed25519 private key.");
  }
  return key;
}

export function signOfflineBuilderManifest({ manifestBytes, builderPrivateKey } = {}) {
  const bytes = ensureCanonicalBytes(manifestBytes);
  const key = requirePrivateEd25519(builderPrivateKey);
  return Object.freeze({
    manifestSha256: createHash("sha256").update(bytes).digest("hex"),
    builderSignatureBase64: sign(null, Buffer.concat([BUILDER_DOMAIN, bytes]), key).toString("base64"),
  });
}

/**
 * Owner must independently inspect evidence and supply the exact reviewed
 * 64-character digest. This primitive checks digest equality; it is not a
 * reviewer, a key manager, an approval policy or a release gate.
 */
export function signOfflineOwnerApproval({ manifestBytes, reviewedManifestSha256, ownerPrivateKey } = {}) {
  const bytes = ensureCanonicalBytes(manifestBytes);
  const observed = createHash("sha256").update(bytes).digest();
  if (typeof reviewedManifestSha256 !== "string" || !SHA256.test(reviewedManifestSha256) ||
      reviewedManifestSha256 !== observed.toString("hex")) {
    throw new Error("Owner has not provided the exact independently reviewed manifest SHA-256.");
  }
  const key = requirePrivateEd25519(ownerPrivateKey);
  return Object.freeze({
    manifestSha256: observed.toString("hex"),
    ownerSignatureBase64: sign(null, Buffer.concat([OWNER_DOMAIN, observed]), key).toString("base64"),
  });
}
