import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { checkServerIdentity } from "node:tls";
import {
  GENESIS_HEAD, GENESIS_RECEIPT, WITNESS_CAS_DOMAIN, WITNESS_READ_DOMAIN,
  independentWitnessOwnerCasSigningBytes, verifyIndependentWitnessCasReceipt,
  verifyIndependentWitnessHead,
} from "./offline-independent-witness-service.mjs";

const HEX64 = /^[0-9a-f]{64}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const nonce = () => randomBytes(32).toString("hex");
function refuse(why) { throw new Error(`Remote witness refused: ${why}`); }

function validateConfig(config) {
  if (!config || !/^[\w.:-]+$/u.test(config.hostname ?? "") ||
      !Number.isSafeInteger(config.port) || config.port < 1 || config.port > 65535 ||
      !HEX64.test(config.serverCertSha256) || !HEX64.test(config.pinSha256) ||
      !HEX64.test(config.ownerPinSha256) || !HEX64.test(config.hostIdentitySha256) ||
      !HEX64.test(config.ledgerIdSha256) || config.pinSha256 === config.ownerPinSha256 ||
      !config.key || !config.cert || !config.ca || !config.publicKeyPem || !config.ownerPublicKeyPem) {
    refuse("incomplete pinned TLS, witness, owner or scope configuration");
  }
  const signer = createPublicKey(config.publicKeyPem);
  const owner = createPublicKey(config.ownerPublicKeyPem);
  if (signer.asymmetricKeyType !== "ed25519" || owner.asymmetricKeyType !== "ed25519" ||
      sha256(signer.export({ format: "der", type: "spki" })) !== config.pinSha256 ||
      sha256(owner.export({ format: "der", type: "spki" })) !== config.ownerPinSha256) {
    refuse("witness or owner public key pin mismatch");
  }
}

async function exchange(config, endpoint, message) {
  const body = JSON.stringify(message);
  if (Buffer.byteLength(body) > 4096) refuse("oversized request");
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      hostname: config.hostname, port: config.port, method: "POST", path: endpoint,
      agent: false, minVersion: "TLSv1.3", rejectUnauthorized: true,
      ca: config.ca, key: config.key, cert: config.cert,
      checkServerIdentity: (host, cert) => {
        const error = checkServerIdentity(host, cert);
        if (error) return error;
        if (!cert.raw || sha256(cert.raw) !== config.serverCertSha256) {
          return new Error("remote witness server certificate pin mismatch");
        }
        return undefined;
      },
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
    }, (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        text += chunk;
        if (Buffer.byteLength(text) > 16384) response.destroy(new Error("oversized witness response"));
      });
      response.once("error", reject);
      response.once("end", () => {
        try {
          const data = JSON.parse(text);
          if (JSON.stringify(data) !== text) refuse("noncanonical response");
          if (response.statusCode !== (endpoint === "/v1/cas" ? 201 : 200)) {
            refuse(`HTTP ${response.statusCode}: ${data.error ?? "unknown error"}`);
          }
          if (!data || Object.keys(data).sort().join(",") !==
            ["status", "witnessCasAuthorized", "dockerLoadAuthorized", "deployAuthorized", "receipt"].sort().join(",") ||
            data.status !== "INDEPENDENT_WITNESS_RECEIPT" ||
            data.witnessCasAuthorized !== false || data.dockerLoadAuthorized !== false ||
            data.deployAuthorized !== false) refuse("invalid receipt envelope");
          resolve(data.receipt);
        } catch (error) { reject(error); }
      });
    });
    request.setTimeout(5000, () => request.destroy(new Error("remote witness request timeout")));
    request.once("error", reject);
    request.end(body);
  });
}

// The caller must supply an independently held exact floor. Without prior state,
// pass 0 + GENESIS_RECEIPT explicitly, acknowledging the first trust bootstrap.
export async function remoteWitnessHead(config, { minimumSequence, expectedHeadSha,
  minimumReceiptSha256 } = {}) {
  validateConfig(config);
  if (!Number.isSafeInteger(minimumSequence) || minimumSequence < 0 || !HEX40.test(expectedHeadSha) ||
      !HEX64.test(minimumReceiptSha256)) {
    refuse("independently held sequence, head and receipt pins required");
  }
  const request = {
    version: 1, domain: WITNESS_READ_DOMAIN, challenge: nonce(),
    hostIdentitySha256: config.hostIdentitySha256, ledgerIdSha256: config.ledgerIdSha256,
  };
  const receipt = await exchange(config, "/v1/head", request);
  const verified = verifyIndependentWitnessHead({ receipt, request, publicKeyPem: config.publicKeyPem,
    pinSha256: config.pinSha256, minimumSequence, minimumReceiptSha256 });
  if (verified.sequence !== minimumSequence || verified.headSha !== expectedHeadSha) {
    refuse("head differs from independently held exact floor");
  }
  return Object.freeze({ ...verified, signedReceipt: receipt });
}

export async function remoteWitnessCas(config, proposal) {
  validateConfig(config);
  if (!proposal || !Number.isSafeInteger(proposal.expectedSequence) || proposal.expectedSequence < 0 ||
      !HEX40.test(proposal.expectedHeadSha) || !HEX40.test(proposal.nextHeadSha) ||
      !HEX64.test(proposal.expectedReceiptSha256) || !HEX64.test(proposal.transitionSha256)) {
    refuse("invalid independently held predecessor or proposed transition");
  }
  if (!config.ownerPrivateKeyPem) refuse("client-side owner private key required");
  const ownerPrivate = createPrivateKey(config.ownerPrivateKeyPem);
  if (ownerPrivate.asymmetricKeyType !== "ed25519" ||
      sha256(createPublicKey(ownerPrivate).export({ type: "spki", format: "der" })) !== config.ownerPinSha256) {
    refuse("owner private key pin mismatch");
  }
  const request = {
    version: 1, domain: WITNESS_CAS_DOMAIN, challenge: nonce(), requestId: nonce(),
    hostIdentitySha256: config.hostIdentitySha256, ledgerIdSha256: config.ledgerIdSha256,
    expectedSequence: proposal.expectedSequence, expectedHeadSha: proposal.expectedHeadSha,
    expectedReceiptSha256: proposal.expectedReceiptSha256,
    nextHeadSha: proposal.nextHeadSha, transitionSha256: proposal.transitionSha256,
    ownerExpiresAt: Math.floor(Date.now() / 1000) + 20,
  };
  const signed = { ...request, ownerSignature: sign(null,
    independentWitnessOwnerCasSigningBytes(request), ownerPrivate).toString("base64") };
  const receipt = await exchange(config, "/v1/cas", signed);
  const verified = verifyIndependentWitnessCasReceipt({ receipt, request: signed,
    publicKeyPem: config.publicKeyPem, pinSha256: config.pinSha256,
    ownerPublicKeyPem: config.ownerPublicKeyPem, ownerPinSha256: config.ownerPinSha256 });
  return Object.freeze({ ...verified, signedReceipt: receipt });
}

export { GENESIS_HEAD, GENESIS_RECEIPT };
