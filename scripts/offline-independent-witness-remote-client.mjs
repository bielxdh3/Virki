import { readIndependentWitnessCredential } from "./lib/offline-independent-witness-service.mjs";
import { remoteWitnessCas, remoteWitnessHead } from "./lib/offline-independent-witness-remote-client.mjs";

// Operator-owned keys, certificate pins, and externally persisted floors are
// provided by the caller. The witness server never receives the owner key.
const env = process.env;
if (process.platform !== "linux") throw new Error("Native Linux remote witness client required");
const readEnvFile = (name) => {
  if (!env[name]) throw new Error(`missing ${name}`);
  return readIndependentWitnessCredential(env[name]);
};
const options = {
  hostname: env.VIRKI_WITNESS_CLIENT_SERVER_HOST,
  port: Number(env.VIRKI_WITNESS_CLIENT_SERVER_PORT),
  serverCertSha256: env.VIRKI_WITNESS_CLIENT_SERVER_CERT_SHA256,
  ca: readEnvFile("VIRKI_WITNESS_CLIENT_TLS_CA"),
  cert: readEnvFile("VIRKI_WITNESS_CLIENT_TLS_CERT"),
  key: readEnvFile("VIRKI_WITNESS_CLIENT_TLS_KEY"),
  publicKeyPem: readEnvFile("VIRKI_WITNESS_SIGNER_PUBLIC_KEY"),
  pinSha256: env.VIRKI_WITNESS_SIGNER_PIN,
  ownerPublicKeyPem: readEnvFile("VIRKI_WITNESS_OWNER_PUBLIC_KEY"),
  ownerPinSha256: env.VIRKI_WITNESS_OWNER_PIN,
  hostIdentitySha256: env.VIRKI_WITNESS_HOST_SHA256,
  ledgerIdSha256: env.VIRKI_WITNESS_LEDGER_SHA256,
};
const [command, ...args] = process.argv.slice(2);
let result;
if (command === "head" && args.length === 3) {
  const [sequence, expectedHeadSha, receiptSha256] = args;
  result = await remoteWitnessHead(options,
    { minimumSequence: Number(sequence), expectedHeadSha, minimumReceiptSha256: receiptSha256 });
} else if (command === "cas" && args.length === 5) {
  const [sequence, expectedHeadSha, expectedReceiptSha256, nextHeadSha, transitionSha256] = args;
  options.ownerPrivateKeyPem = readEnvFile("VIRKI_WITNESS_CLIENT_OWNER_SIGNER_KEY");
  result = await remoteWitnessCas(options, {
    expectedSequence: Number(sequence), expectedHeadSha, expectedReceiptSha256,
    nextHeadSha, transitionSha256,
  });
} else {
  throw new Error("usage: remote-client.mjs head <sequence> <headSha> <receiptSha256> | cas <sequence> <expectedHeadSha> <expectedReceiptSha256> <nextHeadSha> <transitionSha256>");
}
process.stdout.write(`${JSON.stringify(result)}\n`);
