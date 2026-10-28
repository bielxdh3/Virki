import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import path from "node:path";
import { prepareVerifiedOfflineTransportPlan } from "./offline-production-transport.mjs";

export const offlineRepositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const NOT_READY = Object.freeze({
  status: "OFFLINE_NOT_READY", deployAuthorized: false, transferAuthorized: false,
});
const SHA = /^[a-f0-9]{40}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;

// Independent pre-transfer inspection only. No returned status grants deploy.
export async function runOfflineContingencyPreflight(input, { inspect = prepareVerifiedOfflineTransportPlan } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
    Object.keys(input).length !== 3 ||
    !["candidateDirectory", "trustedDirectory", "repositoryRoot"].every((key) =>
      typeof input[key] === "string" && input[key].length > 0 && input[key].length <= 4096)) {
    return NOT_READY;
  }
  try {
    const result = await inspect(input);
    if (!result || result.status !== "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED" ||
      result.deployAuthorized !== false || result.transferAuthorized !== false ||
      !SHA.test(result.revision) || !DIGEST.test(result.signedManifestSha256)) return NOT_READY;
    return Object.freeze({
      status: "OFFLINE_PRETRANSFER_INSPECTED_ONLY",
      revision: result.revision,
      signedManifestSha256: result.signedManifestSha256,
      deployAuthorized: false, transferAuthorized: false,
    });
  } catch {
    // Verification diagnostics may contain host paths or configuration data.
    return NOT_READY;
  }
}

const entry = fileURLToPath(import.meta.url);
const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
let invoked = false;
let canonicalInvocation = false;
try {
  const actualEntry = realpathSync.native(entry);
  const actualInvocation = invokedPath === null ? null : realpathSync.native(invokedPath);
  invoked = actualInvocation !== null && actualInvocation === actualEntry;
  canonicalInvocation = invoked && invokedPath === entry && invokedPath === actualInvocation;
} catch {
  // Imported libraries never become operator entrypoints from a missing path.
}
if (invoked) {
  const args = process.argv.slice(2);
  const valid = canonicalInvocation && args.length === 4 && args[0] === "--candidate" && args[2] === "--trust" &&
    args[1].length > 0 && args[3].length > 0;
  const result = await runOfflineContingencyPreflight({
    candidateDirectory: valid ? args[1] : "",
    trustedDirectory: valid ? args[3] : "",
    repositoryRoot: offlineRepositoryRoot,
  });
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exitCode = result.status === "OFFLINE_PRETRANSFER_INSPECTED_ONLY" ? 0 : 1;
}
