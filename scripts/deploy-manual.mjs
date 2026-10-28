import path from "node:path";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runOfflineContingencyPreflight } from "./offline-contingency-preflight.mjs";
import { stageLocalOfflineCandidate } from "./lib/offline-manual-staging.mjs";

// Operator entrypoint for the separately signed, GitHub-free manual lane.
// The current native host bootstrap/witness protocol cannot authorize remote
// transfer or release. This entrypoint stages REAL checked bytes locally,
// exposes exact blocking stages and NEVER invokes a remote mutating command.
const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const INPUTS = Object.freeze(["candidateDirectory", "trustedDirectory", "stagingParent", "repositoryRoot"]);

function invalid(status, phases = {}) {
  return Object.freeze({ status, phases, transferAuthorized: false, deployAuthorized: false });
}
function disjoint(a, b) {
  return a !== b && !a.startsWith(b + path.sep) && !b.startsWith(a + path.sep);
}
function canonical(value) {
  return typeof value === "string" && value.length > 1 && value.length <= 4096 &&
    path.isAbsolute(value) && path.normalize(value) === value &&
    value !== path.parse(value).root && !value.includes("\0");
}

export function sameSignedManualPretransfer(before, after) {
  const digest = /^[a-f0-9]{64}$/u;
  const source = /^[a-f0-9]{40}$/u;
  return before?.status === "OFFLINE_PRETRANSFER_INSPECTED_ONLY" &&
    after?.status === "OFFLINE_PRETRANSFER_INSPECTED_ONLY" &&
    before.deployAuthorized === false && after.deployAuthorized === false &&
    before.transferAuthorized === false && after.transferAuthorized === false &&
    source.test(before.revision) && before.revision === after.revision &&
    digest.test(before.signedManifestSha256) &&
    before.signedManifestSha256 === after.signedManifestSha256 &&
    digest.test(before.signedEnvelopeSha256) &&
    before.signedEnvelopeSha256 === after.signedEnvelopeSha256;
}

/**
 * Does not accept evidence, signer, SSH, witness, receipt, transport or shell
 * overrides. The existing native read-only preflight must verify owner/builder
 * signatures, protected operator pins, clean Git source, and pinned host checks
 * before locally re-copying the exact 11-file candidate with digest readback.
 * This is an operator preparation step and never authorizes host transport.
 */
export async function runManualOperator(request = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request) ||
    Object.keys(request).length !== INPUTS.length ||
    INPUTS.some((field) => !Object.hasOwn(request, field) || !canonical(request[field])) ||
    !disjoint(request.candidateDirectory, request.stagingParent) ||
    !disjoint(request.trustedDirectory, request.stagingParent) ||
    !disjoint(request.repositoryRoot, request.stagingParent) ||
    !disjoint(request.repositoryRoot, request.trustedDirectory) ||
    !disjoint(request.candidateDirectory, request.trustedDirectory)) {
    return invalid("MANUAL_OPERATOR_INPUT_REJECTED", { input: "REJECTED" });
  }
  const { candidateDirectory, trustedDirectory, repositoryRoot, stagingParent } = request;
  const before = await runOfflineContingencyPreflight({ candidateDirectory, trustedDirectory, repositoryRoot });
  if (before.status !== "OFFLINE_PRETRANSFER_INSPECTED_ONLY" ||
      before.transferAuthorized !== false || before.deployAuthorized !== false) {
    return invalid("MANUAL_PRETRANSFER_NOT_READY", {
      ownerSignatureAndPinnedHost: "NOT_VERIFIED", localStaging: "NOT_STARTED",
      remoteTransfer: "BLOCKED", release: "BLOCKED",
    });
  }
  try {
    const copy = await stageLocalOfflineCandidate({ candidateDirectory, stagingParent });
    if (copy.status !== "LOCAL_STAGING_BYTES_COPIED_UNTRUSTED" ||
        copy.fileCount !== 11 || copy.manifestSha256 !== before.signedManifestSha256 ||
        copy.transferAuthorized !== false || copy.deployAuthorized !== false) {
      return invalid("MANUAL_LOCAL_STAGING_FAILED", {
        ownerSignatureAndPinnedHost: "READ_ONLY_INSPECTED", localStaging: "FAILED",
        remoteTransfer: "BLOCKED", release: "BLOCKED",
      });
    }
    // P2: prior inspection authenticates *source* signatures, not the staged
    // envelope. Always re-run the complete independent owner/builder + host
    // preflight on the exact staged 11-file candidate, and bind the canonical
    // signature envelope SHA as well as the manifest before returning success.
    // The remote inspection is READ-ONLY. No result authorizes transfer.
    const postCopy = await runOfflineContingencyPreflight({
      candidateDirectory: copy.stagedDirectory, trustedDirectory, repositoryRoot,
    });
    if (!sameSignedManualPretransfer(before, postCopy)) {
      return Object.freeze({
        status: "MANUAL_POST_STAGE_SIGNATURE_RECHECK_FAILED",
        stagedDirectory: copy.stagedDirectory,
        phases: Object.freeze({
          ownerSignatureAndPinnedHost: "REINSPECTION_FAILED",
          localStaging: "OWNED_STAGE_RETAINED_FOR_RECONCILIATION",
          remoteTransfer: "BLOCKED", release: "BLOCKED",
        }),
        transferAuthorized: false, deployAuthorized: false,
      });
    }
    return Object.freeze({
      status: "MANUAL_LOCAL_STAGE_VERIFIED_REMOTE_BLOCKED",
      revision: before.revision,
      signedManifestSha256: before.signedManifestSha256,
      signedEnvelopeSha256: before.signedEnvelopeSha256,
      stagedDirectory: copy.stagedDirectory,
      phases: Object.freeze({
        ownerSignatureAndPinnedHost: "READ_ONLY_INSPECTED",
        localStaging: "ELEVEN_FILES_COPIED_AND_READ_BACK",
        trustedNativeBootstrap: "EXTERNAL_INSTALLATION_REQUIRED",
        independentMonotonicWitnessCas: "EXTERNAL_PROOF_REQUIRED",
        immutableImageImportAndSupervisor: "EXTERNAL_PROOF_REQUIRED",
        remoteTransfer: "BLOCKED",
        release: "BLOCKED",
      }),
      transferAuthorized: false,
      deployAuthorized: false,
    });
  } catch (error) {
    if (error?.code === "MANUAL_STAGE_AFTER_RENAME_UNCERTAIN") {
      return Object.freeze({
        status: "MANUAL_STAGING_SYNC_UNCERTAIN_RETAINED",
        stagedDirectory: error.stagedDirectory,
        phases: Object.freeze({
          localStaging: "OWNED_STAGE_RETAINED_FOR_RECONCILIATION",
          remoteTransfer: "BLOCKED", release: "BLOCKED",
        }),
        transferAuthorized: false, deployAuthorized: false,
      });
    }
    return invalid("MANUAL_LOCAL_STAGING_FAILED", {
      ownerSignatureAndPinnedHost: "READ_ONLY_INSPECTED", localStaging: "FAILED",
      remoteTransfer: "BLOCKED", release: "BLOCKED",
    });
  }
}

const executable = fileURLToPath(import.meta.url);
const invoked = process.argv[1] ? path.resolve(process.argv[1]) : null;
let isEntrypoint = false;
let isCanonical = false;
try {
  isEntrypoint = invoked !== null && realpathSync.native(invoked) === realpathSync.native(executable);
  isCanonical = isEntrypoint && invoked === executable && realpathSync.native(invoked) === invoked;
} catch { /* missing paths are never valid entrypoints */ }
if (isEntrypoint) {
  const args = process.argv.slice(2);
  const correct = isCanonical && args.length === 6 &&
    args[0] === "--candidate" && args[2] === "--trust" && args[4] === "--stage-parent";
  const result = correct ? await runManualOperator({
    candidateDirectory: args[1], trustedDirectory: args[3],
    stagingParent: args[5], repositoryRoot: repoRoot,
  }) : invalid("MANUAL_OPERATOR_INPUT_REJECTED", { input: "REJECTED" });
  process.stdout.write(JSON.stringify(result) + "\n");
  // This exit code is deliberately nonzero until the independent host trust,
  // monotonic external witness and protected native release path exist.
  process.exitCode = 2;
}
