import assert from "node:assert/strict";
import test from "node:test";
import {
  coordinateTrustedManualOfflineRelease,
  verifyCheckedManualCoordinatorJoin,
} from "./trusted-release-coordinator.mjs";

const SHA = "a".repeat(40);
const ARCHIVE = "b".repeat(64);
const DIGEST = "c".repeat(64);
const SIGNATURE = Buffer.alloc(64, 7).toString("base64");

function checkedEvidence() {
  return {
    manual: {
      status: "OWNER_MANUAL_SOURCE_INSPECTED_RELEASE_BLOCKED",
      deployAuthorized: false, sourceSha: SHA, archiveSha256: ARCHIVE,
      ciSourceBranch: "approved-source", sequence: 7,
      expiresAt: 1800000000, approvalSha256: "d".repeat(64),
    },
    signed: {
      status: "INSPECTED_ONLY_RELEASE_BLOCKED", deployAuthorized: false,
      sourceSha: SHA, verifiedManifestSha256: DIGEST,
      checkedImageRoles: ["runtime", "migrator"],
    },
    inspected: {
      manifestDigest: DIGEST,
      expected: { sourceSha: SHA, sourceArchiveSha256: ARCHIVE, lastSequence: 6 },
    },
    manifest: { source_sha: SHA, sequence: 7 },
  };
}

test("manual coordinator join requires separately checked exact source, manifest, images and sequence", () => {
  assert.equal(verifyCheckedManualCoordinatorJoin(checkedEvidence()), true);
  for (const mutate of [
    (v) => { v.manual.status = "OWNER_MANUAL_SOURCE_PREVIEW_ONLY"; },
    (v) => { v.manual.deployAuthorized = true; },
    (v) => { v.manual.sourceSha = "d".repeat(40); },
    (v) => { v.manual.archiveSha256 = "e".repeat(64); },
    (v) => { v.manual.ciSourceBranch = "main"; },
    (v) => { v.manual.sequence = 8; },
    (v) => { v.manual.approvalSha256 = "invalid"; },
    (v) => { v.manual.expiresAt = NaN; },
    (v) => { v.signed.sourceSha = "d".repeat(40); },
    (v) => { v.signed.deployAuthorized = true; },
    (v) => { v.signed.verifiedManifestSha256 = "f".repeat(64); },
    (v) => { v.signed.checkedImageRoles = ["runtime", "runtime"]; },
    (v) => { v.inspected.expected.lastSequence = 7; },
    (v) => { v.manifest.sequence = 8; },
    (v) => { v.manifest.source_sha = "f".repeat(40); },
  ]) {
    const data = checkedEvidence();
    mutate(data);
    assert.throws(() => verifyCheckedManualCoordinatorJoin(data), /blocked/u);
  }
  assert.throws(() => verifyCheckedManualCoordinatorJoin({ ...checkedEvidence(),
    manual: { ...checkedEvidence().manual, checkedOwnerSignature: SIGNATURE },
  }), /blocked/u, "manual verifier results cannot silently grow a caller approval");
});

test("manual installed coordinator accepts no caller trust policy and blocks uninstalled/WSL use", async () => {
  assert.deepEqual(await coordinateTrustedManualOfflineRelease({
    candidateDirectory: "/tmp/invalid", ownerKeyPem: "attacker",
  }), { status: "blocked", deployAuthorized: false });
  assert.deepEqual(await coordinateTrustedManualOfflineRelease({
    candidateDirectory: "/tmp/invalid",
  }), { status: "blocked", deployAuthorized: false });
});
