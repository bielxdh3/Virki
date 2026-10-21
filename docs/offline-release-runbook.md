# Virki offline release — operator preparation (NOT AUTHORIZED)

**Status: implementation foundation only, NOT an enabled production deployment workflow.**
The ordinary GitHub/CodeQL/GHCR deployment path remains unchanged. A successful
local test run or a GitHub PR marked *mergeable* must never be represented as
hosted CodeQL approval or as permission to deploy.

## Boundaries and exact release identity

- Use a clean named `main` checkout with `HEAD == refs/remotes/origin/main`
  and record its full 40-character SHA. Worktrees stay below
  `E:\Virki\.worktrees` on the development computer.
- Run the exact-SHA isolated 19-stage CI with Node 22. A 22/22 E2E result in
  one run does not erase another run's failure; preserve all failures and the
  original run manifest. `validateOfflineCiEvidence` checks report shape, **not
  independently authenticated execution**.
- Run Semgrep OSS separately, preserve its raw report and explicit per-finding
  dispositions. CodeQL is **NOT_RUN**; Semgrep is **not equivalent to CodeQL**.
  A replacement of assurance requires separate, explicit owner acceptance.
- Build runtime and migrator locally from the **same accepted `main` SHA**
  using the pinned Dockerfile, with `linux/amd64`, read-only non-root runtime,
  OCI source/revision labels and no GHCR pull or publication. Test both images,
  keep real raw smoke logs and their exact hash-bound JSON receipts.
- Prepare the **unsigned** candidate using
  `node scripts/offline-release-build.mjs --request <private-absolute-request.json>`.
  The request must refer only to existing real evidence: source SHA, independent
  host identity, predecessor, sequence, scanner rules, CI, smoke and disposable
  backup-restore. The builder does not run those checks for the operator and
  does not attest they occurred. It leaves a 10-file candidate, not an approved
  release.
- A separately protected builder key and distinct owner key must each sign the
  exact canonical manifest. The owner must independently inspect and affirm its
  SHA-256 digest and explicitly accept the reduced offline assurance. Do not
  generate owner signatures from the candidate, commit private keys or install
  keys on the server using code supplied in an unverified TAR. The owner-signed
  candidate contains **exactly 11 files**: `manifest.json`, `signatures.json`,
  `source.tar`, `runtime.tar`, `migrator.tar`, `ci-report.json`,
  `scanner-report.json`, `finding-review.json`, `runtime-smoke.json`,
  `migrator-smoke.json`, `backup-restore.json`.

## Host trust and stop conditions

1. Independent, root-owned, already-installed native Linux/amd64 verifier;
   **v2 trust policy** and revocations in `/etc/virki/offline-release`, durable replay
   ledger in `/var/lib/virki/offline-release`. Both `revokedKeyIds` and
   `revokedPinsSha256` must be independently synchronized with the owner's
   revocation decisions; merely revoking a signer ID on a development PC does
   not revoke its host-pinned key. The old pin-only v1 policy fails closed.
   **No installer or trust root may
   originate from a candidate archive.** WSL is not an acceptable target.
2. Verify host identity, independent builder/owner Ed25519 key pins, explicit
   owner assurance flag, revocations, predecessor, sequence, validity window,
   source/archive/report digests, OCI layer/config identities, full source Git
   blob correspondence and trusted provenance of scanner/CI reports.
3. Authenticate the **same immutable bytes at their use point**. Do not feed a
   path back to `docker load` after verification if the path could be replaced.
   Verify loaded image ID, revision/source labels, architecture and nonroot user
   before tagging expected private image aliases.
4. Reserve the accepted nonce/sequence in a crash-durable *attempted* state.
   Hold the operation boundary until protected backup+disposable restore,
   migration, application health, Cloudflare and rollback checks finish.
   After a crash, manual reconciliation is required; never delete a lock to
   silently retry or mark an interrupted release completed.
5. The production host requires a separately measured disk budget. The
   conservative estimator retains **4 GiB after** full staged archives, two
   copies of expanded Docker images, and 3x database footprint plus 512 MiB.
   Image/DB sizes must be measured on the target host, not asserted by the
   uploaded bundle. Preserve old release, database, volumes, Cloudflare Tunnel
   and **every deManage service and data resource**.
6. Existing `scripts/deploy-production.mjs` and
   `scripts/production-server.sh` **do not implement this offline protocol**:
   they require hosted CodeQL/GHCR and the latter assumes `ci=success`.
   Piping their unverified source script to `bash` is expressly forbidden for
   offline release. No deployed marker may claim hosted CI success.

## Evidence and disposition

Before approval, retain the exact final SHA, `run-manifest.json` with all
19/19 stages, complete scanner/finding-review report, runtime and migrator
image IDs and hashes, real disposable restoration report, host-preflight and
free disk measurements, owner-approved manifest SHA-256, key IDs, policy
revision and rollback procedure. Private credentials, raw database content,
recovery factors or email payloads must not appear in logs or PR comments.

**Current release gate: BLOCKED.** The native installed trust policy, owner
approval/signature, trusted image-loading/application path and source/host
verification must be completed before any production mutation. Until that is
true, operators may inspect and test offline artifacts locally only.
