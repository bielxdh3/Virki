# Local release preparation without GitHub Actions

This is an operator-facing record of local **validation**, not production approval. The existing `OWNER_APPROVED_EXACT_SHA_CODEQL_SARIF_GATE` and the GitHub Actions/GHCR provenance checks remain unchanged and fail closed. A local green test run cannot be used as a substitute for a successful exact-SHA `push` CI/CodeQL run on `main`.

### Observed results

- On `b66881323b97b4d778208f4eb2263a07289f2264`, native `amd64` Docker production and migrator targets built successfully. Their local images reported the matching source/revision labels. The production dependency-boundary assertion, production HTTP/OIDC/runtime smoke and disposable PostgreSQL migrator smoke all exited successfully. No images were pushed to GHCR.
- The disposable `scripts/backup-restore-validation.mjs` run completed with exit code 0 in the local Docker-enabled workspace. This is not a proof that a production backup is restorable.
- On security-fix commit `eaafde581b25212cc641ec620e73cb0b8af6e2b8`, isolated Linux runner `e50272703b` completed **19/19 stages with `exitCode=0` and `failedStages=[]`** (Node `22.23.3`, npm `10.9.9`, Chromium 153; 22/22 authenticated browser E2E passed). Its ignored evidence is under `.virki-mission-tmp/isolated-runs/e50272703b/`.
- Three new GCM regression tests failed before the code change and passed after the change; the full directly affected set passed 37/37 on Node 22 with `NODE_ENV=test`. A subsequent targeted scan of the precise GCM Semgrep rule on the three patched sources reported zero findings. This targeted scan does not re-establish the original full 83-rule result.
- This report is a later documentation-only addition and does not retroactively make those OCI builds or scans results for a later SHA. Repeat exact-revision verification on any final release candidate.

## Environment and isolation

- Use the approved isolated Docker test runner with Node 22 and npm 10 for source tests and builds; the Windows host's Node 24/npm 11 is not the project test environment. Never use it to change the project dependency tree.
- Pin every locally built image to a full Git SHA. Use disposable databases, containers, and networks with distinct Virki names. Never use production credentials, remote SSH, the production operator config, or deManage resources in local validation.
- Save each runner's `run-manifest.json`, the scan rule commit and scan output, and image architecture, source/revision labels and image IDs. Make clear whether a command ran on the original SHA or on a subsequent commit.
- The production runtime image is separate from the migrator; verify the former runs unprivileged and contains neither Prisma CLI nor other forbidden tooling.

## Local static-analysis triage (2026-10-21)

The Semgrep OSS 1.181.0 scan used 83 community rules pinned at `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9`, and reported 15 findings across 344 analyzed files on original commit `b66881323b97b4d778208f4eb2263a07289f2264`:

| Findings | Review and disposition |
| --- | --- |
| 3 AES-GCM authentication tag lengths (`email.ts`, `oidc-secrets.ts`, `security.ts`) | **Confirmed weakness and fixed** in `fix(security): require full-length GCM authentication tags`. Under Node 22, each function accepted a correctly truncated 4-byte tag before the patch. All three regression tests were RED before and GREEN after; full 16-byte tags remain readable, including the OIDC previous-key rotation case. All three decryptors now require `{ authTagLength: 16 }`. Newly produced encrypted data already had full-length tags; there is no change to its wire format. This does not prove every stored record's integrity or close the separate deferred A20 finding. |
| 5 insecure HTTP requests in `e2e/jwks-service.spec.ts` | Test-only, loopback JWKS fixture URLs; not evidence of insecure transport in the deployed OIDC issuer. No production-code change warranted by these matches. |
| 4 dynamic `RegExp` constructions in `database-role-isolation.test.mjs`, `e2e/low05-diagnostics.mjs`, `production-compose.test.mjs`, `production-remote.test.mjs` | First, third and fourth are test/fixture code built from fixed function names or service identifiers. The LOW05 diagnostic interpolates fixed session cookie names after explicit regex escaping; the string being tested is untrusted, but not the compiled regex pattern. No directly attacker-controlled regex **pattern** demonstrated. |
| 1 suspected ReDoS in `scripts/lib/production-config.mjs` | Used for the operator-configured production root, not an HTTP request. The `(?:segment/)*segment` alternatives are separated by a slash, limiting overlap of repeated parts. No exploitable superlinear case has been established; no speculative allowlist or release-policy relaxation. |
| 2 `shell: true` calls in dependency/tooling audit scripts | Windows-only invocation of `npm.cmd`, with fixed audit/list argument arrays and no user-input arguments; developer-only audit tools, not request handlers. Retain as reviewed risk, not a confirmed remote command injection. |

Semgrep pattern findings and this source review are **not** equivalent to CodeQL `security-extended` or a generated CodeQL SARIF report. The Semgrep process originally exited zero without `--error`, so its exit code was not a zero-findings claim. A targeted rerun of the GCM rule is useful to confirm that the three former matches are gone; it is not a repeat of the full 83-rule scan.

## OCI and database release rehearsal

For each new candidate SHA, run and record the exact SHA/architecture of both `infra/Dockerfile.prod` targets, check OCI revision/source labels, then run `scripts/production-image-assertion.mjs`, `scripts/production-runtime-smoke.mjs`, and `scripts/production-migrator-smoke.mjs` against those images. Migrator smoke applies and checks committed migrations on a disposable PostgreSQL database. Exercise `scripts/backup-restore-validation.mjs` against its own disposable database: that proves the fixture path, **not** recovery of the server's actual backups. Run the complete 19-stage isolated Linux suite on the final source SHA, not merely an ancestor.

An amd64-only local image does not prove that arm64 image build or execution succeeds. Local Docker image IDs are not GHCR registry manifest digests. Do not publish local images, modify the accepted production pointer, or infer remote/Cloudflare/SMTP readiness from these smokes.

## Why release remains blocked and a safe alternative design

The current production trust chain requires successful **GitHub Actions** `push` runs of CI and CodeQL on the exact `main` SHA, a reviewed CodeQL SARIF policy, GitHub-run-log-anchored immutable private GHCR evidence, both runtime/migrator image digests, and owner approval. Billing prevented the latest workflow jobs from starting; it did not establish a source failure. The CodeQL CLI's published terms do not authorize ordinary analysis of this private codebase without an applicable commercial license. Do not run that CLI on the private repository under the open-source exception, and do not rename a Semgrep report as CodeQL output.

**No owner-approved replacement policy exists.** An offline release mode would require a separate, deliberate security design and explicit approval *before* any change to the acceptance gate. At minimum:

1. Generate an immutable manifest binding **full Git SHA**, clean source archive hash, source remote, target architecture, runtime/migrator image content digests, exact tooling versions, scanner/rules hash, raw test report hashes, reviewed finding decisions and expiry.
2. Sign the manifest using an independently protected, narrowly scoped **owner release-signing key**; pin its public key, expected manifest schema and algorithm on the native Linux host. Do not store the signing private key in Git, Docker images, a PR, the development runner, or a copied `.env`.
3. Require a separate human approval bound to the same manifest digest, enforce replay/downgrade protection and key revocation, and verify everything fail-closed **before** contacting production. A local signature by the developer alone is weaker than independent hosted-CI provenance; signing does not create independent evidence of a correct test run.
4. Keep private GHCR transport with digest-only deployment and minimum-privilege, separate publication/read credentials. Require native amd64 and arm64 build/test evidence for any supported dual-architecture release; do not call QEMU emulation native evidence.
5. Preserve disposable production-backup restore, first-ADMIN/rescue preconditions, SSH host pinning, maintenance/rollback, protected environment-file handling, and deManage isolation. Never automatically fall back from an unavailable gate to an unsigned local path.

This is an **architecture proposal, not a release mechanism**. Implementing it would change the existing owner-approved security boundary and requires separate design review, explicit owner policy approval, adversarial tests, and a staged host validation. Until then, release/preflight must continue refusing local-only evidence. The lower-risk immediate outcome is a fully tested PR with a clearly documented **external release blocker**, not an unverified deployment.

## Outstanding acceptance before any deployment

Confirm a clean merged `main` and its exact checks (or a separately approved and implemented policy); approved OCI digests and private GHCR package metadata; actual native Debian host identity and installation/first-ADMIN state; recent restorable backup and migration invariants; the live USER portal route, Cloudflare Access on the ADMIN host, SMTP, and safe rollback. The earlier `/srv/virki` observation is historical; it is not proof of present host state. Do not use the ordinary upgrade path before first ADMIN exists.
