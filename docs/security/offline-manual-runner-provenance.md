# Independent manual runner provenance preview

Manual local CI reports and Semgrep JSON reports are **claims**, even when they
contain all 19 expected stages, plausible timestamps, zero findings and SHA-256
digests. These files alone cannot establish execution, CodeQL success or hosted
CI. The normal hosted GitHub Actions/CodeQL/GHCR release lane is unchanged.

`scripts/offline-manual-runner-provenance.mjs` is an explicit, fail-closed
inspection entrypoint for an *independent, owner-installed Linux verifier*:

```text
node scripts/offline-manual-runner-provenance.mjs \
  --revision <exact-main-commit-sha> \
  --ci-manifest /private/run-manifest.json \
  --scanner-report /private/semgrep-report.json \
  --attestation /private/independent-runner-attestation.json \
  --ci-console /private/full-ci-stdout.log \
  --scanner-console /private/full-scanner-stdout.log
```

The verifier loads its *only* trust anchor from
`/etc/virki/manual-runner-trust.json`. It requires a root-owned Linux process,
protected root-owned `/etc/virki`, and a root-owned regular single-link 0600
policy file. The path and key cannot be selected through command arguments or
the submitted release bundle. The installed JSON policy is canonical compact
JSON with exactly these fields: `version` (1), `keyId` (SHA-256 of DER SPKI),
`runnerId`, `runnerExecutableSha256`, `runnerLauncherSha256`,
`scannerExecutableSha256`, `scannerRulesCommit` and `publicKeySpkiBase64`
(Ed25519 SPKI DER). Policy bytes and file identity are checked before/after
reading. **No trust key or purportedly successful attestation is provisioned by
this repository.**

The canonical compact JSON attestation envelope has `statement` and
`signatureBase64`. The Ed25519 signature covers the UTF-8 bytes of
`"virki:manual-independent-runner:v1\0"` followed by `JSON.stringify(statement)`.
The statement includes version 1, kind
`VIRKI_INDEPENDENT_MANUAL_RUNNER_V1`, exact source SHA/branch, the SHA-256 of
the original CI and Semgrep report bytes, the pinned identities above, both
observed child process outcomes (`exitCode`, `timedOut`, `truncated`,
`spawnError`, `stdoutSha256`, `capturedBytes`) and the ordered 19 observed stage
results (`name`, `exitCode`). The verifier also hashes and checks each raw full
process console against the signed observation. Each process and stage must
have exited zero without timeout, truncation or spawn error.

The **independent runner must sign only after independently pinning and checking
the executable/launcher/scanner bytes and observing actual child results**.
No independently installed signer, protected identity or captured production
run is available in this worktree. The unit tests exercise cryptographic
bindings with disposable keys solely as test fixtures; they do **not** install
an operational trust anchor. Operational outcome is therefore **NO_GO** until
the owner installs an independent signer/verifier and supplies real evidence.
Even a verified manual receipt is explicitly `LOCAL_ONLY`; it does not attest
CodeQL, hosted CI, GHCR, production execution or deployment authorization.
