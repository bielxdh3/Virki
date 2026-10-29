# Manual CodeQL CLI diagnostic (W53, local evidence only)

`node scripts/manual-codeql-cli-diagnostic.mjs` inspects **one fixed local CodeQL CLI diagnostic**. It does not accept arguments, alternate paths, environment overrides, reviewer decisions, or new trust pins. It does not contact GitHub, run CodeQL, modify original evidence, or authorize a deployment. Exit code `1` means the diagnostic was read but release remains `NO_GO`; `2` means the input is invalid or unavailable.

The independently recorded W50 sample has two hard-coded, source-reviewed identities in `scripts/lib/manual-codeql-cli-diagnostic.mjs`:

- Original detached Git source commit: `c3ea768956bc3522363b725c138086a3c3e1c399`.
- Local CodeQL 2.27.3 SARIF SHA-256: `af395b6840d587ed423c121c7a9310bc30ab55dad17e45b68be4b32281c40c76`.

The CLI reads the original SARIF from its **fixed sibling** W50 scratch path. The archived digest and source SHA are code-owned diagnostic reference pins, not independent execution provenance. A checkout can change after scanning, and its current identity cannot attest to the files analyzed by CodeQL. The `sourceCheckoutMatchesPin` field is intentionally always `false`, with an explicit `PINNED_SOURCE_CHECKOUT_UNVERIFIED` blocker. This prevents a misleading clean-checkout assertion.

The diagnostic does **not** execute Git or any native subprocess. An earlier candidate used `git status` on the archived worktree; even an absolute pinned Git executable with isolated environment can execute arbitrary filters from repository-local `.git/config` and tracked `.gitattributes`. It was rejected in independent review and removed. The test suite now checks that attempts to intercept child-process execution never observe a native Git launch. Source provenance must come from a future independently trusted execution attestation, not this diagnostic.

The library checks the real CLI driver form (`name: CodeQL`, `organization: GitHub`, `semanticVersion: 2.27.3`), the CodeQL format/category, result-to-rule and artifact references, and original JS/TS extraction notices. It reports `72` unadjudicated results with `458/459` expected JS/TS files extracted. The missing file is the extensionless disposable JavaScript fixture `infra/offline/fixtures/fake-image-import-docker`.

`status: NO_GO` or `status: INVALID` **always** carries `gateDecision: NO_GO`, `authorizesRelease: false`, and `trustedScannerExecution: false`. Self-reported SARIF `executionSuccessful: true`, zero results, a forged extracted count, or a clean detached checkout cannot make this verifier succeed. No accepted-finding table exists. All alerts require normal independent security adjudication under the existing hosted workflow.

This is a separate diagnostic facility. Do not reuse it as a policy engine or change `scripts/codeql-sarif-policy.mjs` to accept the local sample. The hosted/main-only SARIF policy and its existing reviewed fingerprints remain authoritative for their own exact source/CI context; they are not altered by this diagnostic.

Run the isolated adversarial suite with `npm run test:offline:codeql-cli:diagnostic`. The test reads the original SARIF read-only when available and exercises forged driver formats, result counts, extraction claims, path traversal, artifact mismatches, disabled execution and caller-selected files. A missing original artifact means the real-artifact tests are skipped, never silently replaced by synthetic trusted evidence.
