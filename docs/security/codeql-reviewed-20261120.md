# CodeQL review — exact historical main PUSH findings (2026-11-20)

## Scope and provenance

This note covers only two findings in the JavaScript/TypeScript SARIF emitted by hosted CodeQL run `44688261830` for main SHA `669e897d0adf3d0457d18ff680b7cf2123a2885d`. The retrieved local artifact was `E:\Temp\virki-codeql-main-44688261830\javascript.sarif`, SHA-256 `a3dd05e5c9557495963f946f5d5bb70df6bff3f8ef9dd0245f29f8ab8379137d`.

The scanner completed and emitted 55 results. The repository SARIF policy then failed closed: 53 results matched existing exact dispositions and two results were unreviewed. This is a policy failure after scanner completion, not a failed scanner and not a hosted CodeQL success for any later SHA.

## Exact findings

Both findings use `js/shell-command-injection-from-environment` (warning; security severity 6.3; CWE-78/CWE-88) in `scripts/staging-runbook-lifecycle.test.mjs`:

| Source location | Exact SARIF identity |
| --- | --- |
| `:403` | `js/shell-command-injection-from-environment|scripts/staging-runbook-lifecycle.test.mjs|2d350a82d76eabf3:1|15` |
| `:623` | `js/shell-command-injection-from-environment|scripts/staging-runbook-lifecycle.test.mjs|fbff554d652a47c5:1|15` |

The SARIF code flows point from `process.execPath` into a JavaScript template string and then into the source string passed to `spawnSync(bash, ["-c", ...])`. The test harness extracts shell helpers from the staging runbook and uses the exact absolute path of the Node executable that is running the test. These are test-only paths, not production request handlers or production runbook inputs. However, interpolating an absolute path into shell source is a real quoting boundary: shell metacharacters in an unusual or attacker-controlled runtime installation path could be interpreted. The finding is therefore not dismissed merely because it occurs in a test.

## Source hardening

The test harness was changed to preserve the exact current Node executable without interpolating it into shell source or passing the absolute path in shell command arguments:

- The shell source reads `node_bin` from standard input with `IFS= read -r -d ''`, using NUL as the delimiter.
- `process.execPath` (or the metacharacter-bearing symlink path in the adversarial test) is sent as NUL-terminated stdin data, not shell source, an environment override, or a command argument.
- Bash receives a fixed dummy `$0` plus only helper-specific positional values (the two IPs where applicable); the extracted helper invokes the exact path read from stdin.
- The same pattern is used by both affected test paths. It does not fall back to PATH lookup or a generic `node` command.
- Linux-only regressions create symlinks whose paths contain literal `$(touch${IFS}...)` command-substitution payloads, pass them as NUL-delimited stdin data through both affected shell-helper paths, execute the exact symlinked Node binary, and assert that the marker file was not created.

This change removes the shell-source interpolation while retaining the same absolute Node binary. It does not modify the staging runbook's production instructions or authorize staging activity.

## Narrow historical dispositions

The two exact identities above are admitted at a maximum count of one each only when the raw SARIF file bytes have SHA-256 `a3dd05e5c9557495963f946f5d5bb70df6bff3f8ef9dd0245f29f8ab8379137d`, the exact digest of the original `javascript.sarif` artifact. The CLI and production-CI evidence path compute this digest from the file bytes before evaluation. An artifact with different raw bytes (and therefore a different SHA-256) remains unreviewed even if it repeats the same finding fingerprints; an exact byte-for-byte copy is content-identical and has the same digest. These two dispositions do not accept changed rule/path/fingerprint/column values or duplicates. They do not add any new acceptance for `infra/offline/native-supervisor`; the distinct post-fix FD-pinned residual retains its separate pre-existing exact disposition.

The original CID pathname-read race remains unaccepted. In particular, `js/file-system-race|infra/offline/native-supervisor/run-disposable-fd-lifecycle-test.mjs|bc6600c95727700f:1|11` remains rejected; the post-fix FD-pinned residual has its separate exact disposition and does not replace the original vulnerable identity.

## Validation and remaining gate

- Re-evaluate the original SARIF after adding only these two exact one-count identities, bound to its raw-byte SHA-256; observed result: `55 total / 55 accepted / 0 violations`.
- Confirm a different SARIF artifact with the same two fingerprints is rejected, including when it has the same source metadata but different bytes, through both the policy evaluator and exact-SHA production-CI verifier.
- Policy unit tests: `node --test scripts/codeql-sarif-policy.test.mjs` — 32/32 PASS, including changed-fingerprint, missing-fingerprint, duplicate-count and original CID path-race rejection cases.
- Exact-SHA production-CI tests: `node --test scripts/production-ci.test.mjs` — 25/25 PASS, including rejection of the two historical fingerprints when supplied by different SARIF bytes.
- Affected staging-runbook lifecycle test on Linux/Node 22: 23 PASS, 0 FAIL, 1 SKIP because `jq` is unavailable in the offline WSL environment; the metacharacter-path regression passed.
- `npm run lint`, `node --check` on changed JavaScript modules, and `git diff --check`: PASS.
- Run hosted CodeQL on the resulting published child SHA. A local historical SARIF policy pass does not retroactively change run `44688261830` and is not a hosted CodeQL pass for the new SHA.

No merge, deploy, cutover, production activation, Cloudflare/TLS change, credential change, issue #90 change, or PR #133 change is authorized by this review.

Independent read-only review of the two exact dispositions and source hardening completed with a scoped GO and no confirmed P1/P2 implementation finding. The reviewer confirmed the raw-byte hashing and CLI/production-CI wiring, but did not execute tests. The production-CI regression test for same fingerprints with different bytes was added after that review and was validated locally; this does not replace hosted CodeQL on a newly published SHA.
