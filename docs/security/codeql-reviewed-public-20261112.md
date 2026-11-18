# CodeQL public exact-SHA review — 2026-11-12

**Scope: two specific CodeQL findings only.** This ledger records independent
source review, not a staging, production, release, or merge approval.

## Authentic evidence and narrow policy

- [Public GitHub CodeQL run 43136441828, attempt 2](https://github.com/bielxdh3/Virki/actions/runs/43136441828), exact source SHA `261177e3b2bafbd0ebdfa65e0a054473d1236110`, CodeQL CLI 2.27.1, JavaScript/TypeScript `security-extended`. The hosted scan completed successfully; the *subsequent repository SARIF policy* rejected two unreviewed results among 48. The private-in-repository SARIF policy deliberately **failed closed**.
- Actual uploaded [SARIF artifact 13914650729](https://github.com/bielxdh3/Virki/actions/runs/43136441828/artifacts/13914650729), ZIP SHA-256 `b48caf536a150bc04fea82841b5c31842a04c0cac5144d1f85f0a3ac508ddb63` as reported by the uploader. The exact two identifiers below were read from that SARIF, not reconstructed from synthetic tests.
- Independent read-only source reviewer checked both control/data flows against the published SHA. No exploitable P1/P2 was demonstrated in the constrained, non-production roles below. This does **not** assert that all same-user filesystem races are impossible or replace formal security/release approval.
- Each disposition permits **only one occurrence** of the exact four-part `rule|relative path|line fingerprint|column fingerprint`; altered findings, extra counts, unreviewed rules and the historical vulnerable CID pathname race remain disallowed. This changes **no source scanning coverage, queries, or CodeQL configuration**, and is not a wildcard suppression.

## Independently adjudicated findings

| Rule and source | Exact SARIF identity | Attack invariant, limits and verdict |
| --- | --- | --- |
| `js/file-system-race` at `scripts/staging-otp-preflight.mjs:218` | `js/file-system-race|scripts/staging-otp-preflight.mjs|1a5be53b7e24b39c:1|5` | **SOURCE GO in its constrained offline use; no stage/release authority.** `readUnlinkedText` (205–235) validates absolute non-UNC paths and their parents; a leaf must be regular, singly linked (`nlink=1`) and size-bounded. On POSIX `openSync` uses `O_NOFOLLOW` and `O_NONBLOCK`, with pre-lstat versus pinned-FD fstat and post-FD/lstat checks, and an FD-only bounded read. Its payload is still rejected unless two **distinct caller-supplied** Ed25519 public keys validate the signed approval and observation at the expected source SHA (82–135); **their authenticity must be pinned out of band by the operator**, not by this tool. The result always declares `stagingAuthorization=NOT_GRANTED_BY_THIS_TOOL` and `release=NO_GO` (173–178). **Residual:** Windows Node 22 cannot guarantee an atomic nofollow parent chain; same-user writable directory/path swapping is not excluded. A future staging operator must use trusted private directories/ACLs, independent out-of-band public-key pins, and platform-specific review. A hostile same-user/path scenario beyond these assumptions must be fixed with stronger native FD/path anchoring rather than relying on this disposition. Existing tests `scripts/staging-otp-preflight.test.mjs:226–305` cover signed data, aliases, hardlinks and fail-closed errors, not an adversarial same-user race. |
| `js/user-controlled-bypass` at `scripts/integration/loopback-smtp-sink.mjs:159` | `js/user-controlled-bypass|scripts/integration/loopback-smtp-sink.mjs|a7bddb165db5ff66:1|4` | **SOURCE GO for disposable SMTP test receiver only.** A client controls which protocol command it sends (`AUTH PLAIN` versus `AUTH LOGIN`), **not** the `authorized` state. The receiver binds exclusively to `127.0.0.1` and synthetic `.invalid` mailboxes (29–41, 63–68, 195–203); the auth command is rejected before TLS and EHLO (138–159), and both AUTH branches call `checkAuth` comparing the exact randomly supplied username/password (87–92, 120–135, 158–165). `MAIL FROM` requires `authorized`, the recipient is fixed, and only one DATA message is accepted (166–174). `packages/auth/src/email-smtp-wire.integration.test.ts:101–128` physically rejects plaintext AUTH; its end-to-end worker test establishes STARTTLS/real login/OTP over **loopback only**. No external inbox or production SMTP relay is involved. |

## Required validation for this policy change

1. On the **parent SHA**, run the original fail-closed SARIF policy against the *actual* hosted artifact: it reports `48 total / 46 accepted / 2 unreviewed` and exits nonzero.
2. Test that precisely these two SARIF identities can be accepted *once*, but any changed rule, path, line hash, column fingerprint, missing fingerprint, duplicate, or the historically unsafe CID race still fails.
3. Run the policy against the **same unmodified real SARIF**, which must then report `48 / 48`, and run Node 22 policy tests plus all gates actually affected by this policy-only change.
4. Re-run actual licensed CodeQL **on the resulting public-repository child SHA** through hosted GitHub Actions before declaring the new CodeQL job green. A local historical SARIF acceptance alone is never a current-SHA hosted CodeQL pass.

Production and independent external staging remain **NO-GO** pending the actual hosted checks, segregated deployment/SMTP acceptance, independent operator and release approval.
