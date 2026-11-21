# Issue #90 review package: complete V23–V32 source reconstruction

The cumulative V23 baseline is included from original local commit `d12eeaacf9358ed6e099c369c3f45fe1789507e8`. The previous local-only dependency is eliminated. No other part of the experimental branch history is included.

The only external source required for static reconstruction is the official BuildKit repository, pinned to `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`. The complete V23–V32 ten-patch chain is listed in `issue90-review-patches.sha256`, in application order. CI verifies hashes, reconstructs the exact Git trees in an isolated index, runs ordinary unprivileged Go regressions (including V32 same-UID ptrace and procfd refusal), and exercises the privileged synthetic multi-UID custody/race, executable-ownership and cross-UID downgrade-without-flag fixtures. See the V29–V32 supplements for the precise remaining production boundaries.

| Stage | Expected Git tree |
| --- | --- |
| V23 | `7eb9bfebb607c6795138b50d9bd9453b87c09b3d` |
| V24 | `d4b9e014f42deaa152bc7e3be3175080f1ddb271` |
| V25 | `b0bcf49bf41ece17080aeba5a4f218f0cb165fb1` |
| V26 | `1b0ad7d10b0ef7413a2a72b6bdff5c8b90f51d2f` |
| V27 | `932758801e6c0b47d3eceaef7aca96b1c5734e87` |
| V28 | `c7234b862c991a940c3047f05a6f2752d7fd1e6f` |
| V29 | `9607e2d13c28168f2f00a9370737b622b080ccc9` |
| V30 | `c8f6df12b47ef2540bf2553ac5a9ecc9ce892971` |
| V31 | `c8d30aca6c0df02cd49b5746d414194496fa72ff` |
| V32 | `fcecd3d1c3d9810bb3060310f822fcb7f6da5305` |

The last tree is the locally verified DEV source configuration. V30 fixes a helper pathname-to-exec swap through FD-pinned execution; V31 makes root-owner/immutable-ancestry checks **mandatory whenever root launches a distinct receiver UID**, even if the caller omits the optional policy flag. V32 additionally requires the independent receiver to become non-dumpable after exec, preventing a separate same-UID process from attaching via ptrace or reading its process FD links. The synthetic fixtures prove that a root-owned helper under a receiver-owned directory and a receiver-owned helper are refused; a trusted helper still runs. **This is not equivalent to eliminating a same-UID attacker who can edit the receiver-owned stage directory.** This package does not certify independently provisioned custody for an actual production lifetime, peer authentication of arbitrary transport endpoints, or production admission. The Linux multi-process fixture checks same-namespace rename/symlink/write/mount attempts from an independently unprivileged peer, but cannot prove every hostile mount configuration. The existing vet exception remains as recorded. Do not enable protected FileSync or deploy.

The CI toolchain is pinned to Go 1.26.10 for Linux amd64 and verified against SHA-256 ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5. Only vendored Go dependencies are used, with network module resolution and automatic toolchain download disabled. The already-hardened parent case is also exercised separately. Hosted results must be checked on the exact PR head.
