# Issue #90 review package: complete V23–V27 source reconstruction

The cumulative V23 baseline is included from original local commit `d12eeaacf9358ed6e099c369c3f45fe1789507e8`. The previous local-only dependency is eliminated. No other part of the experimental branch history is included.

The only external source required for static reconstruction is the official BuildKit repository, pinned to `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`. All five patch files are included in this review branch and listed in `issue90-review-patches.sha256`, in application order. CI verifies the hashes and reconstructs the exact Git trees in an isolated index without executing the experimental code.

| Stage | Expected Git tree |
| --- | --- |
| V23 | `7eb9bfebb607c6795138b50d9bd9453b87c09b3d` |
| V24 | `d4b9e014f42deaa152bc7e3be3175080f1ddb271` |
| V25 | `b0bcf49bf41ece17080aeba5a4f218f0cb165fb1` |
| V26 | `1b0ad7d10b0ef7413a2a72b6bdff5c8b90f51d2f` |
| V27 | `932758801e6c0b47d3eceaef7aca96b1c5734e87` |

The last tree is the locally verified DEV source configuration. This package does not certify peer identity, independently provisioned custody for the entire execution lifetime, or the outstanding adversarial acceptance criterion. The earlier local positive test results and vet exception remain as recorded. Hosted static replay is not a Go test execution. Do not merge, enable protected FileSync, or deploy.
