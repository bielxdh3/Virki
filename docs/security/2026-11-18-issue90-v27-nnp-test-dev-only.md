# C1 V27 — ordinary NoNewPrivs regression portability (2026-11-18)

V27 addresses the native Codex P2 finding on PR #133 (discussion 4622385884). The launcher regression accepts either valid initial NoNewPrivs state, checks child behavior and preservation of the parent state, and distinguishes the baseline-zero evidence in a named subtest. It does not change the receiver or launcher implementation.

- Ordinary V24 suite on WSL: four regular tests PASS; opt-in privileged fixture SKIP. The baseline-zero subtest PASS (parent 0, child 1, parent remains 0).
- Ordinary launcher test under an already-hardened parent: PASS; only the baseline-zero measurement SKIP, explicitly identified.
- Incremental V27 patch SHA-256: `C273B310ED366C188030004CF416FB5B6020FC63CB073320C72FE8CF6EF877A7`.
- V26 input tree: `1b0ad7d10b0ef7413a2a72b6bdff5c8b90f51d2f`; V27 output tree: `932758801e6c0b47d3eceaef7aca96b1c5734e87`. Local apply, tree identity and reverse checks PASS.

Review the sequential V24–V27 patches together. V26 already implements real/effective/saved IDs, capability checks and private TMPDIR. The V27 test supports both initial NoNewPrivs states; the V26 baseline-zero result remains valid. The V23 prerequisite is now included. The GitHub CI manifest checks published patch integrity and static replay, not an end-to-end hosted BuildKit build. The independently provisioned directory-custody contract, descriptor/namespace and peer-identity assurance, and the remaining acceptance criterion of issue #90 are not certified by these ordinary tests. DEV-only, no merge or production activation.
