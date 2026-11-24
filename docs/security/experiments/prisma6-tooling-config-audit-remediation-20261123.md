# Prisma 6 tooling advisory remediation — 2026-11-23

Scope: dependency tooling only. This does not authorize merging the Virki security stack or deploying production.

The pinned Prisma CLI and client are 6.19.3. The official `@prisma/config@6.19.3` manifest requires exact `deepmerge-ts@7.1.5` and `effect@3.21.0`. npm audit reported five high-severity transitive entries originating in:

- GHSA-ggr8-5vv4-36mx (`deepmerge-ts`, fixed in 8.x).
- GHSA-7589-6fvf-x4pw (`effect`, fixed above 3.22.0).

Changing npm `overrides` without changing those exact package contracts caused `npm ls` to reject the dependency tree. Merely upgrading the CLI to Prisma 7.10.1 was not a valid remediation: its `@prisma/config` still pinned vulnerable `effect@3.20.0`, and it changes the database client architecture.

This branch keeps Prisma CLI and Client 6.19.3 and locally includes the Apache-2.0 licensed, prebuilt `@prisma/config@6.19.3` from the official npm distribution in `vendor/prisma-config-6.19.3/`. Its executable `dist/index.js` is byte-identical to the upstream npm package, SHA-256:

`92e63036b4da306abcb5fa4cfaa3a5b87508268e4f773f2b7638a061bf500a64`

The **only functional manifest changes** are the exact runtime dependency declarations `deepmerge-ts@8.0.2` and `effect@3.22.5`. Unused upstream development/build/test dependencies and scripts are omitted from this prebuilt local package; they were found to bring additional vulnerable Vitest/Tinypool packages into the npm audit because npm installs development dependencies of linked packages. Name/version, Apache license, authored JavaScript and TypeScript declarations are preserved. The root uses a direct `file:vendor/prisma-config-6.19.3` development dependency, with **no invalid overrides**, so `npm ls` must pass. The Docker build stages explicitly copy the local package before `npm ci`, and `.dockerignore` preserves only its required distribution subtree.

Security controls are unchanged: `scripts/tooling-audit-policy.mjs` still requires a real online full-tree npm audit with zero vulnerabilities (apart from a pre-existing, strictly bounded, separately documented picomatch exception); failed registry access fails closed; production-only audits remain mandatory; and installed Prisma versions remain pinned. A regression test verifies the original JavaScript digest, license, patched dependencies, absence of unused test scripts, valid lockfile links and Docker context.

**Evidence before Build Ready:** `npm ci`, `npm ls --all`, full live tooling audit, production-only audit, Prisma generation/validation, typecheck, lint, builds, relevant tests and hosted CI must succeed on the exact commit. Even if they all pass, issue #90 still needs authorized production ownership/C4 proof and issue #119 still needs post-deployment live HTTP/browser evidence; both issues remain OPEN and production remains NO-GO.

## Focused runtime compatibility gate — 2026-11-23

`scripts/prisma6-config-runtime-compat.test.mjs` exercises the actual linked `@prisma/config@6.19.3` package with the remediated `effect@3.22.5` and `deepmerge-ts@8.0.2`, not only the lockfile. A disposable `prisma.config.cjs` is loaded through both `c12.loadConfig` with the upgraded `deepmerge` merger and `@prisma/config.loadConfigFromFile`. The c12 test wraps the merger and asserts it was actually called (observed once in the focused diagnostic); merely supplying an unused option would not pass. Tests verify path resolution, `defineConfig` experimental-feature gating, Effect schema acceptance/refusal, and non-mutating nested object/array merge semantics. No private DB or production network is needed; temporary files are removed by each test. Node 22.22.1 on WSL/Linux: 3 PASS, 0 FAIL/SKIP. Windows Node 24.14.1: 3 PASS, 0 FAIL/SKIP. The hosted `Audit Prisma tooling policy` CI job now executes this additional test against its pinned Node 22 runtime.

These results support the tested real configuration paths; they do not claim proof for arbitrary third-party JavaScript configs (which execute code by design) or exotic Map-valued `c12` merges. Neither the SHA256 of the upstream prebuilt `dist/index.js` nor any security audit threshold, runtime dependency version, Docker policy or Prisma major version was modified.
