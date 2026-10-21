# A21 post-fix independent review

**Date:** 2026-10-20\
**Repository:** `bielxdh3/Virki`\
**Source HEAD:** `34b476b49e77535f38cc417ffc082c7578c5ee6b`\
**Branch:** `cdx/virki-five-report-security-triage-20261020`\
**Review type:** read-only review by a fresh native Codex subagent using GPT-6 Luna, reasoning effort high.

## Result

**`NO_CONFIRMED_P1_P2`** in the latest complete A21 patch. The review did not report an actionable P1 or P2 finding.

## Scope reviewed

- `scripts/backup-restore-validation.mjs`
- `infra/postgres-init/10-virki-database-roles.sh`
- `docs/database-privilege-transition.md`

The review was performed after the restore-fixture correction. Its bounded request specifically named the `pg_dump`/`pg_restore` path using `--no-owner --no-privileges`, initializer/migrator order, migration identity, role boundaries, `virki_security` ownership, schema and routine allowlists, `SECURITY DEFINER` ownership and search path, audit-retention privileges, and default grants. The reviewer returned the explicit disposition above and noted the limits below, without a separate pass/fail checklist for each subtopic. The post-fix review remained read-only; it changed no files and operated on no production roles, database, container, secret, or volume.

## Corroborating disposable evidence

After the review, the primary agent ran the changed A21 validation in the worktree with Node `v22.23.3`:

```text
npx --yes node@22.23.3 scripts/backup-restore-validation.mjs
exit code: 0
```

The script's owned disposable PostgreSQL 17 container and temporary files were removed by its cleanup path. This is local disposable evidence; it is not a production restore.

## Limits

The reviewer noted that the fixture does not compare migration checksums or every migration-history field, and does not exhaustively enumerate every direct/default grant or every schema object. The review did not itself execute the PostgreSQL fixture. The reported result is therefore bounded to the listed files and concrete P1/P2 review criterion; it is not a proof of every database privilege invariant or a substitute for hosted, production, or restore-from-owner-backup evidence.
