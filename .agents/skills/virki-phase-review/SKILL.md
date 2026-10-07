---
name: virki-phase-review
description: Check a completed Virki change or milestone against its requested scope, security boundaries, and validation evidence.
---

# Virki phase review

Compare the completed change with the user request and current `AGENTS.md`. Inspect relevant code paths, migration/data effects, deleted-scope completeness, documentation, and validation evidence. Treat commit output and CI as evidence only after checking the actual SHA and run result.

For a single-agent task, perform this as a fresh adversarial pass by the same agent. Never claim that it was independent. Check for security regressions, architecture drift, data loss, stale product concepts, UI mismatch, and unverified deployment claims. Fix accepted findings and rerun affected checks.

Report the commit and CI state when known, findings with file/line evidence, validation limits, and whether required human or external checks remain.
