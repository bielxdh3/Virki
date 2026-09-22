---
name: bielos-publication-check
description: Assess BielOS source, history, and repository metadata before any public release or access change.
---

# BielOS publication check

This skill assesses publication readiness; it never changes repository visibility. Keep the repository private unless the owner explicitly authorizes a separate visibility change.

## Inspect

- Current tracked files, ignored-file policy, examples, build outputs, fixtures, and docs.
- Full reachable Git history for secrets, personal infrastructure, private data, backups, and credentials that may require rotation.
- GitHub Actions logs/artifacts, releases, issues, pull requests, wiki, discussions, and repository metadata when tools and authorization allow.
- Whether the public site reveals protected application data or private operational details.
- Required license and external DNS, Tunnel, and Access state.

Never print secret values, raw IPs, private logs, credentials, backup data, or private user records. Do not force-push, delete repository records, create a release, or change visibility as part of an assessment.

## Verdict

Use `OK temporário com cautela`, `Manter privado`, `Bloqueado até corrigir`, or `Criar repo público sanitizado`. Distinguish checks completed from unavailable checks. Treat a credential in reachable history as compromised and require rotation before any public release. Recommend a safe history rewrite or fresh sanitized lineage when needed, but do not perform it without a separate explicit request.

Do not claim full publication readiness unless source, history, and external repository records were actually assessed.
