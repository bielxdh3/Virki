---
name: bielos-phase-review
description: Use when reviewing a BielOS commit, checking a completed phase, comparing the latest main commit with the requested scope, or deciding the next BielOS phase.
---

# BielOS Phase Review Skill

Use this skill to review completed BielOS phases and prepare the next step.

Keep output compact.

Do not narrate file inspection.

Do not provide progress updates.

## Review Goals

Verify whether the latest commit:

1. Matches the requested phase.
2. Stayed within scope.
3. Preserved BielOS security boundaries.
4. Avoided unrelated refactors.
5. Avoided future module implementation.
6. Avoided committing secrets or private operational data.
7. Updated documentation when behavior changed.
8. Added or preserved relevant validation commands.

## BielOS Security Boundaries

Preserve these unless the user explicitly requested a change:

- `biel.dev.br` remains public.
- `hub.biel.dev.br` remains private.
- Cloudflare Access remains the outer boundary.
- BielOS internal auth remains required behind Access.
- Origin-side Cloudflare Access JWT validation must not be weakened.
- Docker host-published ports must stay bound to `127.0.0.1`.
- `.env` and real secrets must never be committed.
- Public site must not expose private operational details.
- Future modules must remain placeholders unless explicitly requested.

## Review Process

Inspect:

- latest commit SHA and message;
- changed files;
- relevant code paths;
- documentation updates;
- validation or CI changes;
- security-sensitive behavior.

Do not claim CI passed unless it is confirmed.

If workflow runs are unavailable or empty, say:

`CI remoto não confirmado.`

## Output Format

Use only:

- Status
- Commit
- Files changed
- Behavior changed
- Review verdict
- Issues found
- CI/validations
- Next recommended phase
- Codex level

Keep it short.

## Verdict Labels

Use one:

- `Aprovado`
- `Aprovado com ressalva`
- `Hotfix necessário`
- `Reprovado`

## Codex Level Guidance

Use:

- `Low` for tiny copy/doc-only changes.
- `Medium` for Docker, docs, scripts, simple CI, small UI, or operational tasks.
- `High` for auth, sessions, CSRF, Cloudflare Access, JWT, Prisma schema, database safety, security controls, migrations, backup/restore.
- `Extra High` only for critical security audits or repeated failures.

## Next Phase Prompt

When asked for the next step, provide a complete Codex prompt.

The prompt must include:

- current latest commit;
- task name;
- context;
- scope;
- explicit do-not rules;
- documentation expectations;
- validation expectations;
- expected commit message;
- final summary requirements.

Keep the prompt phase-scoped.
