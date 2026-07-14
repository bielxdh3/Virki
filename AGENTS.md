# BielOS Agent Instructions

BielOS is a private personal hub, not a public SaaS.

The repository represents the real private BielOS codebase. Treat it as security-sensitive even when the task appears small.

## Core Priorities

1. Preserve security boundaries.
2. Keep changes small and phase-scoped.
3. Do not implement future modules unless explicitly requested.
4. Do not expose secrets or private operational data.
5. Minimize output.
6. Prefer boring, maintainable solutions over clever complexity.
7. Do not invent repository state. Inspect files before making claims.

## Required BielOS Skill Selection

Every BielOS prompt must explicitly name the required BielOS skill at the top before general instructions.

The agent must follow the selected skill strictly before applying the general rules in this `AGENTS.md` file.

Use these skills by task type:

- Phase review, commit review, completed phase check, next-step review, or deciding the next BielOS phase:
  `.agents/skills/bielos-phase-review/SKILL.md`
- Security, authentication, CSRF, sessions, Cloudflare, Docker exposure, secrets, audit logs, or production hardening:
  `.agents/skills/bielos-security-review/SKILL.md`
- Making the repository public, sharing repository access, publication safety, or sanitized public release:
  `.agents/skills/bielos-publication-check/SKILL.md`

If no existing BielOS skill matches the task, stop and report exactly:

`No matching BielOS skill found for this task.`

Do not proceed with implementation when no matching BielOS skill exists.

Do not invent a new skill unless the user explicitly requests creating one.

## Project Model

- `biel.dev.br` is the public site.
- `hub.biel.dev.br` is the private hub.
- The hub must remain protected by Cloudflare Access first and BielOS internal auth second.
- Cloudflare Access and BielOS internal auth are separate layers. Do not collapse them.
- Docker host-published ports must remain bound to `127.0.0.1`.
- Future modules are reserved unless explicitly requested:
  - L-vault
  - root.ark
  - H-vault
- GymForge is no longer merely reserved: its private-hub MVP includes participant and exercise administration, attendance check-ins and correction, single-set workout creation/editing plus explicit deletion, rankings and streaks, competition lifecycle management, participant assignment, deterministic automatic scoring, and additive competition score correction.
- The current workout MVP intentionally creates and edits exactly one set per workout. Updates must fail safely when a stored workout unexpectedly has zero or multiple sets, while explicit workout deletion must transactionally remove all dependent sets.
- GymForge competition score-correction Phases 2 and 3 are complete. Corrections preserve the separate current-state automatic base, use append-only additive/revocation history, and remain private to the existing authenticated hub boundary.
- Further GymForge feature expansion is frozen while BielOS Core is the active product path. No GymForge invitation or optional feature phase is next.
- Preserve existing GymForge behavior and its Cloudflare Access, BielOS internal auth, CSRF, audit logging, and private hub boundaries; integration work is limited to accurate hub registry/navigation behavior unless the user explicitly changes this direction.
- Do not add GymForge upload or photo proof, public registration, invite acceptance before Phase 4, import/export, unsafe competition deletion, a public API, or broad social feed behavior unless explicitly requested in a scoped phase.

## Output Rules

Keep output minimal.

Do not provide progress updates.

Do not narrate routine actions such as:
- reading files;
- editing files;
- running commands;
- checking configs;
- inspecting diffs.

Do not explain obvious implementation details unless they affect:
- security;
- architecture;
- validation;
- data integrity;
- deployment behavior.

Only interrupt if:
- a blocking ambiguity requires user input;
- a command fails and changes the plan;
- a security-sensitive issue is found;
- the requested scope cannot be completed.

## Final Response Format

Use this format only:

- Status
- Files changed
- Behavior changed
- Validations run
- Validations not run
- Remaining limitations

Keep the final response compact.

Do not include long logs unless a command failed.

If a command failed, include only:
- the command;
- the relevant error lines;
- the corrective action or limitation.

Do not include motivational commentary, apologies, speculation, or broad explanations.

If the task was completed, say so directly and stop.

## Security Rules

Never print, commit, log, or expose:

- `.env` contents;
- Cloudflare tunnel tokens;
- Cloudflare credentials JSON;
- Cloudflare Access JWTs;
- cookies;
- session tokens;
- raw authorization headers;
- raw request headers;
- raw IP addresses;
- database URLs with passwords;
- private keys;
- database dumps;
- backups;
- Google Takeout data;
- Gmail exports;
- Gmail attachments;
- private operational logs.

Use placeholders in examples.

Safe placeholders include:
- `replace-with-local-secret`
- `change-me-in-your-local-env`
- `owner@example.invalid`
- `https://<team-name>.cloudflareaccess.com`
- `<Access application AUD tag>`

## Validation Expectations

When relevant, run or document:

```bash
npm run secrets:scan
npm run lint
npm run typecheck
npm run prisma:validate
npm run build
```

For Docker-related changes, also validate the relevant Compose config when feasible.

For security changes, explicitly state what could not be validated locally.

## Token Economy Rules

- Prefer the smallest safe context.
- Inspect only files relevant to the task.
- Do not read broad repository context unless required.
- For docs-only tasks, run only `npm run secrets:scan` unless the prompt explicitly asks for more.
- Do not run `npm run build`, `npm run typecheck`, `npm run lint`, Docker commands, or Prisma commands for docs-only changes.
- Use one skill at most unless the task is explicitly security-sensitive.
- Do not spawn subagents unless explicitly requested.
- Keep final output compact.
- Report skipped validations as intentionally skipped when they are not relevant.

## Codex Behavior

Follow repository instructions and relevant skills.

Use `E:\BielOS` as the local BielOS repository path for this machine.

Use minimal output mode by default.

Do not create unrelated refactors.

Do not modify unrelated files.

Do not add dependencies unless they are clearly justified.

Do not change runtime authentication, Cloudflare behavior, Docker port bindings, or database schema unless the task explicitly requires it.
