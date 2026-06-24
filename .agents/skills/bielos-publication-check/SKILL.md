---
name: bielos-publication-check
description: Use when checking whether the BielOS repository can be made public temporarily, reviewing public exposure risk, scanning for secrets, or preparing a sanitized public release.
---

# BielOS Publication Check Skill

Use this skill before making BielOS public or sharing repository access.

BielOS is a private personal hub. Treat publication as a controlled exposure event.

Keep output compact.

Do not narrate every search.

Do not print secrets.

## Goal

Determine whether the repository is reasonably safe for temporary public visibility.

This is not a guarantee. A complete publication review requires local full-history scanning.

## Required Checks

Inspect the current repository state for:

- `.env`;
- `.env.*`;
- Cloudflare tunnel tokens;
- Cloudflare credential JSON;
- Cloudflare Access JWTs;
- cookies;
- session tokens;
- private keys;
- database URLs with real passwords;
- database dumps;
- backups;
- logs;
- Google Takeout;
- Gmail exports;
- Gmail attachments;
- real owner credentials;
- hardcoded API keys;
- hardcoded auth tokens.

Check `.gitignore`.

Check `.env.example`.

Check docs for excessive operational disclosure.

Check whether public-site leaks private hub internals.

Check whether current repo visibility is private or public.

## Search Terms

Use searches such as:

- `.env`
- `DATABASE_URL`
- `POSTGRES_PASSWORD`
- `BIELOS_OWNER_PASSWORD`
- `CLOUDFLARE_TUNNEL_TOKEN`
- `CLOUDFLARE_ACCESS_AUDIENCE`
- `CLOUDFLARE_TEAM_DOMAIN`
- `cf-access-jwt-assertion`
- `cookie`
- `session token`
- `Authorization`
- `Bearer`
- `API_KEY`
- `ACCESS_TOKEN`
- `AUTH_TOKEN`
- `CLIENT_SECRET`
- `BEGIN PRIVATE KEY`
- `ghp_`
- `github_pat_`
- `AKIA`
- `ASIA`
- `AIza`
- `xoxb`
- `sk_live`
- `sk_test`
- `takeout`
- `gmail`
- `attachments`
- `backup`
- `dump`
- `sqlite`

## Local Full-History Commands

When advising the user, recommend these commands for local verification:

```bash
npm run secrets:scan
git log --all --name-only --pretty=format: | sort -u | grep -Ei '(^|/)(\.env|.*\.env.*|.*\.pem|.*\.key|.*\.json|.*\.sql|.*\.db|.*\.sqlite|.*\.dump|backup|takeout|gmail|attachments)'
git grep -n -I -E 'ghp_|github_pat_|AKIA|ASIA|AIza|xox[baprs]-|sk_live_|sk_test_|BEGIN .*PRIVATE KEY|cf-access-jwt|CLOUDFLARE_TUNNEL_TOKEN|DATABASE_URL|POSTGRES_PASSWORD|BIELOS_OWNER_PASSWORD|CLIENT_SECRET|API_KEY|AUTH_TOKEN|ACCESS_TOKEN' $(git rev-list --all)
```

If any real secret appears in history, advise:

1. Rotate the secret immediately.
2. Keep the repo private.
3. Rewrite history only if necessary and understood.
4. Force-push only after understanding consequences.
5. Treat exposed credentials as compromised.

## Publication Verdicts

Use one:

- `OK temporário com cautela`
- `Manter privado`
- `Bloqueado até corrigir`
- `Criar repo público sanitizado`

## Temporary Public Rules

If temporary publication is acceptable, recommend:

- keep public only for the necessary window;
- do not broadly share the link;
- disable Issues and Discussions if unnecessary;
- do not include private operational docs if avoidable;
- return to private afterward;
- never add real data while public.

## Output Format

Use only:

- Status
- Current visibility
- Findings
- No obvious secret found
- Remaining risk
- Required local checks
- Recommendation

Do not claim the repo is fully safe unless full-history scanning was actually completed.
