# Codex Rules

These rules apply when using Codex or another implementation agent on BielOS.

## Scope

- Keep Phase 01 focused on BielOS Core.
- Do not implement L-vault, root.ark, H-vault, or GymForge until the core access model is ready.
- Keep module folders and module cards as reserved placeholders only.

## Language

- Code, folder names, variables, schemas, and technical docs stay in English.
- User-facing UI text can stay in English for now.

## Security

- Never create or commit a real `.env` file.
- Never commit API keys, tokens, Cloudflare credentials, Gmail data, Google Takeout exports, logs, IP addresses, private paths, database dumps, or backup archives.
- Keep public pages generic.
- Do not expose internal ports, local server details, stack internals, counts, logs, filenames, or operational data on public pages.
- Prefer environment-based configuration over hardcoded machine details.

## Implementation

- Prefer stable runtime foundations: Node 22 LTS, TypeScript 5.x, and stable Next.js releases.
- Avoid experimental or canary dependencies unless a stable build is impossible.
- If a canary dependency is necessary, document the exact version, reason, limitation, and planned removal path.
- Do not add real authentication until the auth design is explicitly scoped.
- Do not add Cloudflare Access or Tunnel credentials to the repository.
