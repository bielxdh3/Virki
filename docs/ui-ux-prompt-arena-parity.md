# Prompt Arena parity evidence

Campaign snapshot: `bielxdh3/Prompt-Arena` `main` at `6501e8541c13993adef267a291f84686e42c684d` (planning baseline `7a3842795192eaa887cedf7b233664e8b53b1940`).

This is the implementation ledger for the current local parity pass. It maps the Prompt Arena interaction system to BielOS without importing Arena-domain data or commands.

| Prompt Arena capability | BielOS mapping | Disposition | Evidence |
| --- | --- | --- | --- |
| Semantic canvas/surface/accent/status tokens | Shared Hub shell tokens and legacy-variable bridge | COMPLETE | `apps/hub/src/app/globals.css` |
| Serif-first typography and seven local/system stacks | Appearance control with bounded allowlist | COMPLETE | `appearance-controls.tsx`, `globals.css` |
| 90–115% stepped scale | Shell-level `font-size` token | COMPLETE | `appearance-controls.tsx`, `globals.css` |
| Sand/Sage/Plum, Compact/Rounded, Neutral/Warm/Paper | Live preview and shared semantic selectors | COMPLETE | `appearance-controls.tsx`, `globals.css` |
| Standard/high contrast and 0–200% motion scale | Bounded appearance controls; reduced motion still forces zero discretionary motion | COMPLETE | `appearance-controls.tsx`, `globals.css` |
| Reduced motion | Stored preference plus OS default and CSS suppression | COMPLETE | `appearance-controls.tsx`, `globals.css` |
| Versioned bounded import/export | JSON v1, 8 KiB limit, allowlist validation, no account data | COMPLETE | `appearance-controls.tsx` |
| Persistent sidebar/workspace/topbar | CoreShell, dashboard, project detail, and GymForge shell migration | COMPLETE | `core/shell.tsx`, `page.tsx`, `core/projects/[projectId]/page.tsx`, `gymforge/page.tsx` |
| Compact navigation and skip link | Short labels, route-aware active state, skip-to-content | COMPLETE | `core/navigation.ts`, `core/shell.tsx`, `page.tsx` |
| Command palette interaction | Ctrl/Cmd+K searchable authorized route palette with bounded local relevance/recency | COMPLETE | `core/command-palette.tsx`, `core-ui.test.ts` |
| Panels, cards, status chips, forms, disclosure, contained evidence | Shared semantic CSS and Core capability/audit surfaces with source/observation timestamps | COMPLETE | `globals.css`, Core routes, `core/capabilities.ts` |
| Responsive 320px intent, wrapped controls, bounded wide evidence | Responsive shell/grid and overflow-safe text rules | COMPLETE | `globals.css` |
| Tauri/Arena benchmark execution, model providers, desktop bridge | BielOS has no equivalent and must not import Arena-domain functionality | NOT_APPLICABLE | Approved boundary in `docs/decisions.md` |
| Human visual/interaction acceptance in an authenticated browser | Requires owner-controlled Cloudflare/session smoke | AWAITING_HUMAN_VALIDATION | `docs/deployment-verification.md` |

The implementation keeps security-critical disclosures, CSRF, authorization, audit, and recovery behavior intact while moving secondary explanation behind disclosure where possible. A human visual review remains a real acceptance gate; source and DOM checks do not substitute for it.
