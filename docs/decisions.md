# Decisions

## 0001: Monorepo Structure

Use a simple npm workspaces monorepo with `apps`, `packages`, `modules`, `infra`, and `docs`.

Reason: this keeps the project easy to inspect, works on Windows, and remains portable to Linux through Docker.

## 0002: Reserved Modules

Create folders and dashboard cards for L-vault, root.ark, H-vault, and GymForge, but do not implement module applications in the MVP.

Reason: Core security and navigation should exist before sensitive module work begins.

## 0003: Public and Private Surface Split

Keep `apps/public-site` separate from `apps/hub`.

Reason: the public site must remain generic while the private hub can evolve behind Cloudflare Access and application authentication.

## 0004: Environment-Based Configuration

Use `.env.example` for documented configuration and keep real `.env` files ignored.

Reason: the project must move from Windows to Linux without hardcoded machine-specific values.

## 0005: Stable Runtime Foundation

Use Node 22 LTS, TypeScript 5.x, and a stable Next.js release for the Phase 01 scaffold.

Reason: the core should start from predictable long-term-support runtime choices. Canary versions should be avoided unless a stable build becomes impossible, and any exception must be documented with the exact limitation.

## 0006: Core Authorization And Application Classification

BielOS Core is the authenticated private-hub platform, GymForge is an available integrated application, and L-vault, root.ark, and H-vault remain reserved modules.

Core project authorization uses global role first and explicit `ProjectAccess` for non-public member visibility. Project access does not grant global administration. Permanent project deletion and `SecurityUnlock` runtime behavior remain blocked in the initial Core expansion.

Reason: this uses the existing schema while keeping access precedence, lifecycle, and sensitive gates explicit.

## 0007: Prompt Arena Becomes The Canonical BielOS UI/UX Target

Discard the current BielOS UI/UX direction as the future design target. Keep the current implementation only until a dedicated migration replaces it.

Use `bielxdh3/Prompt-Arena` as the canonical UI/UX source of truth, with the Prompt Arena `main` snapshot observed at `7a3842795192eaa887cedf7b233664e8b53b1940` as the planning baseline. Future BielOS UI/UX work is a parity/port task, not a free redesign or loose inspiration exercise.

The parity requirement includes the complete Prompt Arena UI/UX feature set that is applicable to BielOS: shell and navigation language, semantic design tokens, typography, panel/card/control patterns, status and feedback states, forms, tables, long-content handling, responsive behavior, accessibility/focus semantics, reduced motion, appearance customization, appearance preview/reset/import/export, all seven font stacks, bounded font scaling, all accent/radius/surface presets, and the same calm information-first visual hierarchy.

Arena-domain functionality itself is not imported unless BielOS independently requires it; the requirement is to map Prompt Arena UI/UX patterns onto equivalent BielOS concepts and screens.

Every implementation phase that modifies UI/UX must use the `ui-ux-pro-max` skill. Any Prompt Arena UI/UX feature that is not ported must be explicitly marked `NOT_APPLICABLE` with a reviewed justification rather than silently omitted.

The canonical detailed migration plan is `docs/ui-ux-prompt-arena-roadmap.md`. Older roadmap language about independently redesigning or polishing the BielOS Hub is superseded where it conflicts with that plan.

Reason: the user explicitly chose the Prompt Arena / Claude-derived interface as the BielOS visual and interaction baseline and wants the existing BielOS design direction replaced rather than incrementally polished.

## 0008: Minimal-First Information Density Is Mandatory

Every future BielOS UI/UX surface must show only the information required for the user's current decision or action by default.

Long instructional paragraphs, repeated labels, duplicated status copy, implementation terminology, permission explanations, and secondary metadata must not be permanently exposed when the same workflow can be understood from concise labels, hierarchy, state, and placement. Secondary explanation belongs behind contextual help, disclosure, tooltip, expandable detail, or a dedicated secondary surface when it is genuinely needed.

Administrative and project-access screens must be especially strict: one clear action flow, aligned controls, obvious current state, concise feedback, and no wall of text competing with the primary task. Security requirements remain fully enforced server-side; simplifying the interface must never mean weakening authorization, elevation, confirmation, or audit boundaries.

Alignment, spacing, visual grouping, and progressive disclosure are acceptance criteria, not cosmetic polish. A screen that is technically complete but visually noisy, misaligned, redundant, or non-intuitive fails UI/UX acceptance.

This rule applies to all future Prompt Arena parity work and must be evaluated with `ui-ux-pro-max` during implementation and Biel 3 independent review.

Reason: the user explicitly rejected the current project-access presentation because it exposed too much explanatory information at once and was visually misaligned. BielOS should feel self-explanatory through structure, not through persistent instruction text.

## 0009: Intuition-First UI and Extreme Text Compression

BielOS UI must be understandable primarily through structure, placement, grouping, state, iconography, and familiar interaction patterns. Visible text is a fallback for ambiguity, not the default mechanism for teaching the interface.

Every visible string must be challenged. If meaning survives by removing it, shortening it, replacing it with a familiar compact concept, or moving it behind progressive disclosure, the more compressed option is preferred.

Navigation is included. Long destination names such as `Seção de operações`, `Segurança pessoal`, `Seção de auditoria`, `Segurança da conta`, `Catálogo de módulos`, `Segurança administrativa`, and `Solicitações de conta` are not the future target. Prefer compact concepts such as `Ops`, `Pessoal`, `Audit`, `Conta`, `Módulos`, `Admin`, and `Pedidos` when context keeps them unambiguous. Decorative numeric prefixes should disappear unless they carry real product meaning.

Prompt Arena remains canonical for visual language and interaction systems, but literal Prompt Arena text density is not a parity requirement. Where a Prompt Arena pattern uses persistent secondary descriptions, BielOS must first test whether placement, state, iconography, a shorter label, tooltip, disclosure, drawer, or dedicated detail surface can communicate the same information with less visible copy.

The canonical compression contract is `docs/ui-ux-intuition-first.md`. Where it conflicts with a text-heavy interpretation of `docs/ui-ux-prompt-arena-roadmap.md`, the intuition-first rule wins while accessibility and security-critical disclosure remain mandatory.

Reason: the user wants the entire site compressed as far as practical and based on intuition. The current numbered, sentence-like navigation and explanatory administrative surfaces require too much reading for ordinary use.