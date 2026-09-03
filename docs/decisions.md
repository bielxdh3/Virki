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
