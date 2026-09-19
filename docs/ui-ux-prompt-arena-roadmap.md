# BielOS UI/UX Rebaseline — Prompt Arena Parity Roadmap

## Decision

The current BielOS UI/UX direction is no longer the target. The local campaign has replaced the shared Hub shell, tokens, appearance contract, navigation, and corresponding Core surfaces with the Prompt Arena interaction language; the prior CSS remains only where an unchanged legacy surface still needs a safe incremental mapping.

The new canonical UI/UX target is the Prompt Arena interface from `bielxdh3/Prompt-Arena`, using the current Prompt Arena `main` snapshot observed for this campaign at commit `6501e8541c13993adef267a291f84686e42c684d`; the earlier `7a3842795192eaa887cedf7b233664e8b53b1940` remains the planning baseline.

This is a **port/parity requirement, not an inspiration brief**. Future BielOS UI/UX work must reproduce the Prompt Arena visual language, interaction language, accessibility behavior, appearance controls, layout system, responsive behavior, and reusable UI patterns as faithfully as the BielOS web architecture permits.

The user explicitly wants the existing BielOS UI/UX discarded as a design target and replaced by the Prompt Arena / Claude-derived direction.

## Implementation rule

Every future UI/UX implementation phase must:

1. use the `ui-ux-pro-max` skill;
2. inspect the pinned Prompt Arena source before implementation;
3. map Prompt Arena UI/UX behavior to the corresponding BielOS surface instead of inventing a new visual language;
4. preserve BielOS authorization, security, data, route, and module boundaries;
5. treat deviations from Prompt Arena parity as exceptions that require an explicit written justification and Biel 3 review;
6. keep Biel 3 as Architect, orchestrator, independent reviewer, and acceptance authority; Biel 4 remains Executor only through Dual Codex App Server under the normal project rules.

This planning change does not authorize UI code changes by itself.

## Source-of-truth inventory

Prompt Arena UI/UX source material includes, at minimum:

- `src/styles.css` — canonical visual tokens, shell, panels, controls, states, responsive behavior, appearance styling, tables, rows, forms, cards, diagnostics, history, and view-specific layout patterns;
- `src/App.tsx` — application shell, navigation semantics, page/view composition, Settings surfaces, live/error state semantics, and interaction wiring;
- `src/appearance.ts` — appearance preference contract and normalization;
- `src/font-options.ts` — the seven selectable local/system font stacks;
- `docs/DESIGN_SYSTEM.md` — intended visual language and accessibility rules;
- `ROADMAP.md` P6 — responsive shell, accessibility, reduced motion, appearance controls, dashboard/history polish, and product-polish acceptance criteria.

Future implementation must compare the live Prompt Arena source against this inventory so newly added Prompt Arena UI/UX features are not silently omitted.

## Mandatory visual language

BielOS must adopt the Prompt Arena visual character:

- calm, information-first composition instead of a dense operations-dashboard aesthetic;
- dark neutral gray default canvas with a restrained warm accent;
- strongly rounded surfaces;
- subtle gray surface gradients;
- thin semantic borders;
- soft panel shadows;
- large breathing room and deliberate spacing;
- readable typography with serif-first default intent;
- visual hierarchy based on content, typography, surfaces, borders, and restrained accent rather than decorative effects;
- success and danger represented through dedicated semantic tokens;
- primary actions represented through the active accent token;
- no independent BielOS-only visual language layered on top of this system unless explicitly approved.

## Mandatory semantic token system

BielOS must port the semantic-token approach rather than scattering raw visual literals.

Required token families include equivalent hooks for:

- canvas;
- surface;
- raised surface;
- soft surface;
- muted surface;
- border;
- strong border;
- primary text;
- muted text;
- subtle text;
- accent;
- strong accent;
- accent ink/contrast color;
- success;
- danger;
- small, medium, and large radii;
- panel shadow;
- UI font stack;
- font scale.

The implementation must preserve the ability for the appearance system to drive these tokens at the application-shell level.

## Mandatory appearance features

All current Prompt Arena appearance capabilities are part of the BielOS target.

### Font family

Support the same seven selectable local/system stacks or faithful web-safe equivalents:

1. Times New Roman with Linux serif fallbacks;
2. Georgia;
3. Garamond;
4. Arial;
5. Verdana;
6. Trebuchet MS;
7. System Mono.

Default intent: Times New Roman with the explicit fallback chain used by Prompt Arena where applicable.

### Font scale

Support the same bounded scale:

- 90%;
- 95%;
- 100%;
- 105%;
- 110%;
- 115%.

The scale must affect the application shell consistently rather than isolated widgets.

### Accent presets

Port all Prompt Arena accent presets:

- Sand;
- Sage;
- Plum.

Accent selection must propagate through primary actions, focus treatment, selected controls, and other semantic accent usages.

### Radius presets

Port both Prompt Arena radius modes:

- Compact;
- Rounded.

They must alter the shared radius scale rather than a few hardcoded components.

### Surface presets

Port all Prompt Arena surface modes:

- Dark neutral;
- Dark warm;
- Paper.

`Paper` must behave as a real light/high-contrast reading surface with correct `color-scheme`, text, border, success, danger, and shadow adaptation.

### Reduced motion

Expose reduced-motion preference and honor both the stored preference and platform accessibility expectations wherever motion exists.

### Appearance lifecycle

Port the full appearance UX contract:

- normalized/sanitized local preference state;
- safe persistence;
- live preview;
- reset/restore default action;
- bounded versioned import;
- bounded versioned export;
- invalid/oversized appearance payload rejection;
- no secrets or private account data in appearance payloads.

Prompt Arena currently bounds appearance payloads to 8 KiB and schema version 1; BielOS should preserve the same UX behavior unless a later architecture decision explicitly changes the storage contract.

## Mandatory application shell

Port the Prompt Arena shell structure and behavior to BielOS:

- persistent desktop sidebar plus main workspace;
- desktop sidebar width and density visually equivalent to Prompt Arena;
- independent sidebar/workspace scrolling where appropriate;
- brand lockup at the top;
- primary navigation grouped under a small uppercase heading;
- each navigation item has a primary label and a secondary description;
- semantic button-based navigation;
- `aria-current="page"` or equivalent active-page semantics;
- hover state with surface/border reinforcement;
- active state with raised surface, strong border, and inset accent indicator;
- sidebar footer/status block anchored to the bottom when space permits;
- topbar with page title/eyebrow and compact status/version metadata;
- bounded centered main content region comparable to Prompt Arena's content width;
- view stack with consistent vertical spacing.

BielOS route semantics remain BielOS-specific, but the shell interaction and visual treatment should match Prompt Arena.

## Mandatory accessibility and interaction behavior

Port all current accessibility-oriented UI features:

- visible keyboard focus ring on buttons, links, inputs, selects, and textareas;
- skip-to-content link;
- screen-reader-only utility pattern;
- semantic active navigation state;
- keyboard-reachable controls;
- empty/loading/error status messaging with appropriate live/alert semantics;
- strong text wrapping/overflow handling for long identifiers and content;
- usable contrast across every surface/accent combination;
- reduced-motion support;
- no pointer-only interaction required for core workflows.

Accessibility parity is part of visual acceptance, not a later optional polish pass.

## Mandatory reusable component patterns

BielOS must port and reuse the Prompt Arena component language wherever a corresponding surface exists.

### Panels and cards

- large-radius semantic panels;
- subtle gradient background;
- thin border;
- restrained panel shadow;
- section panels with responsive internal padding;
- hero/intro panels where a route needs a primary contextual summary;
- metric cards and metric grids;
- dashboard link cards;
- recent-activity rows;
- compact diagnostics panels;
- provider/card-style selectable tiles adapted to BielOS entities where relevant.

### Buttons and actions

- accent-backed primary button;
- text button / low-chrome action;
- clear hover treatment;
- selected-state treatment;
- disabled cursor/state;
- focus-visible ring;
- action groups that wrap safely.

### Status

- status chips with semantic ready/loading/error states;
- version/metadata chips;
- status dot treatment;
- neutral, success, and danger state presentation;
- compact state icon + explanatory copy pattern.

### Forms

- consistent field label;
- select/input/textarea styling from semantic surfaces and borders;
- field help copy;
- field error copy;
- grouped fieldsets;
- checkbox/toggle presentation;
- range control presentation for bounded numeric appearance controls;
- selected-choice card pattern;
- live preview card pattern;
- destructive actions visually separated from primary actions.

### Lists, rows, and detail views

- clean list-row separators rather than excessive nested cards;
- selected row treatment;
- compact metadata lines;
- master/detail or split layouts when information hierarchy benefits from them;
- explicit empty states;
- loading states;
- error states;
- read-only evidence/detail blocks where BielOS has analogous audit/history content.

### Tables and wide evidence

- horizontally bounded table wrapper with local overflow rather than page-wide overflow;
- semantic header treatment;
- stable row borders;
- long values wrap where possible;
- wide data uses contained horizontal scrolling only where necessary.

### Long text / evidence blocks

- bounded-height scroll region;
- pre-wrap behavior;
- anywhere wrapping for long unbroken values;
- semantic muted surface and border.

## Mandatory information architecture patterns

Where BielOS has equivalent content, port these Prompt Arena UX patterns rather than inventing unrelated structures:

- dashboard metric summaries;
- dashboard shortcut grid;
- recent activity/history rows;
- diagnostics summary;
- filter toolbar;
- split history/detail layouts;
- settings grid;
- appearance controls + preview side-by-side layout;
- selected entity cards;
- compact fact rows;
- boundary/safety notice blocks;
- read-only detail sections separated by semantic borders;
- compact export/action areas when export exists;
- clear distinction between editable controls and immutable/read-only evidence.

Arena-specific benchmarking functionality is **not** to be copied into BielOS merely because it has UI. The requirement is to port its UI/UX pattern to equivalent BielOS concepts.

## Mandatory responsive behavior

Prompt Arena's responsive shell is a hard target, not optional polish.

The future BielOS implementation must preserve:

- minimum usable viewport around 320 px;
- fluid main content width;
- responsive grids using `minmax`/equivalent behavior;
- safe collapse of multi-column cards and settings layouts;
- no page-wide horizontal overflow caused by ordinary content;
- contained overflow for genuinely wide data tables/evidence;
- readable navigation on narrow widths;
- reachable actions after wrapping/collapse;
- long-value wrapping;
- stable focus and interaction behavior at narrow widths.

Exact breakpoints may differ when adapting Tauri desktop layouts to the BielOS web shell, but the resulting behavior must be equivalent and documented.

## Mandatory motion behavior

Match Prompt Arena's restrained motion model:

- short, low-amplitude hover/selection transitions;
- no gratuitous animation;
- loading/status pulse only where it communicates state;
- primary-button lift or equivalent minimal feedback;
- reduced-motion mode disables or minimizes non-essential motion.

## Migration roadmap

### UIX-0 — Source lock and parity matrix — COMPLETE (local)

Planning-only.

- Pin the Prompt Arena source snapshot used for parity.
- Inventory every reusable UI/UX feature in Prompt Arena source and design docs.
- Map each feature to a BielOS surface or mark it `NOT_APPLICABLE` with justification.
- Build a visual parity checklist covering shell, navigation, tokens, components, states, appearance, accessibility, responsiveness, and interaction.
- No application code changes in this phase.

Acceptance: no Prompt Arena UI/UX feature is silently omitted from the migration matrix.

### UIX-1 — Shell, tokens, typography, and appearance foundation — COMPLETE (local; human visual gate remains)

- Replace the current BielOS visual shell with the Prompt Arena shell language.
- Port semantic tokens, typography, sidebar/workspace/topbar, panel primitives, focus behavior, skip link, and appearance state hooks.
- Implement the full appearance feature set: 7 fonts, 90–115% scale, Sand/Sage/Plum accents, Compact/Rounded radii, Neutral/Warm/Paper surfaces, reduced motion, preview/reset/import/export.

Acceptance: authenticated Core shell reads visually and interactively as the Prompt Arena design system while preserving BielOS routes and security.

### UIX-2 — Core component parity — COMPLETE (local shared mapping; human visual gate remains)

- Port Prompt Arena patterns for buttons, status chips, panels, cards, forms, fields, toggles, rows, empty/loading/error states, tables, long-text blocks, notices, diagnostics, and selected states.
- Remove obsolete BielOS-specific styling patterns once each affected surface reaches parity.

Acceptance: shared Core primitives no longer depend on the discarded BielOS visual language.

### UIX-3 — Surface-by-surface BielOS migration — COMPLETE (local shared mapping; human visual gate remains)

Migrate every current private-hub surface, including at minimum:

- Hub home/dashboard;
- Core Projects list;
- project detail;
- project access administration;
- administrative elevation/security;
- personal sessions;
- audit/activity;
- applications/identity-access surfaces;
- operations/status surfaces;
- login;
- language selector;
- GymForge existing frozen feature surfaces;
- module registry/reserved-module surfaces.

No currently implemented workflow may become visually orphaned.

Acceptance: every current BielOS screen uses the Prompt Arena parity system and all existing behavior remains reachable.

### UIX-4 — Responsive, accessibility, and interaction parity — COMPLETE LOCALLY; human validation remains

- Validate keyboard navigation and focus-visible behavior.
- Validate skip link and semantic current-page navigation.
- Validate live/error/empty/loading messaging semantics.
- Validate all appearance combinations.
- Validate desktop, narrow/tablet, and mobile-like widths.
- Eliminate page-wide overflow and inaccessible wrapped controls.
- Validate reduced-motion behavior.

Acceptance: parity survives normal responsive and accessibility paths, not only a desktop screenshot.

### UIX-5 — Human visual acceptance — AWAITING_HUMAN_VALIDATION

- Conduct authenticated visual smoke across all representative Hub surfaces.
- Compare against Prompt Arena source behavior and the parity matrix.
- Record every deviation.
- Fix blocking and unexplained parity gaps through the normal Biel 3 → Biel 4 → Biel 3 loop.

Acceptance: Biel 3 can state that the old BielOS UI/UX target has been replaced by Prompt Arena parity with no unexplained feature omissions.

## Supersession rule

Any older roadmap entry that says to "redesign", "polish", "clean up", or otherwise independently evolve the BielOS Hub UI is superseded by this roadmap where the two conflict.

The future task is **not** to polish the Claudio/current BielOS stylesheet. The future task is to replace that design target with Prompt Arena parity.

Current CSS/code may remain temporarily for runtime continuity until UIX implementation is explicitly authorized.

## Non-goals of this planning change

This documentation update does not:

- change application code;
- replace CSS today;
- change routes;
- change auth/security behavior;
- modify database/schema;
- modify Cloudflare or Docker;
- unfreeze GymForge feature expansion;
- implement new module functionality;
- authorize deployment of a future UI implementation.

It only changes the canonical product plan and design direction.
