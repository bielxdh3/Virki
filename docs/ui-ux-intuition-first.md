# BielOS UI/UX — Intuition-First and Extreme Text Compression

## Status

This is a canonical UI/UX rule for BielOS.

It supplements and, where necessary, overrides text-heavy interpretations of `docs/ui-ux-prompt-arena-roadmap.md`.

Prompt Arena remains the visual and interaction-system source of truth, but **BielOS must not copy unnecessary text density merely for parity**. When literal Prompt Arena copy patterns conflict with a more intuitive BielOS flow, the interaction pattern is preserved while the text is compressed.

Every future UI/UX implementation must use `ui-ux-pro-max` and must be independently reviewed by Biel 3 under the normal project workflow.

## Core principle

**The site should explain itself through structure before it explains itself through words.**

Everything visible should earn its place.

Text is a last-mile clarification tool, not the primary navigation or workflow mechanism.

The default screen should contain the minimum text required for a user to understand state, choose an action, and recover from an error.

## Compression hierarchy

For every visible string, evaluate in this order:

1. Can position or grouping communicate it?
2. Can an icon plus accessible label communicate it?
3. Can state styling communicate it?
4. Can a shorter label communicate it?
5. Can the detail be shown only on demand?
6. Only then keep explanatory text permanently visible.

If a string can be removed without making the workflow ambiguous, remove it.

## Mandatory rules

- Use the shortest clear label that preserves meaning.
- Prefer familiar nouns and verbs over internal system terminology.
- Do not expose policy identifiers, enum names, implementation names, or backend vocabulary in normal UI.
- Do not show instructions for a workflow that can be made self-evident through layout and sequencing.
- Do not repeat the same state in a heading, badge, description, helper text, and button.
- Do not permanently display secondary metadata that is not needed for the current decision.
- Do not render explanatory paragraphs beside ordinary controls.
- Prefer progressive disclosure, drawers, tooltips, contextual help, detail views, and expandable sections for secondary information.
- Prefer concise inline validation over long instructional copy.
- Prefer a single primary action per local decision point.
- Keep related controls visually aligned and spatially grouped.
- Remove decorative numbering or labels when position and iconography already establish navigation order.
- Every icon-only control must remain accessible through an `aria-label`, tooltip, or equivalent non-visual accessible name.
- Compression must never remove required legal, destructive-action, privacy, recovery, or security disclosure when the user genuinely needs that information to make an informed decision.

## Navigation rule

Navigation must be compressed aggressively.

The current style of entries such as:

- `Seção de operações`
- `Segurança pessoal`
- `Seção de auditoria`
- `Segurança da conta`
- `Catálogo de módulos`
- `Segurança administrativa`
- `Solicitações de conta`

is not the future target.

Prefer short, immediately scannable concepts such as:

- `Hub`
- `Ops`
- `Projetos`
- `Pessoal`
- `Audit`
- `Conta`
- `Módulos`
- `Admin`
- `Pedidos`

Exact final labels must be validated in context, but the rule is fixed: **one compact concept per destination, no sentence-like navigation labels**.

Secondary descriptions under every nav item are not mandatory BielOS parity requirements. They should be omitted by default and used only when a destination would otherwise be ambiguous.

Number prefixes such as `01`, `02`, `03` should be removed unless they carry real product meaning. Navigation order itself is sufficient.

## Forms and administration

Administrative surfaces must be especially strict.

A normal administrative flow should present:

- the current state;
- the necessary choice;
- the primary action;
- concise feedback.

Everything else is secondary.

Avoid permanent walls of helper copy, raw scope names, permission explanations, duplicated role descriptions, or implementation terminology.

Security remains enforced in backend policy. A simpler UI must not mean weaker authorization, confirmation, audit, recovery, or destructive-action safeguards.

## Error and status language

Errors should answer two things with the fewest words possible:

1. What failed?
2. What can the user do next?

Do not expose internal action names, stack vocabulary, policy identifiers, or implementation details unless the screen is explicitly an engineering/debug surface.

Success feedback should normally be one concise state change, not a paragraph.

## Progressive disclosure

Secondary information should appear only when requested or contextually necessary.

Preferred mechanisms:

- tooltip for short explanation;
- small disclosure/chevron for optional details;
- drawer for an action-specific form;
- modal only when focus or confirmation genuinely requires it;
- dedicated detail screen for extensive information;
- expandable technical details on diagnostic surfaces.

The primary screen must remain calm even if the underlying system is complex.

## Acceptance criteria

A UI/UX phase fails review if any representative screen is:

- text-heavy without necessity;
- dependent on instructions to explain ordinary interaction;
- full of redundant labels;
- visually misaligned;
- difficult to scan quickly;
- exposing backend/security implementation vocabulary to ordinary users;
- showing secondary detail before the user asks for it;
- using verbose navigation when a compact concept is sufficient.

For every migrated surface, Biel 3 must explicitly review:

- what text was removed;
- what text remains and why it is necessary;
- whether the flow is understandable without instructions;
- whether accessibility survived the compression;
- whether security-critical disclosure remains sufficient.

## Relationship to Prompt Arena parity

Prompt Arena remains canonical for:

- shell composition;
- spacing;
- typography system;
- semantic tokens;
- components;
- interaction states;
- accessibility;
- responsive behavior;
- appearance controls;
- visual hierarchy.

But BielOS is **not required to preserve Prompt Arena's text volume** where its domain can be more concise.

If a Prompt Arena pattern uses a primary label plus persistent secondary description, BielOS should first test whether the secondary description can be removed, moved to contextual help, or represented by state/placement.

The goal is not minimalism for decoration. The goal is **maximum comprehension with minimum visible text**.

## Non-goals

This rule does not authorize application-code changes by itself.

It does not weaken:

- Cloudflare Access;
- BielOS authentication;
- authorization;
- administrative safeguards;
- CSRF;
- audit;
- data isolation;
- destructive-action confirmation;
- recovery requirements.

It only establishes the required future information architecture and interaction language.