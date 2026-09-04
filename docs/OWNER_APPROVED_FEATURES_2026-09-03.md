# Owner-approved feature backlog — 2026-09-03

This document records product decisions approved by the repository owner on 2026-09-03.

It is a planning record only. An item appearing here does **not** mean it is implemented, validated, deployed, or allowed to bypass BielOS security/review gates. Existing UIX and roadmap status remain unchanged until implementation evidence exists.

## Approved features

- [#8 — Universal Command Palette](https://github.com/bielxdh3/BielOS/issues/8)
- [#9 — Project Health Cards](https://github.com/bielxdh3/BielOS/issues/9)
- [#10 — Unified Activity Inbox](https://github.com/bielxdh3/BielOS/issues/10)
- [#11 — Automation Recipes](https://github.com/bielxdh3/BielOS/issues/11)
- [#12 — Module Capability Contract v1](https://github.com/bielxdh3/BielOS/issues/12)
- [#13 — Recovery Center](https://github.com/bielxdh3/BielOS/issues/13)

## Architectural ordering

1. Module Capability Contract v1 should precede broad Root.ark/L-vault integration and should define the allowed cross-module data/action boundary.
2. Project Health Cards and Recovery Center should consume only authorized, freshness-tagged module capabilities.
3. Unified Activity Inbox should aggregate only approved event metadata and deep-link back to the authoritative owning module.
4. Automation Recipes must execute only declared capabilities and preserve confirmation/audit requirements.
5. Universal Command Palette can unify navigation/actions after the underlying capability and authorization semantics are explicit.

## UI/UX invariants

- Prompt Arena parity remains the canonical BielOS visual target.
- Future UI/UX work must use the approved UI/UX process/skill.
- Minimal-first and intuition-first information density remain mandatory.
- Default surfaces should show only what is necessary for the current action; secondary detail stays behind progressive disclosure.
- GymForge expansion remains frozen unless separately approved.
