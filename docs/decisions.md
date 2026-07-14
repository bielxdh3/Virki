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
