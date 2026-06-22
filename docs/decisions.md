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

## 0005: Next Canary With Webpack

Use `next@16.3.0-canary.60` with Webpack build and dev commands for the initial scaffold.

Reason: the current stable Next release depends on a vulnerable PostCSS version, while this canary uses the fixed PostCSS release. Webpack is pinned because Turbopack build crashed during Windows validation.
