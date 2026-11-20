# Issue #119 — defensive maintenance and acceptance boundaries

This revision addresses two repository-owned items from issue #119. The starting main revision was `669e897d0adf3d0457d18ff680b7cf2123a2885d`. It does not authorize merge, deployment, production activation, or external configuration changes.

## Public-site CSP

The public site uses the Next.js 16 request-time nonce pattern (see [Next.js CSP guide](https://nextjs.org/docs/app/guides/content-security-policy)). Its proxy sets the document policy and its root layout renders HTML dynamically, including the framework's not-found page. The production script policy no longer permits generic inline scripts; all other existing directives are retained, including the inline-style allowance needed by the default not-found document. Development retains the framework's existing eval allowance. Hub and Portal application configuration and the existing powered-by-header suppression from PR #132 remain unchanged.

The local browser validation covered normal 200 and 404 documents, matching script nonces, fresh nonces across requests, and absence of ordinary execution errors. Production HTML was private/no-store. Development-specific runtime-added nodes are not counted as scripts emitted by the server document; the regression checks the actual document response. The existing browser suite now includes not-found coverage and checks the normal landing document before navigating to the Portal. This is local/DEV evidence, not a live-edge attestation.

## OIDC discovery alignment

The supported protocol in `docs/sso-integration.md` is Authorization Code with PKCE S256. The existing client defaults and project registration adapter already select `code` and `authorization_code`. The discovery configuration now explicitly advertises only `code`, instead of inheriting broader library defaults. The ordinary local discovery fixture asserts that contract. There is no change to stored client secrets, accounts, grants, or session policy.

## Acceptance boundaries

- PR #132 already implemented powered-by-header suppression; its hosted evidence should not be repeated without cause.
- The prior Cloudflare API observation reported minimum TLS 1.0. TLS 1.2 minimum and compatibility validation remain a separate authorized-infrastructure decision. No edge setting was changed by this revision.
- Historical scan observations are not a complete security assessment; specialist validation and any required controlled authenticated assurance remain open. Do not attach raw reports or credentials. No live probing was performed.
- Current main's prior CodeQL policy enforcement failure is a distinct gate. Do not suppress findings or change the analysis policy to clear it.
- Issue #90 is excluded. This revision does not modify its artifacts or operational controls.

Retain issue #119 until all applicable acceptance requirements and authorizations have been satisfied. Hosted check and review receipts must identify the exact published revision.
