# BielOS Isolated Intake Service

`apps/intake` is a small HTTP service for the public `/api/apply` and `/api/catalog` paths. The public site never imports the private database package. The intake service receives a distinct `BIELOS_INTAKE_DATABASE_URL` and must be backed by a database role restricted to the catalog and intake/outbox tables; it must not receive credentials that can read users, sessions, projects, grants, audits, administrative credentials, or elevation state.

The service fails closed unless `BIELOS_INTAKE_ENABLED=true`, the restricted database URL exists, a dedicated `BIELOS_INTAKE_ABUSE_SECRET` exists, and the email outbox encryption key exists. Production Compose defaults the feature flag to `false` and publishes no intake host port; an explicit private production environment value is required to enable it after the rollout gates pass. Public routing to `/api/apply` is a separate deployment gate and is not implied by the container existing.

Handlers enforce exact public origin, JSON content type, bounded body size and field counts, normalized email, required per-module reasons, public/requestable catalog filtering, generic responses, and HMAC-only abuse identifiers. The only public module keys currently eligible are `gymforge`, `aip`, and `rootark`; private and unlisted records are never returned.
