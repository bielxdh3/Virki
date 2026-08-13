# GymForge

GymForge is an implemented private-hub MVP available through the authenticated BielOS hub. Its current scope includes participant and exercise administration, attendance and correction, single-set workout create/edit/delete, rankings and streaks, competition lifecycle and assignment, deterministic scoring, and additive score-correction history.

The existing Cloudflare Access, BielOS internal authentication, CSRF, authorization, session, and audit boundaries remain required. Further expansion is frozen: invitations and invite acceptance, public registration, photo or upload proof, import/export, a public API, unsafe competition deletion, and broad social behavior remain blocked. This directory is a module placeholder; runtime implementation lives under `apps/hub/src/app/gymforge/`.
