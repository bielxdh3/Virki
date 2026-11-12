# Isolated staging email-worker identity — offline role contract

**Status: LOCAL POSTGRESQL ACL PROOF ONLY / STAGING DELIVERY NO-GO.**

The source includes a separate worker-only PostgreSQL role and a Compose
override for a **manually authorized, independently isolated staging host**.
Neither file is part of ordinary stage, deploy, start or restart commands.
Stage keeps the worker OFF. No production database changes, provider delivery
or deployment are authorized by this document. Never use the helper as a
Docker Postgres entrypoint initializer: the mail tables must first exist
from committed Prisma migrations.

## Approval and provisioning gates

An independent owner must identify and approve the **exact** staging host,
DB host/name, immutable image/SHA, dedicated test identities, distinct
runtime/migrator/worker credentials, relay account, permitted recipient
inboxes, sending rate, TLS trust, monitoring, rollback owner and test window.
None may reuse production or deManage assets. If any fact cannot be proved,
the outcome remains **NO-GO**.

After all migrations on the approved isolated staging database, and with
the worker still OFF, a separately authorized operator can inspect the
postmigration script:

- infra/postgres-init/11-virki-email-worker-role.sh

It requires a unique 64-hex worker DB password, distinct from the
bootstrap/runtime/migrator/audit-maintenance secrets. Credentials stay in
the operator-owned secret mechanism; do not commit integration env files,
put passwords in command arguments, or work around a blocked VM operation.

Provisioning is a single PostgreSQL transaction. It creates/reconciles a
login-only NOINHERIT role without elevated attributes, permits SELECT on
the ciphertext outbox and delivery attempts, narrowly scoped outbox
status/lease updates, and column-scoped attempt INSERT. It cannot enqueue,
change recipients or ciphertext, rewrite attempt receipts, read User,
Session or AuditLog, or create database/schema objects. Excess privileges
inherited from PUBLIC — including TEMP, any other public data relation
and sequences, column grants and protected security-schema functions — cause
rejection and rollback of the role reconciliation. The helper clears ambient
libpq PG* connection settings, pins the local PostgreSQL Unix socket on port
5432 and verifies the connected server is not TCP before role mutations.

The worker-only Compose override is:

- infra/docker-compose.staging-email-worker.yml

It requires the separate variable VIRKI_STAGING_EMAIL_WORKER_DATABASE_URL,
without fallback to the Hub DATABASE_URL. The operator must independently
verify the URL authenticates as virki_email_worker, targets the same isolated
staging database used by Hub and has no production endpoint or identity.
The normal production Compose and role settings deliberately remain
unchanged until independently accepted and approved.

Do not load the override into ordinary production commands or start the
worker until SMTP STARTTLS/AUTH, test recipient allowlist, provider quota,
outbox backlog, worker DB privileges, redacted monitoring and explicit owner
approval have passed. The first permitted send must correlate the outbox
row, attempt row, SMTP acceptance, Brevo provider receipt and a message in
the independently controlled test inbox. An RFC Message-ID or a database
SENT flag is not sufficient proof of receipt. Preserve rollback custody.

## Local evidence versus external acceptance

The opt-in script scripts/staging-email-worker-role.disposable.mjs requires
VIRKI_STAGING_WORKER_ROLE_PROOF=local-disposable-only on Windows. It pins
the installed PostgreSQL 18.6 image and local Linux Docker engine and uses
one UUID-labelled container, Docker network:none and tmpfs-only PGDATA.
It tests real SQL grants and denials, transactional refusal before schema
migrations, refusal of unsafe PUBLIC grants, idempotence, and positive
worker-only SELECT/UPDATE/INSERT. It verifies exact container identity
before deletion. No VM, external TCP, SSH, email provider, integration
script or production host is involved.

This is PostgreSQL **permission testing on a minimal disposable schema**,
not an authenticated application-worker session on the full independent
staging schema. That and end-to-end Hub/PostgreSQL, ADMIN/USER/MFA,
WebAuthn, worker/Brevo/inbox, rollback and exact-SHA hosted CI/CodeQL
remain **NO-GO** until independently evidenced. GitHub billing failures
before any runner step do not count as CI PASS.
