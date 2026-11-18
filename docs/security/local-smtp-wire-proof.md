# Disposable SMTP wire proof (local only)

Run from a **named clean or intentionally staged Virki worktree** on Windows
with the installed, valid Docker Inc.-signed Docker Desktop Linux engine:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\e2e\run-isolated-linux-docker.ps1 -IntegrationOnly -IntegrationTestFile packages/auth/src/email-smtp-wire.integration.test.ts
```

The runner checks the local Docker daemon, records the Git SHA plus staged
patches, provisions an owned tmpfs PostgreSQL with an isolated non-superuser
role, and executes the SMTP suite only after disconnecting the package-install
bootstrap network. Its test network is Docker `--internal`. The test itself
requires a Linux namespace with no IPv4 default route, an initially empty
database, and an explicit dedicated-runner marker. All Docker resources are
identified by immutable IDs before cleanup. Network access for `apt` / `npm
ci` is used during bootstrap; no external network is available during the
SMTP test phase. This flow does not require GitHub Actions billing.

The test generates a CA and a server certificate with IP SAN `127.0.0.1`
inside its temporary directory, binds a sink to **127.0.0.1 only**, and verifies
that plaintext AUTH is refused. The actual Virki email worker runs as a
separate Node 22 process, with a minimal environment containing only disposable
PostgreSQL credentials, SMTP credentials, the outbox AES key and the generated
CA. Nodemailer must establish STARTTLS with CA verification and authenticate
before the sink permits exactly one envelope with a synthetic
`@integration.invalid` recipient. The sink accepts the complete wire message
in memory, extracts its OTP without logging it, and verifies the recovery
challenge through `verifyMultiMethodRecoveryEmail`. The test checks a wrong
code, successful proof, one-use replay denial, the independent TOTP requirement,
and the persisted `SENT` delivery attempt with a matching SMTP `Message-ID`.
Worker, server and certificate cleanup run in `finally`; the runner enforces
deadlines and refuses skipped TAP tests. Suite output redacts six-digit values.

The dedicated command is `npm run test:integration:email-smtp-wire`, but it
**cannot** be launched safely on its own: the Docker runner must provision the
fresh database and network and supply its exclusive markers. Generic
`npm run test:integration` intentionally excludes this suite. Source-only
negative contracts may be run without Docker:

```bash
node --test scripts/integration/email-smtp-wire.test.mjs
```

A successful local wire test proves SMTP protocol acceptance by the disposable
sink, not delivery by Brevo or another external provider, public inbox
delivery, Cloudflare Access policy, or production readiness. Never connect the
test to a live SMTP host, production database, inherited `.env`, or actual
email recipient.
