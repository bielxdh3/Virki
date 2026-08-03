# BielOS Email Delivery Boundary

The email boundary is provider-neutral. `@bielos/auth/email` owns the durable outbox contract, idempotency key, safe worker claim, bounded retry, terminal failure, locale-aware rendering, and deterministic test transport. A provider adapter must implement only:

```ts
type EmailTransport = {
  send(message: { to: string; subject: string; text: string }): Promise<void>;
};
```

Outbox payloads keep public template values separate from encrypted protected values. Raw links, codes, passwords, secrets, and bearer material are never stored as plaintext, logged, or included in audit metadata. Delivery success is authoritative only after the adapter resolves; a failed attempt never becomes `SENT`.

Production is intentionally unavailable until a real SMTP adapter and encrypted outbox key are configured. `BIELOS_EMAIL_TRANSPORT=smtp` selects the provider-neutral Nodemailer adapter; the adapter requires certificate-validated TLS/STARTTLS, bounded connection/greeting/socket timeouts, and redacts provider errors. It never logs SMTP credentials. `BIELOS_EMAIL_OUTBOX_KEY` must be a 32-byte key encoded as hex or base64url. The deterministic transport is test-only and must never be treated as production readiness.

## Brevo preparation

The selected production provider is Brevo SMTP. Keep `BIELOS_INTAKE_ENABLED=false` until the Brevo account, sender-domain authentication, credentials, backup, migrations, owner ceremonies, routing, and final smoke gates are complete.

Use a dedicated sender such as `notifications@notify.biel.dev.br` and configure the private environment with:

```text
BIELOS_EMAIL_TRANSPORT=smtp
BIELOS_EMAIL_SMTP_HOST=smtp-relay.brevo.com
BIELOS_EMAIL_SMTP_PORT=587
BIELOS_EMAIL_SMTP_SECURE=false
BIELOS_EMAIL_SMTP_USER=<Brevo SMTP login, local secret only>
BIELOS_EMAIL_SMTP_PASSWORD=<Brevo SMTP key, local secret only>
BIELOS_EMAIL_FROM=notifications@notify.biel.dev.br
```

Do not put credentials in Git, chat, logs, or documentation.

### DNS record worksheet

Create these only after the Brevo account is created and `notify.biel.dev.br` is added as the authenticated sender domain. Do not invent the Brevo-specific DKIM selector/value: Brevo may provide one TXT record or two CNAME records, and the exact values are account-specific.

| Name | Type | Prepared value | Gate |
| --- | --- | --- | --- |
| `notify.biel.dev.br` | TXT | `v=spf1 include:spf.brevo.com mx ~all` | Merge with any existing SPF; publish only one SPF record. |
| `<Brevo DKIM selector/name>` | TXT or CNAME | `<exact value copied from Brevo>` | Required after Brevo domain verification. |
| `_dmarc.notify.biel.dev.br` | TXT | `v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com` | Start with monitoring; tighten policy after observing reports. |

Brevo's current authentication flow provides the exact domain-verification, DKIM, and DMARC values in the account dashboard. SPF is shown here as the prepared Brevo authorization record; merge it with existing senders instead of creating a second SPF record.
