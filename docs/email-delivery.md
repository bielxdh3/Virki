# BielOS Email Delivery Boundary

The email boundary is provider-neutral. `@bielos/auth/email` owns the durable outbox contract, idempotency key, safe worker claim, bounded retry, terminal failure, locale-aware rendering, and deterministic test transport. A provider adapter must implement only:

```ts
type EmailTransport = {
  send(message: { to: string; subject: string; text: string }): Promise<void>;
};
```

Outbox payloads keep public template values separate from encrypted protected values. Raw links, codes, passwords, secrets, and bearer material are never stored as plaintext, logged, or included in audit metadata. Delivery success is authoritative only after the adapter resolves; a failed attempt never becomes `SENT`.

## Production outbox worker

Production Compose runs `email-worker` without published ports. It polls the durable outbox every five seconds, uses the existing atomic claim and bounded retry state, and loads the configured SMTP adapter from the private environment. `SIGTERM` and `SIGINT` stop polling and allow the current bounded delivery attempt to finish. The worker emits only the fixed safe command-failure message and never logs credentials, payloads, codes, or provider responses.

Production is intentionally unavailable until a real SMTP adapter and encrypted outbox key are configured. `BIELOS_EMAIL_TRANSPORT=smtp` selects the provider-neutral Nodemailer adapter; the adapter requires certificate-validated TLS/STARTTLS, bounded connection/greeting/socket timeouts, and redacts provider errors. It never logs SMTP credentials. `BIELOS_EMAIL_OUTBOX_KEY` must be a 32-byte key encoded as hex or base64url. The deterministic transport is test-only and must never be treated as production readiness.

## Brevo preparation

The selected production provider is Brevo SMTP. Keep `BIELOS_INTAKE_ENABLED=false` until the Brevo account, sender-domain authentication, credentials, backup, migrations, owner ceremonies, routing, and final smoke gates are complete.

The authenticated Brevo sending domain is `biel.dev.br`; the branded subdomain is `notify.biel.dev.br`, and the configured sender is `no-reply@biel.dev.br`. Configure the private environment with:

```text
BIELOS_EMAIL_TRANSPORT=smtp
BIELOS_EMAIL_SMTP_HOST=smtp-relay.brevo.com
BIELOS_EMAIL_SMTP_PORT=587
BIELOS_EMAIL_SMTP_SECURE=false
BIELOS_EMAIL_SMTP_USER=<Brevo SMTP login, local secret only>
BIELOS_EMAIL_SMTP_PASSWORD=<Brevo SMTP key, local secret only>
BIELOS_EMAIL_FROM=no-reply@biel.dev.br
```

Do not put credentials in Git, chat, logs, or documentation.

### DNS record worksheet

The operator-confirmed Brevo state is: `biel.dev.br` is authenticated, `notify.biel.dev.br` is active as the branded subdomain, and `no-reply@biel.dev.br` is configured as the sender. Keep the records below as the deployment reference and verify them against the Brevo dashboard and DNS provider before changing anything. Do not invent the Brevo-specific DKIM selector/value: Brevo may provide one TXT record or two CNAME records, and the exact values are account-specific.

| Name | Type | Prepared value | Gate |
| --- | --- | --- | --- |
| `biel.dev.br` | TXT | `v=spf1 include:spf.brevo.com mx ~all` | Merge with any existing SPF; publish only one SPF record. |
| `<Brevo DKIM selector/name>.biel.dev.br` | TXT or CNAME | `<exact value copied from Brevo>` | Use the exact record shown by Brevo. |
| `_dmarc.biel.dev.br` | TXT | `v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com` | Start with monitoring; tighten policy after observing reports. |

Brevo's current authentication flow provides the exact domain-verification, DKIM, and DMARC values in the account dashboard. SPF is shown here as the prepared Brevo authorization record; merge it with existing senders instead of creating a second SPF record.
