# BielOS Email Delivery Boundary

The email boundary is provider-neutral. `@bielos/auth/email` owns the durable outbox contract, idempotency key, safe worker claim, bounded retry, terminal failure, locale-aware rendering, and deterministic test transport. A provider adapter must implement only:

```ts
type EmailTransport = {
  send(message: { to: string; subject: string; text: string }): Promise<void>;
};
```

Outbox payloads keep public template values separate from encrypted protected values. Raw links, codes, passwords, secrets, and bearer material are never stored as plaintext, logged, or included in audit metadata. Delivery success is authoritative only after the adapter resolves; a failed attempt never becomes `SENT`.

Production is intentionally unavailable while no real adapter has been selected. `BIELOS_EMAIL_TRANSPORT` is a configuration gate, not an adapter implementation. `BIELOS_EMAIL_OUTBOX_KEY` must be a 32-byte key encoded as hex or base64url. The deterministic transport is test-only and must never be treated as production readiness.
