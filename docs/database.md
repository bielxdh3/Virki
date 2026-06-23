# Database

BielOS currently uses Prisma with PostgreSQL.

## Current MVP Workflow

The current local MVP workflow uses:

```bash
npm run prisma:push
```

When the stack is running through Docker, apply schema changes inside the `hub` container:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T hub npm run prisma:push
```

This is acceptable while the database is local, controlled, and has no non-discardable private data.

## Migration Requirement Before Private Data

Before BielOS stores non-discardable private data, the project must switch to a Prisma migration workflow:

- use `prisma migrate dev` during development
- commit migration files
- use `prisma migrate deploy` for production updates
- validate backup and restore before applying production migrations

Phase 05.R removes unused `Session.ipHash` and `Session.userAgent` fields. For the current MVP database, apply the schema with `prisma db push`. Do not use this shortcut after private/non-discardable data ingestion begins.

Because this removes unused columns, a local MVP database may require:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T hub npx prisma db push --schema packages/database/prisma/schema.prisma --accept-data-loss
```

Use this only for the current discardable/local MVP database.

## Deferred Decision

A clean migration history is deferred for now to avoid disrupting the current local MVP setup. This must be revisited before BielOS becomes a durable private data system.
