# Database

BielOS uses Prisma with PostgreSQL.

## Migration Workflow

Phase 07.0 adds committed Prisma migrations. Production and durable local databases should use:

```bash
npm run prisma:migrate:deploy
```

When the production Docker stack is running, run migrations inside the `hub` container so the command uses the same private database environment as the hub:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T hub npm run prisma:migrate:deploy
```

Use this before seeding the OWNER user on a new durable database.

## Local Disposable Workflow

`prisma db push` remains available only for disposable local development databases:

```bash
npm run prisma:push
```

Do not use `db push` for private, durable, or non-discardable production data. It bypasses committed migration history and can hide destructive schema changes that production needs to review.

## Existing MVP Databases

Some local MVP databases were created with `prisma db push` before migrations existed.

For a disposable local database, the cleanest transition is to recreate the local database volume and then run `prisma migrate deploy`.

For any database that must be preserved, do not run destructive reset or `db push`. First create and verify a backup, confirm the live schema matches the initial migration, then baseline the migration manually with Prisma migration tooling before future migrations are deployed.

## Development Changes

For future schema changes:

1. Edit `packages/database/prisma/schema.prisma`.
2. Create a migration with `npm run prisma:migrate --workspace @bielos/database`.
3. Review the generated SQL.
4. Commit both the schema and migration files.
5. Use `npm run prisma:migrate:deploy` for production updates.

Do not ingest private/non-discardable data until backup and restore validation is complete.
