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

## Backup Procedure

Backups are private operational artifacts. Never commit backup files, database dumps, or copied database volumes.

The repository ignores `infra/backups/*` while keeping `infra/backups/.gitkeep`, so local backup files can be written there without being tracked by Git. A location outside the repository is also acceptable.

Create a compressed custom-format PostgreSQL backup from the running production Compose stack:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-privileges' > infra/backups/bielos-YYYYMMDD-HHMMSS.dump
```

Rules:

- Do not print `.env`.
- Do not print database URLs or passwords.
- Do not paste backup output into chat, issues, docs, or logs.
- Confirm the backup file remains untracked before committing anything:

```bash
git status --short
```

For a plain SQL backup of disposable local data only:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-privileges' > infra/backups/bielos-YYYYMMDD-HHMMSS.sql
```

Prefer the custom dump format for restore testing because it is designed for `pg_restore`.

## Restore Procedure

Restore is potentially destructive. Do not restore over durable data unless there is a verified backup, a clear rollback plan, and explicit manual confirmation.

Phase 07.2 must validate restore using a disposable database.

Recommended validation shape:

1. Start a disposable PostgreSQL container or disposable Compose project.
2. Restore the custom dump into the disposable database:

   ```bash
   pg_restore --clean --if-exists --no-owner --no-privileges -d <disposable-database> <backup-file>
   ```

3. Run Prisma validation and application smoke checks against the disposable database.
4. Delete the disposable database after validation.

Do not run destructive restore commands against the real BielOS database during Phase 07.1.
