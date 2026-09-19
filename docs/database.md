# Database

BielOS uses Prisma with PostgreSQL.

## Migration Workflow

Phase 07.0 adds committed Prisma migrations. Production and durable local databases should use:

```bash
npm run prisma:migrate:deploy
```

The production runtime image intentionally omits the Prisma CLI. Do not run migrations inside the `hub` container. When a release includes migration files, run `prisma migrate deploy` from a separate tooling-capable operator environment with the production `DATABASE_URL` supplied privately, after the current backup is verified. This release adds no migration files, so no migration command is required.

The operator environment must use the checked-out release source and Prisma version from the lockfile; never replace migration deployment with `prisma db push`.

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

Do not ingest private/non-discardable data until migrations are deployed and a current backup can be restored into a disposable database.

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

Phase 07.2 validated restore using a disposable PostgreSQL container. The validation used a custom-format dump, restored it with `pg_restore`, confirmed the restored database could be inspected safely, and removed the disposable container and local validation dump afterward.

Use this shape for future restore validation:

1. Start a disposable PostgreSQL container or disposable Compose project.
2. Restore the custom dump into the disposable database:

   ```bash
   pg_restore --clean --if-exists --no-owner --no-privileges -d <disposable-database> <backup-file>
   ```

3. Run Prisma validation and application smoke checks against the disposable database.
4. Delete the disposable database after validation.

Do not run destructive restore commands against the real BielOS database while validating backups. Treat every restore target as disposable unless there is an explicit manual recovery plan.
